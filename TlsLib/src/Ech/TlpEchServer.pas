{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpEchServer;

{$I ..\Include\TlsLib.inc}

interface

uses
  SysUtils,
  TlpCryptoDomainTypes,
  TlpICryptoProvider,
  TlpISecretBuffer,
  TlpWireReader,
  TlpIWireWriter,
  TlpWireWriter,
  TlpWireVectorMarker,
  TlpHandshakeMessage,
  TlpHandshakeMessages,
  TlpCoreExtensions,
  TlpEchConfig,
  TlpEchExtension,
  TlpEchOuterExtensions,
  TlpIEch,
  TlpSecureMemory,
  TlpTlsVersion,
  TlpTlsAlert,
  TlpTlsLibExceptions;

type
  /// <summary>
  /// The client-facing (shared-mode) server side of Encrypted Client Hello (RFC 9849
  /// sec. 7.1). Trial-decrypts the ClientHelloOuter's ech extension against the key
  /// store, reconstructs and validates the ClientHelloInner, and holds the live opener
  /// (for a HelloRetryRequest at seq=1) and the inner random (for the accept
  /// confirmation). A missing ech is "not offered"; a present ech that no key opens is a
  /// shared-mode reject.
  /// </summary>
  TEchServerHandshake = class sealed(TObject)
  strict private
  var
    FProvider: ICryptoProvider;
    FKeyStore: IEchServerKeyStore;
    FTrialDecryptAll: Boolean;
    FStatus: TEchStatus;
    FInnerFramed: TBytes;
    FInnerRandom: TBytes;
    FOpener: IHpkeOpener;
    FSuite: THpkeSuite;
    FConfig: TEchConfig;
    class function ConfigSupports(const AConfig: TEchConfig;
      const ASuite: TEchCipherSuite): Boolean; static;
    class function LocateOuterEchPayload(const ABody: TBytes;
      out AStart, ALen: Int32): Boolean; static;
    class function SingleEchIndex(const AEntries: TArray<TEchExtEntry>): Int32; static;
    class function OuterAad(const AOuterBody: TBytes): TBytes; static;
    class function IsVersions13Only(const AData: TBytes): Boolean; static;
    procedure ReconstructInner(const AEncoded: TBytes;
      const AOuter: TTlsClientHello; const AOuterEntries: TArray<TEchExtEntry>);
  public
    constructor Create(const AProvider: ICryptoProvider;
      const AKeyStore: IEchServerKeyStore; ATrialDecryptAll: Boolean);
    /// <summary>
    /// Processes the framed ClientHelloOuter AOuterFramed. Returns NotOffered (no ech
    /// extension), Accepted (an ech opened; the reconstructed inner is available), or
    /// Rejected (an ech present but no key opened it). Raises illegal_parameter on a
    /// wire inner-type ech, non-zero padding, a missing inner ech marker, or an inner
    /// that offers TLS 1.2 or below.
    /// </summary>
    function ProcessOuter(const AOuterFramed: TBytes): TEchStatus;
    /// <summary>
    /// Processes the second ClientHelloOuter after a HelloRetryRequest, reusing the CH1 HPKE
    /// context at seq=1 (RFC 9849 sec. 6.1.5): the retry ech MUST keep the CH1 config_id and
    /// cipher_suite and carry an empty enc (else illegal_parameter); a re-open failure is
    /// decrypt_error. On success the reconstructed inner CH2 is available in InnerFramed.
    /// </summary>
    function ProcessRetryOuter(const AOuterFramed: TBytes): TEchStatus;
    property Status: TEchStatus read FStatus;
    property InnerFramed: TBytes read FInnerFramed;
    property InnerRandom: TBytes read FInnerRandom;
  end;

implementation

resourcestring
  SWireInnerEch = 'an inner-type encrypted_client_hello arrived at a client-facing server';
  SDuplicateEch = 'more than one encrypted_client_hello extension';
  SNonZeroPadding = 'EncodedClientHelloInner padding is not all zero';
  SInnerSessionIdNotEmpty = 'the EncodedClientHelloInner legacy_session_id is not empty';
  SEncodedInnerNotCanonical = 'the EncodedClientHelloInner legacy_version or ' +
    'legacy_compression_methods is not the TLS 1.3 canonical form';
  SMissingInnerEch = 'the reconstructed inner has no inner-type encrypted_client_hello';
  SInnerOffersLegacy = 'the inner ClientHello offers TLS 1.2 or below';
  SEchRetryMismatch = 'the retry ech changed config_id/cipher_suite or set a non-empty enc';
  SEchRetryDecrypt = 'the retry ech failed to decrypt at seq=1';

{ TEchServerHandshake }

constructor TEchServerHandshake.Create(const AProvider: ICryptoProvider;
  const AKeyStore: IEchServerKeyStore; ATrialDecryptAll: Boolean);
begin
  inherited Create;
  FProvider := AProvider;
  FKeyStore := AKeyStore;
  FTrialDecryptAll := ATrialDecryptAll;
  FStatus := TEchStatus.NotOffered;
end;

class function TEchServerHandshake.ConfigSupports(const AConfig: TEchConfig;
  const ASuite: TEchCipherSuite): Boolean;
var
  LI: Int32;
begin
  for LI := 0 to System.High(AConfig.CipherSuites) do
    if (AConfig.CipherSuites[LI].KdfId = ASuite.KdfId) and
      (AConfig.CipherSuites[LI].AeadId = ASuite.AeadId) then
      Exit(True);
  Result := False;
end;

class function TEchServerHandshake.LocateOuterEchPayload(const ABody: TBytes;
  out AStart, ALen: Int32): Boolean;
var
  LReader, LExts, LEchData, LPayload: TWireReader;
  LExtType: UInt16;
  LType: TEchClientHelloType;
begin
  // walk the ClientHello body to the outer-form ech extension's payload vector and report its
  // [AStart, AStart+ALen) span in ABody
  Result := False;
  AStart := 0;
  ALen := 0;
  LReader := TWireReader.Create(ABody);
  LReader.Skip(2);           // legacy_version
  LReader.Skip(32);          // random
  LReader.OpenVector(1);     // legacy_session_id
  LReader.OpenVector(2);     // cipher_suites
  LReader.OpenVector(1);     // legacy_compression_methods
  LExts := LReader.OpenVector(2);
  while not LExts.EndReached do
  begin
    LExtType := LExts.ReadUInt16;
    LEchData := LExts.OpenVector(2);
    if LExtType = TExtensionTypes.EncryptedClientHello then
    begin
      if not TEchClientHelloType.TryFromByte(LEchData.ReadUInt8, LType) then
        Exit;
      if LType <> TEchClientHelloType.Outer then
        Exit;
      LEchData.Skip(2 + 2 + 1); // kdf_id, aead_id, config_id
      LEchData.OpenVector(2);   // enc
      LPayload := LEchData.OpenVector(2);
      AStart := LPayload.Position;
      ALen := LPayload.Remaining;
      Exit(True);
    end;
  end;
end;

class function TEchServerHandshake.SingleEchIndex(
  const AEntries: TArray<TEchExtEntry>): Int32;
var
  LI: Int32;
begin
  // at most one encrypted_client_hello (RFC 8446 4.2 forbids a repeated extension type); the
  // first is authoritative everywhere, so a duplicate is rejected before any trial decryption
  Result := -1;
  for LI := 0 to System.High(AEntries) do
    if AEntries[LI].ExtType = TExtensionTypes.EncryptedClientHello then
    begin
      if Result >= 0 then
        raise EFatalAlertTlsLibException.CreateRes(
          TTlsAlertDescription.IllegalParameter, @SDuplicateEch);
      Result := LI;
    end;
end;

class function TEchServerHandshake.OuterAad(const AOuterBody: TBytes): TBytes;
var
  LStart, LLen: Int32;
begin
  // the ClientHelloOuterAAD (RFC 9849 sec. 5.2) is the received ClientHelloOuter with the ech
  // payload zeroed in place - a byte-exact patch of what the client sent, never a re-encoding,
  // so any client's serialization (extension order, unknown extensions) authenticates unchanged
  Result := System.Copy(AOuterBody);
  if LocateOuterEchPayload(Result, LStart, LLen) and (LLen > 0) then
    FillChar(Result[LStart], LLen, 0);
end;

class function TEchServerHandshake.IsVersions13Only(const AData: TBytes): Boolean;
var
  LReader, LList: TWireReader;
  LVersion: UInt16;
  LHasTls13: Boolean;
begin
  // supported_versions body (1-byte-length-prefixed uint16 list): the inner MUST NOT offer TLS
  // 1.2 or below (RFC 9849 sec. 7.1), so reject any sub-1.3 codepoint. GREASE and 1.3+ values are
  // all above 1.3's 0x0304 and are left to the normal version negotiation, never treated as
  // legacy (RFC 8701) - the inner is valid as long as it offers 1.3 and nothing older.
  Result := False;
  LHasTls13 := False;
  LReader := TWireReader.Create(AData);
  LList := LReader.OpenVector(1);
  if LList.EndReached then
    Exit;
  while not LList.EndReached do
  begin
    LVersion := LList.ReadUInt16;
    if LVersion < TlsWireVersionTls13 then
      Exit;
    if LVersion = TlsWireVersionTls13 then
      LHasTls13 := True;
  end;
  Result := LHasTls13;
end;

procedure TEchServerHandshake.ReconstructInner(const AEncoded: TBytes;
  const AOuter: TTlsClientHello; const AOuterEntries: TArray<TEchExtEntry>);
var
  LReader, LSession, LSuites, LComp, LExts: TWireReader;
  LEncEntries, LReconEntries: TArray<TEchExtEntry>;
  LInner: TTlsClientHello;
  LType: TEchClientHelloType;
  LOuterEch: TEchOuterClientHello;
  LPadding, LCompMethods: TBytes;
  LI: Int32;
  LHasVersions: Boolean;
  LWriter: IWireWriter;
  LMarker: TWireVectorMarker;
begin
  // parse EncodedClientHelloInner: client_hello (extensions bounded by their own length
  // prefix) followed by padding, which must be all zero
  LReader := TWireReader.Create(AEncoded);
  LInner := Default(TTlsClientHello);
  // the encoded inner must be the canonical TLS 1.3 form: legacy_version 0x0303, an empty
  // legacy_session_id (RFC 9849 sec. 5.1), and a single null legacy_compression_methods (RFC
  // 8446 sec. 4.1.2). The re-frame below canonicalizes these fields, so verifying them here
  // keeps the reconstructed transcript byte-exact with the client's rather than silently rewriting
  if LReader.ReadUInt16 <> TlsWireVersionTls12 then
    raise EFatalAlertTlsLibException.CreateRes(
      TTlsAlertDescription.IllegalParameter, @SEncodedInnerNotCanonical);
  LInner.Random := LReader.ReadBytes(32);
  LSession := LReader.OpenVector(1);
  if LSession.Remaining <> 0 then
    raise EFatalAlertTlsLibException.CreateRes(
      TTlsAlertDescription.IllegalParameter, @SInnerSessionIdNotEmpty);
  LSuites := LReader.OpenVector(2);
  LInner.CipherSuites := nil;
  LI := 0;
  while not LSuites.EndReached do
  begin
    SetLength(LInner.CipherSuites, LI + 1);
    LInner.CipherSuites[LI] := LSuites.ReadUInt16;
    Inc(LI);
  end;
  LComp := LReader.OpenVector(1);
  LCompMethods := LComp.ReadBytes(LComp.Remaining);
  if (System.Length(LCompMethods) <> 1) or (LCompMethods[0] <> 0) then
    raise EFatalAlertTlsLibException.CreateRes(
      TTlsAlertDescription.IllegalParameter, @SEncodedInnerNotCanonical);
  LExts := LReader.OpenVector(2);
  LEncEntries := TEchOuterExtensions.ParseExtensions(
    LExts.ReadBytes(LExts.Remaining));
  LPadding := LReader.ReadBytes(LReader.Remaining);
  if not TSecureMemory.ConstantTimeIsAllZero(LPadding) then
    raise EFatalAlertTlsLibException.CreateRes(
      TTlsAlertDescription.IllegalParameter, @SNonZeroPadding);

  LReconEntries := TEchOuterExtensions.Reconstruct(AOuterEntries, LEncEntries);

  // the inner must carry an inner-type ech marker and must be TLS 1.3-only
  LType := TEchClientHelloType.Outer;
  LHasVersions := False;
  for LI := 0 to System.High(LReconEntries) do
  begin
    if LReconEntries[LI].ExtType = TExtensionTypes.EncryptedClientHello then
      TEchExtension.Decode(LReconEntries[LI].Data, LType, LOuterEch)
    else if LReconEntries[LI].ExtType = TExtensionTypes.SupportedVersions then
    begin
      LHasVersions := True;
      if not IsVersions13Only(LReconEntries[LI].Data) then
        raise EFatalAlertTlsLibException.CreateRes(
          TTlsAlertDescription.IllegalParameter, @SInnerOffersLegacy);
    end;
  end;
  if LType <> TEchClientHelloType.Inner then
    raise EFatalAlertTlsLibException.CreateRes(
      TTlsAlertDescription.IllegalParameter, @SMissingInnerEch);
  if not LHasVersions then
    raise EFatalAlertTlsLibException.CreateRes(
      TTlsAlertDescription.IllegalParameter, @SInnerOffersLegacy);

  // re-frame the inner: legacy_session_id copied from the outer (RFC 9849 sec. 5.1)
  LInner.LegacySessionId := AOuter.LegacySessionId;
  LWriter := TWireWriter.Create;
  LMarker := LWriter.OpenVector(2);
  LWriter.WriteBytes(TEchOuterExtensions.EncodeExtensions(LReconEntries));
  LWriter.CloseVector(LMarker);
  LInner.Extensions := LWriter.ToBytes;
  FInnerRandom := LInner.Random;
  FInnerFramed := THandshakeFraming.Frame(TTlsHandshakeType.ClientHello,
    THandshakeMessages.EncodeClientHello(LInner));
end;

function TEchServerHandshake.ProcessOuter(
  const AOuterFramed: TBytes): TEchStatus;
var
  LOuterBody, LAad, LEncoded: TBytes;
  LOuter: TTlsClientHello;
  LEntries: TArray<TEchExtEntry>;
  LReader, LBody: TWireReader;
  LI, LEchIdx: Int32;
  LType: TEchClientHelloType;
  LOuterEch: TEchOuterClientHello;
  LEntry: TEchKeyEntry;
  LKeys: TArray<TEchKeyEntry>;
  LOpener: IHpkeOpener;
  LOpened: Boolean;
begin
  LOuterBody := System.Copy(AOuterFramed, 4, System.Length(AOuterFramed) - 4);
  LOuter := THandshakeMessages.DecodeClientHello(LOuterBody);
  // an absent extensions field is a legacy (<=TLS 1.2) ClientHello shape: no ech is offered,
  // and version negotiation later rejects it - do not decode_error on the missing vector here
  if System.Length(LOuter.Extensions) = 0 then
  begin
    FStatus := TEchStatus.NotOffered;
    Exit(FStatus);
  end;
  LReader := TWireReader.Create(LOuter.Extensions);
  LBody := LReader.OpenVector(2);
  LEntries := TEchOuterExtensions.ParseExtensions(LBody.ReadBytes(LBody.Remaining));

  LEchIdx := SingleEchIndex(LEntries);
  if LEchIdx < 0 then
  begin
    FStatus := TEchStatus.NotOffered;
    Exit(FStatus);
  end;

  TEchExtension.Decode(LEntries[LEchIdx].Data, LType, LOuterEch);
  if LType = TEchClientHelloType.Inner then
    raise EFatalAlertTlsLibException.CreateRes(
      TTlsAlertDescription.IllegalParameter, @SWireInnerEch);

  LAad := OuterAad(LOuterBody);
  LKeys := FKeyStore.Entries;
  for LI := 0 to System.High(LKeys) do
  begin
    LEntry := LKeys[LI];
    if (not FTrialDecryptAll) and (LEntry.Config.ConfigId <> LOuterEch.ConfigId) then
      Continue;
    if not ConfigSupports(LEntry.Config, LOuterEch.CipherSuite) then
      Continue;
    FSuite := THpkeSuite.Create(LEntry.Config.KemId, LOuterEch.CipherSuite.KdfId,
      LOuterEch.CipherSuite.AeadId);
    if not FProvider.Hpke.SuiteSupported(FSuite) then
      Continue;
    LOpened := False;
    try
      LOpener := LEntry.RecipientKey.SetupOpener(FSuite, LOuterEch.Enc,
        LEntry.Config.HpkeInfo);
      LEncoded := LOpener.Open(LAad, LOuterEch.Payload);
      LOpened := True;
    except
      on E: EHpkeOpenTlsLibException do
        LOpened := False;
    end;
    if LOpened then
    begin
      ReconstructInner(LEncoded, LOuter, LEntries);
      FOpener := LOpener;
      FConfig := LEntry.Config;
      FStatus := TEchStatus.Accepted;
      Exit(FStatus);
    end;
  end;

  FStatus := TEchStatus.Rejected;
  Result := FStatus;
end;

function TEchServerHandshake.ProcessRetryOuter(
  const AOuterFramed: TBytes): TEchStatus;
var
  LOuterBody, LAad, LEncoded: TBytes;
  LOuter: TTlsClientHello;
  LEntries: TArray<TEchExtEntry>;
  LReader, LBody: TWireReader;
  LI, LEchIdx: Int32;
  LType: TEchClientHelloType;
  LOuterEch: TEchOuterClientHello;
begin
  LOuterBody := System.Copy(AOuterFramed, 4, System.Length(AOuterFramed) - 4);
  LOuter := THandshakeMessages.DecodeClientHello(LOuterBody);
  // CH1 was accepted, so CH2 MUST re-offer the outer ech (RFC 9849 sec. 6.1.5); an absent
  // extensions field carries none - missing_extension, not a decode_error on the vector
  if System.Length(LOuter.Extensions) = 0 then
    raise EFatalAlertTlsLibException.CreateRes(
      TTlsAlertDescription.MissingExtension, @SEchRetryMismatch);
  LReader := TWireReader.Create(LOuter.Extensions);
  LBody := LReader.OpenVector(2);
  LEntries := TEchOuterExtensions.ParseExtensions(LBody.ReadBytes(LBody.Remaining));
  LEchIdx := SingleEchIndex(LEntries);
  // CH1 was accepted, so CH2 MUST re-offer the outer ech (RFC 9849 sec. 6.1.5)
  if LEchIdx < 0 then
    raise EFatalAlertTlsLibException.CreateRes(
      TTlsAlertDescription.MissingExtension, @SEchRetryMismatch);
  TEchExtension.Decode(LEntries[LEchIdx].Data, LType, LOuterEch);
  if LType = TEchClientHelloType.Inner then
    raise EFatalAlertTlsLibException.CreateRes(
      TTlsAlertDescription.IllegalParameter, @SWireInnerEch);
  // the retry reuses the CH1 context: config_id and cipher_suite unchanged, enc empty
  if (LOuterEch.ConfigId <> FConfig.ConfigId) or
    (LOuterEch.CipherSuite.KdfId <> FSuite.Kdf) or
    (LOuterEch.CipherSuite.AeadId <> FSuite.Aead) or
    (System.Length(LOuterEch.Enc) <> 0) then
    raise EFatalAlertTlsLibException.CreateRes(
      TTlsAlertDescription.IllegalParameter, @SEchRetryMismatch);

  LAad := OuterAad(LOuterBody);
  try
    LEncoded := FOpener.Open(LAad, LOuterEch.Payload); // seq advances to 1
  except
    on E: EHpkeOpenTlsLibException do
      raise EFatalAlertTlsLibException.CreateRes(
        TTlsAlertDescription.DecryptError, @SEchRetryDecrypt);
  end;
  ReconstructInner(LEncoded, LOuter, LEntries);
  FStatus := TEchStatus.Accepted;
  Result := FStatus;
end;

end.
