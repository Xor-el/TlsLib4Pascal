{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpEchClient;

{$I ..\Include\TlsLib.inc}

interface

uses
  SysUtils,
  TlpCryptoDomainTypes,
  TlpICryptoProvider,
  TlpWireReader,
  TlpHandshakeMessages,
  TlpCoreExtensions,
  TlpExtensionVector,
  TlpEchConfig,
  TlpEchExtension,
  TlpEchOuterExtensions,
  TlpIEch,
  TlpTls13KeySchedule,
  TlpArrayUtilities,
  TlpTlsLibExceptions,
  TlpSecureMemory;

type
  /// <summary>
  /// The frozen client ECH policy (RFC 9849): parses the ECHConfigList once and holds
  /// the GREASE and retry flags. Immutable; safe to share lock-free.
  /// </summary>
  TEchClientPolicy = class sealed(TInterfacedObject, IEchClientPolicy)
  strict private
  var
    FConfigs: TArray<TEchConfig>;
    FGrease: Boolean;
    FIsRetry: Boolean;
  public
    constructor Create(const AConfigListBytes: TBytes; AGrease, AIsRetry: Boolean);
    function Configs: TArray<TEchConfig>;
    function GreaseEnabled: Boolean;
    function IsRetryAttempt: Boolean;
  end;

  /// <summary>
  /// The client-side ECH encoding of RFC 9849 sec. 5.1 / 5.2 / 6.1.3. Produces the
  /// EncodedClientHelloInner (the HPKE plaintext: empty legacy_session_id, a chosen
  /// contiguous run of extensions replaced by one ech_outer_extensions block, then
  /// padding) and drives the HPKE seal against a selected ECHConfig. A per-connection
  /// instance holds the live sealer so a HelloRetryRequest can re-seal at seq=1.
  /// </summary>
  TEchClientHandshake = class sealed(TInterfacedObject, IEchClientHandshake)
  strict private
  var
    FCrypto: ICryptoProvider;
    FConfig: TEchConfig;
    FSuite: IHpkeSuite;
    FSealer: IHpkeSealer;
    FEnc: TBytes;
    class function ServerNameLength(const AEntries: TExtensionVector;
      out AHasServerName: Boolean): Int32; static;
    class function MatchesOuter(const AEntry: TExtensionEntry;
      const AOuter: TExtensionVector): Boolean; static;
    class function CompressibleRun(const AInner, AOuter: TExtensionVector;
      out AStart, ALength: Int32): Boolean; static;
  public
    constructor Create(const ACryptoProvider: ICryptoProvider; const AConfig: TEchConfig;
      const ASuite: IHpkeSuite);

    /// <summary>
    /// The number of zero padding bytes appended to the client_hello of length
    /// AClientHelloLen (RFC 9849 sec. 6.1.3): server-name-length padding to the config's
    /// maximum_name_length, then rounding the whole EncodedClientHelloInner to a
    /// multiple of 32.
    /// </summary>
    class function PaddingLength(AClientHelloLen, AServerNameLength: Int32;
      AHasServerName: Boolean; AMaximumNameLength: Byte): Int32; static;

    /// <summary>
    /// Builds the EncodedClientHelloInner from the inner ClientHello body AInnerBody and
    /// the ClientHelloOuter extensions AOuter: empties legacy_session_id,
    /// replaces the longest contiguous run of compressible extensions that also appear
    /// verbatim in the outer with one ech_outer_extensions block, and appends padding.
    /// </summary>
    function BuildEncodedInner(const AInnerBody: TBytes;
      const AOuter: TExtensionVector): TBytes;

    /// <summary>
    /// Sets up the HPKE sender against the selected config's public key and returns the
    /// KEM encapsulation to place in the ClientHelloOuter ech extension. Holds the live
    /// sealer for a possible HelloRetryRequest re-seal.
    /// </summary>
    function SetupSeal: TBytes;
    /// <summary>Seals APlaintext under the ClientHelloOuterAAD AAad at the sealer's
    /// current sequence number (RFC 9849 sec. 5.2).</summary>
    function Seal(const AAad, APlaintext: TBytes): TBytes;

    /// <summary>
    /// Whether the ECH accept confirmation over the inner transcript matches the last 8
    /// bytes of ServerHello.random (RFC 9849 sec. 7.2), compared in constant time.
    /// AInnerRandom is ClientHelloInner.random; ATranscriptEchConf is the inner
    /// transcript hash with those 8 SH.random bytes zeroed.
    /// </summary>
    class function AcceptConfirmationMatches(const AHkdf: IHkdf;
      const AInnerRandom, ATranscriptEchConf, AServerRandom: TBytes): Boolean; static;

    property Enc: TBytes read FEnc;
  end;

implementation

resourcestring
  SEchEmptyConfigNoGrease = 'an empty ECHConfigList with ECH GREASE disabled would send the ' +
    'true SNI in the clear; supply a config list or enable GREASE';

const
  ServerHelloRandomLength = Int32(32);

{ TEchClientPolicy }

constructor TEchClientPolicy.Create(const AConfigListBytes: TBytes;
  AGrease, AIsRetry: Boolean);
begin
  inherited Create;
  // a malformed list is a typed decode error at configuration time; an empty list is only
  // meaningful as a GREASE-only policy - without GREASE it would silently send the true SNI
  if System.Length(AConfigListBytes) > 0 then
    FConfigs := TEchConfigList.Parse(AConfigListBytes)
  else if not AGrease then
    raise EArgumentTlsLibException.CreateRes(@SEchEmptyConfigNoGrease);
  FGrease := AGrease;
  FIsRetry := AIsRetry;
end;

function TEchClientPolicy.Configs: TArray<TEchConfig>;
begin
  Result := System.Copy(FConfigs);
end;

function TEchClientPolicy.GreaseEnabled: Boolean;
begin
  Result := FGrease;
end;

function TEchClientPolicy.IsRetryAttempt: Boolean;
begin
  Result := FIsRetry;
end;

{ TEchClientHandshake }

constructor TEchClientHandshake.Create(const ACryptoProvider: ICryptoProvider;
  const AConfig: TEchConfig; const ASuite: IHpkeSuite);
begin
  inherited Create;
  FCrypto := ACryptoProvider;
  FConfig := AConfig;
  FSuite := ASuite;
end;

class function TEchClientHandshake.PaddingLength(AClientHelloLen,
  AServerNameLength: Int32; AHasServerName: Boolean;
  AMaximumNameLength: Byte): Int32;
var
  LPad, LLen, LRound: Int32;
begin
  // RFC 9849 sec. 6.1.3 stage 1: pad the server name up to maximum_name_length, or, when
  // the inner offers no server_name, add maximum_name_length + 9
  if AHasServerName then
  begin
    LPad := Int32(AMaximumNameLength) - AServerNameLength;
    if LPad < 0 then
      LPad := 0;
  end
  else
    LPad := Int32(AMaximumNameLength) + 9;
  // stage 2: round the whole EncodedClientHelloInner up to a multiple of 32
  LLen := AClientHelloLen + LPad;
  LRound := 31 - ((LLen - 1) and 31);
  Result := LPad + LRound;
end;

class function TEchClientHandshake.ServerNameLength(
  const AEntries: TExtensionVector; out AHasServerName: Boolean): Int32;
var
  LEntry: TExtensionEntry;
  LReader, LList, LName: TWireReader;
begin
  AHasServerName := False;
  Result := 0;
  if not AEntries.TryFind(TExtensionTypes.ServerName, LEntry) then
    Exit;
  // ServerNameList: the first host_name (type 0) entry's HostName length
  LReader := TWireReader.Create(LEntry.Data);
  if LReader.Remaining < 1 then
    Exit;
  LList := LReader.OpenVector(2);
  if (LList.Remaining >= 1) and (LList.ReadUInt8 = 0) then
  begin
    LName := LList.OpenVector(2);
    AHasServerName := True;
    Result := LName.Remaining;
  end;
end;

class function TEchClientHandshake.MatchesOuter(const AEntry: TExtensionEntry;
  const AOuter: TExtensionVector): Boolean;
var
  LI: Int32;
begin
  // inner and outer extension bytes are both public ClientHello material, so a plain
  // variable-time comparison is correct here - no secret is being matched
  for LI := 0 to AOuter.Count - 1 do
    if (AOuter.Entries[LI].ExtensionType = AEntry.ExtensionType) and
      TArrayUtilities.AreEqual(AOuter.Entries[LI].Data, AEntry.Data) then
      Exit(True);
  Result := False;
end;

class function TEchClientHandshake.CompressibleRun(const AInner,
  AOuter: TExtensionVector; out AStart, ALength: Int32): Boolean;
var
  LI, LRunStart, LRunLen, LBestStart, LBestLen: Int32;
  LCompressible: Boolean;
begin
  // the longest contiguous run of inner extensions that are compressible and appear
  // verbatim in the outer; one run keeps the ech_outer_extensions expansion a contiguous,
  // in-order slice, so the server's reconstruction reproduces the inner exactly
  LBestStart := 0;
  LBestLen := 0;
  LRunStart := 0;
  LRunLen := 0;
  for LI := 0 to AInner.Count - 1 do
  begin
    LCompressible := TEchOuterExtensions.IsCompressible(
      AInner.Entries[LI].ExtensionType) and MatchesOuter(AInner.Entries[LI], AOuter);
    if LCompressible then
    begin
      if LRunLen = 0 then
        LRunStart := LI;
      Inc(LRunLen);
      if LRunLen > LBestLen then
      begin
        LBestLen := LRunLen;
        LBestStart := LRunStart;
      end;
    end
    else
      LRunLen := 0;
  end;
  AStart := LBestStart;
  ALength := LBestLen;
  // compress any run of at least one extension: even a single shared extension is worth an
  // ech_outer_extensions reference, shrinking the sealed inner and keeping the outer uniform
  Result := LBestLen >= 1;
end;

function TEchClientHandshake.BuildEncodedInner(const AInnerBody: TBytes;
  const AOuter: TExtensionVector): TBytes;
var
  LInner: TTlsClientHello;
  LInnerEntries, LEncodedEntries: TExtensionVector;
  LStart, LLen, LI, LSniLen, LPad: Int32;
  LHasSni: Boolean;
  LRefTypes: TArray<UInt16>;
  LEncoded: TBytes;
begin
  LInner := THandshakeMessages.DecodeClientHello(AInnerBody);
  LInnerEntries := TExtensionVector.Parse(LInner.Extensions);

  LEncodedEntries := LInnerEntries;
  if CompressibleRun(LInnerEntries, AOuter, LStart, LLen) then
  begin
    SetLength(LRefTypes, LLen);
    for LI := 0 to LLen - 1 do
      LRefTypes[LI] := LInnerEntries.Entries[LStart + LI].ExtensionType;
    // inner entries with [LStart..LStart+LLen) replaced by one ech_outer_extensions block
    LEncodedEntries.ReplaceRange(LStart, LLen,
      TExtensionEntry.Create(TExtensionTypes.EchOuterExtensions,
      TEchExtension.EncodeOuterExtensions(LRefTypes)));
  end;

  // EncodedClientHelloInner.client_hello: the inner with an empty legacy_session_id
  LInner.LegacySessionId := nil;
  LInner.Extensions := LEncodedEntries.Encode;
  LEncoded := THandshakeMessages.EncodeClientHello(LInner);

  LSniLen := ServerNameLength(LInnerEntries, LHasSni);
  LPad := PaddingLength(System.Length(LEncoded), LSniLen, LHasSni,
    FConfig.MaximumNameLength);
  Result := LEncoded;
  SetLength(Result, System.Length(LEncoded) + LPad);
end;

function TEchClientHandshake.SetupSeal: TBytes;
begin
  FSuite.SetupSealer(FConfig.PublicKey, FConfig.HpkeInfo, FEnc, FSealer);
  Result := FEnc;
end;

function TEchClientHandshake.Seal(const AAad, APlaintext: TBytes): TBytes;
begin
  Result := FSealer.Seal(AAad, APlaintext);
end;

class function TEchClientHandshake.AcceptConfirmationMatches(const AHkdf: IHkdf;
  const AInnerRandom, ATranscriptEchConf, AServerRandom: TBytes): Boolean;
var
  LComputed, LReceived: TBytes;
  LI: Int32;
begin
  if System.Length(AServerRandom) <> ServerHelloRandomLength then
    Exit(False);
  LComputed := TTls13KeySchedule.EchAcceptConfirmation(AHkdf, AInnerRandom,
    ATranscriptEchConf);
  SetLength(LReceived, TEchExtension.ConfirmationLength);
  for LI := 0 to TEchExtension.ConfirmationLength - 1 do
    LReceived[LI] := AServerRandom[TEchExtension.ServerHelloRandomConfirmationOffset + LI];
  Result := TSecureMemory.ConstantTimeAreEqual(LComputed, LReceived);
end;

end.
