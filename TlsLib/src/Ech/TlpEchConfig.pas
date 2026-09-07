{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpEchConfig;

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
  TlpTlsLibExceptions;

type
  /// <summary>
  /// The Encrypted Client Hello outcome of a handshake (RFC 9849), surfaced on the
  /// connection info: ECH was not offered, a GREASE ECH was sent, the server accepted
  /// ECH, the server rejected it (the handshake ran to the public_name), or this is a
  /// backend server that received an already-decrypted inner ClientHello.
  /// </summary>
  TEchStatus = (NotOffered, Greased, Accepted, Rejected, Backend);

  /// <summary>
  /// One HPKE symmetric cipher suite advertised by an ECHConfig (RFC 9849 sec. 4):
  /// the (kdf_id, aead_id) pair. The KEM is carried once at the config level, so this
  /// stays a faithful pair - the KEM is joined in only when a suite is selected.
  /// </summary>
  TEchCipherSuite = record
    KdfId: UInt16;
    AeadId: UInt16;
  end;

  /// <summary>One ECHConfig extension (RFC 9849 sec. 4.2): a type and its opaque data.</summary>
  TEchConfigExtension = record
    ExtType: UInt16;
    Data: TBytes;
  end;

  /// <summary>
  /// A parsed ECHConfig (RFC 9849 sec. 4). Holds the key configuration, the
  /// public_name the ClientHelloOuter is addressed to, and the raw config bytes
  /// (version || length || contents) so the HPKE info string is byte-exact.
  /// </summary>
  TEchConfig = record
  public const
    /// <summary>The only ECHConfig version this library implements.</summary>
    SupportedVersion = UInt16($FE0D);
  strict private
  var
    FVersion: UInt16;
    FConfigId: Byte;
    FKemId: UInt16;
    FPublicKey: TBytes;
    FCipherSuites: TArray<TEchCipherSuite>;
    FMaximumNameLength: Byte;
    FPublicName: TBytes;
    FExtensions: TArray<TEchConfigExtension>;
    FRaw: TBytes;
    class function IsAllDigitsOrHex(const ALabel: TBytes; AStart, ALen: Int32): Boolean; static;
  private
    /// <summary>The version, public_name, extension, and public_key checks a usable config
    /// must pass, independent of cipher-suite selection.</summary>
    function IsStructurallyUsable(const AProvider: ICryptoProvider): Boolean;
  public
    /// <summary>Parses one ECHConfig from AReader (advancing past it) and captures its
    /// raw bytes. Raises EDecodeErrorTlsLibException on a malformed structure.</summary>
    class function Parse(var AReader: TWireReader): TEchConfig; static;
    /// <summary>
    /// Builds an ECHConfig from its fields (used by the key generator and the server
    /// key store). The raw bytes are the canonical encoding, so HpkeInfo is consistent
    /// between a built config and the same config parsed back from the wire.
    /// </summary>
    class function Build(AVersion: UInt16; AConfigId: Byte; AKemId: UInt16;
      const APublicKey: TBytes; const ACipherSuites: TArray<TEchCipherSuite>;
      AMaximumNameLength: Byte; const APublicName: TBytes;
      const AExtensions: TArray<TEchConfigExtension>): TEchConfig; static;
    /// <summary>Whether AName is a valid ECH public_name: a dot-separated sequence of LDH
    /// labels whose final label is not all-digits or 0x-hex (RFC 9849 sec. 6.1.7). Exposed so
    /// the key generator can reject an operator-supplied name before minting a config.</summary>
    class function IsValidPublicName(const AName: TBytes): Boolean; static;
    /// <summary>Serializes this config as version || length || contents (RFC 9849 sec. 4).</summary>
    function Encode: TBytes;
    /// <summary>The HPKE info: "tls ech" || 0x00 || ECHConfig (RFC 9849 sec. 6.1).</summary>
    function HpkeInfo: TBytes;
    /// <summary>The public_name as an ASCII string.</summary>
    function PublicName: string;
    /// <summary>
    /// The first advertised cipher suite AProvider can instantiate (in advertised
    /// order), joined with the config's KEM into a full HPKE suite. False when none is
    /// supported - which also means the KEM is unsupported.
    /// </summary>
    function TrySelectSuite(const AProvider: ICryptoProvider;
      out ASuite: IHpkeSuite): Boolean;
    /// <summary>
    /// Whether a client may offer ECH with this config (RFC 9849 sec. 4.1, 6.1): a
    /// supported version, a valid public_name, no duplicate or unsupported-mandatory
    /// extension, and at least one KEM/KDF/AEAD suite the provider supports. An
    /// unusable config is skipped, never fatal.
    /// </summary>
    function IsUsable(const AProvider: ICryptoProvider): Boolean;
    property Version: UInt16 read FVersion;
    property ConfigId: Byte read FConfigId;
    property KemId: UInt16 read FKemId;
    property PublicKey: TBytes read FPublicKey;
    property CipherSuites: TArray<TEchCipherSuite> read FCipherSuites;
    property MaximumNameLength: Byte read FMaximumNameLength;
    property Extensions: TArray<TEchConfigExtension> read FExtensions;
    property Raw: TBytes read FRaw;
  end;

  /// <summary>
  /// One server ECH key: an ECHConfig, its HPKE recipient key prepared once (build it with
  /// ICryptoProvider.Hpke.ImportRecipientKey), and whether it is advertised in retry_configs.
  /// The operator adds and removes these to track what was published in DNS (RFC 9934),
  /// rotating by swapping in a new store.
  /// </summary>
  TEchKeyEntry = record
    Config: TEchConfig;
    RecipientKey: IHpkeRecipientKey;
    IsRetry: Boolean;
  end;

  /// <summary>
  /// The ECHConfigList codec (RFC 9849 sec. 4): a length-prefixed list of ECHConfigs
  /// in decreasing order of preference. A malformed list is a typed decode error; an
  /// individual unusable config is skipped by the selector, not fatal.
  /// </summary>
  TEchConfigList = class sealed(TObject)
  public
    /// <summary>Parses an ECHConfigList. Raises EDecodeErrorTlsLibException if the outer
    /// structure is malformed.</summary>
    class function Parse(const AData: TBytes): TArray<TEchConfig>; static;
    /// <summary>Serializes a list of configs as an ECHConfigList.</summary>
    class function Encode(const AConfigs: TArray<TEchConfig>): TBytes; static;
    /// <summary>
    /// The first usable config and the HPKE suite selected for it (RFC 9849 sec. 6.1 -
    /// first match in preference order). False when no config is usable.
    /// </summary>
    class function TrySelect(const AConfigs: TArray<TEchConfig>;
      const AProvider: ICryptoProvider; out AConfig: TEchConfig;
      out ASuite: IHpkeSuite): Boolean; static;
  end;

implementation

resourcestring
  SMalformedConfig = 'malformed ECHConfig';

const
  MandatoryExtensionBit = UInt16($8000);

{ TEchConfig }

class function TEchConfig.Parse(var AReader: TWireReader): TEchConfig;
var
  LVersion, LLength: UInt16;
  LContentBytes: TBytes;
  LContents, LKey, LSuites, LName, LExts, LExtData: TWireReader;
  LConfig: TEchConfig;
  LSuiteCount, LExtCount: Int32;
  LWriter: IWireWriter;
begin
  LVersion := AReader.ReadUInt16;
  LLength := AReader.ReadUInt16;
  // bound the contents to the declared length; a version we do not implement is still
  // structurally skipped by consuming exactly length bytes
  LContentBytes := AReader.ReadBytes(LLength);
  LContents := TWireReader.Create(LContentBytes);

  LConfig := Default(TEchConfig);
  LConfig.FVersion := LVersion;

  if LVersion = SupportedVersion then
  begin
    LConfig.FConfigId := LContents.ReadUInt8;
    LConfig.FKemId := LContents.ReadUInt16;
    LKey := LContents.OpenVector(2);
    LConfig.FPublicKey := LKey.ReadBytes(LKey.Remaining);

    // each cipher suite is exactly 4 bytes (kdf + aead) and each extension at least 4 (type +
    // length), so Remaining div 4 is an upper bound on the count: preallocate once and trim,
    // never grow per entry - a retry_configs list arrives before the server is authenticated,
    // so an oversized one must not force a quadratic reallocation
    LSuites := LContents.OpenVector(2);
    SetLength(LConfig.FCipherSuites, LSuites.Remaining div 4);
    LSuiteCount := 0;
    while LSuites.Remaining >= 4 do
    begin
      LConfig.FCipherSuites[LSuiteCount].KdfId := LSuites.ReadUInt16;
      LConfig.FCipherSuites[LSuiteCount].AeadId := LSuites.ReadUInt16;
      Inc(LSuiteCount);
    end;
    LSuites.ExpectEnd; // a trailing 1..3 bytes is a malformed suites vector
    SetLength(LConfig.FCipherSuites, LSuiteCount);

    LConfig.FMaximumNameLength := LContents.ReadUInt8;
    LName := LContents.OpenVector(1);
    LConfig.FPublicName := LName.ReadBytes(LName.Remaining);

    LExts := LContents.OpenVector(2);
    SetLength(LConfig.FExtensions, LExts.Remaining div 4);
    LExtCount := 0;
    while LExts.Remaining >= 4 do
    begin
      LConfig.FExtensions[LExtCount].ExtType := LExts.ReadUInt16;
      LExtData := LExts.OpenVector(2);
      LConfig.FExtensions[LExtCount].Data := LExtData.ReadBytes(LExtData.Remaining);
      Inc(LExtCount);
    end;
    LExts.ExpectEnd; // a dangling 1..3 bytes after the last extension is malformed
    SetLength(LConfig.FExtensions, LExtCount);
    LContents.ExpectEnd;
  end;

  // capture the exact wire bytes (version || length || contents) for HpkeInfo
  LWriter := TWireWriter.Create;
  LWriter.WriteUInt16(LVersion);
  LWriter.WriteUInt16(LLength);
  LWriter.WriteBytes(LContentBytes);
  LConfig.FRaw := LWriter.ToBytes;

  Result := LConfig;
end;

class function TEchConfig.Build(AVersion: UInt16; AConfigId: Byte;
  AKemId: UInt16; const APublicKey: TBytes;
  const ACipherSuites: TArray<TEchCipherSuite>; AMaximumNameLength: Byte;
  const APublicName: TBytes;
  const AExtensions: TArray<TEchConfigExtension>): TEchConfig;
begin
  Result := Default(TEchConfig);
  Result.FVersion := AVersion;
  Result.FConfigId := AConfigId;
  Result.FKemId := AKemId;
  Result.FPublicKey := APublicKey;
  Result.FCipherSuites := ACipherSuites;
  Result.FMaximumNameLength := AMaximumNameLength;
  Result.FPublicName := APublicName;
  Result.FExtensions := AExtensions;
  Result.FRaw := Result.Encode;
end;

function TEchConfig.Encode: TBytes;
var
  LWriter: IWireWriter;
  LOuter, LKey, LSuites, LName, LExts, LExtData: TWireVectorMarker;
  LSuite: TEchCipherSuite;
  LExt: TEchConfigExtension;
begin
  LWriter := TWireWriter.Create;
  LWriter.WriteUInt16(FVersion);
  LOuter := LWriter.OpenVector(2);
  LWriter.WriteUInt8(FConfigId);
  LWriter.WriteUInt16(FKemId);
  LKey := LWriter.OpenVector(2);
  LWriter.WriteBytes(FPublicKey);
  LWriter.CloseVector(LKey);
  LSuites := LWriter.OpenVector(2);
  for LSuite in FCipherSuites do
  begin
    LWriter.WriteUInt16(LSuite.KdfId);
    LWriter.WriteUInt16(LSuite.AeadId);
  end;
  LWriter.CloseVector(LSuites);
  LWriter.WriteUInt8(FMaximumNameLength);
  LName := LWriter.OpenVector(1);
  LWriter.WriteBytes(FPublicName);
  LWriter.CloseVector(LName);
  LExts := LWriter.OpenVector(2);
  for LExt in FExtensions do
  begin
    LWriter.WriteUInt16(LExt.ExtType);
    LExtData := LWriter.OpenVector(2);
    LWriter.WriteBytes(LExt.Data);
    LWriter.CloseVector(LExtData);
  end;
  LWriter.CloseVector(LExts);
  LWriter.CloseVector(LOuter);
  Result := LWriter.ToBytes;
end;

function TEchConfig.HpkeInfo: TBytes;
var
  LWriter: IWireWriter;
begin
  // "tls ech" || 0x00 || ECHConfig (RFC 9849 sec. 6.1)
  LWriter := TWireWriter.Create;
  LWriter.WriteBytes(TBytes.Create($74, $6C, $73, $20, $65, $63, $68));
  LWriter.WriteUInt8(0);
  LWriter.WriteBytes(FRaw);
  Result := LWriter.ToBytes;
end;

function TEchConfig.PublicName: string;
begin
  Result := TEncoding.ASCII.GetString(FPublicName);
end;

function TEchConfig.TrySelectSuite(const AProvider: ICryptoProvider;
  out ASuite: IHpkeSuite): Boolean;
var
  LSuite: TEchCipherSuite;
begin
  Result := False;
  for LSuite in FCipherSuites do
  begin
    ASuite := AProvider.Hpke.Suite(FKemId, LSuite.KdfId, LSuite.AeadId);
    if ASuite <> nil then
      Exit(True);
  end;
end;

function TEchConfig.IsStructurallyUsable(
  const AProvider: ICryptoProvider): Boolean;
var
  LExt: TEchConfigExtension;
  LOther: TEchConfigExtension;
  LI, LJ: Int32;
begin
  Result := False;
  if FVersion <> SupportedVersion then
    Exit;
  if not IsValidPublicName(FPublicName) then
    Exit;
  // reject an unsupported mandatory extension (high bit set) or a duplicate type
  for LI := 0 to System.High(FExtensions) do
  begin
    LExt := FExtensions[LI];
    if (LExt.ExtType and MandatoryExtensionBit) <> 0 then
      Exit;
    for LJ := LI + 1 to System.High(FExtensions) do
    begin
      LOther := FExtensions[LJ];
      if LOther.ExtType = LExt.ExtType then
        Exit;
    end;
  end;
  // the public_key must be a well-formed KEM key (a DNS-published config could carry a wrong
  // length or an invalid EC point); an unusable one is skipped, never sealed against
  Result := AProvider.Hpke.ValidatePublicKey(FKemId, FPublicKey);
end;

function TEchConfig.IsUsable(const AProvider: ICryptoProvider): Boolean;
var
  LSuite: IHpkeSuite;
begin
  Result := IsStructurallyUsable(AProvider) and TrySelectSuite(AProvider, LSuite);
end;

class function TEchConfig.IsAllDigitsOrHex(const ALabel: TBytes;
  AStart, ALen: Int32): Boolean;
var
  LI: Int32;
  LAllDigits: Boolean;
  LB: Byte;
begin
  // RFC 9849 sec. 6.1.7: reject a final label that is all ASCII digits, or "0x"/"0X"
  // followed by a (possibly empty) run of ASCII hex digits
  LAllDigits := True;
  for LI := AStart to AStart + ALen - 1 do
  begin
    LB := ALabel[LI];
    if (LB < Ord('0')) or (LB > Ord('9')) then
    begin
      LAllDigits := False;
      Break;
    end;
  end;
  if LAllDigits then
    Exit(True);
  if (ALen >= 2) and (ALabel[AStart] = Ord('0')) and
    ((ALabel[AStart + 1] = Ord('x')) or (ALabel[AStart + 1] = Ord('X'))) then
  begin
    for LI := AStart + 2 to AStart + ALen - 1 do
    begin
      LB := ALabel[LI];
      if not (((LB >= Ord('0')) and (LB <= Ord('9'))) or
        ((LB >= Ord('a')) and (LB <= Ord('f'))) or
        ((LB >= Ord('A')) and (LB <= Ord('F')))) then
        Exit(False);
    end;
    Exit(True);
  end;
  Result := False;
end;

class function TEchConfig.IsValidPublicName(const AName: TBytes): Boolean;
var
  LI, LLabelStart, LLabelLen, LLastStart, LLastLen: Int32;
  LB: Byte;
begin
  // RFC 9849 sec. 6.1.7: a dot-separated sequence of LDH labels; not beginning or
  // ending with a dot; each label 1..63 octets of letters/digits/hyphen and neither
  // beginning nor ending with a hyphen (RFC 5890); the final label is not all-digits nor 0x-hex.
  if (System.Length(AName) < 1) or (System.Length(AName) > 255) then
    Exit(False);
  if (AName[0] = Ord('.')) or (AName[System.High(AName)] = Ord('.')) then
    Exit(False);
  LLabelStart := 0;
  LLastStart := 0;
  LLastLen := 0;
  LI := 0;
  while LI <= System.Length(AName) do
  begin
    if (LI = System.Length(AName)) or (AName[LI] = Ord('.')) then
    begin
      LLabelLen := LI - LLabelStart;
      if (LLabelLen < 1) or (LLabelLen > 63) then
        Exit(False);
      if (AName[LLabelStart] = Ord('-')) or (AName[LI - 1] = Ord('-')) then
        Exit(False);
      LLastStart := LLabelStart;
      LLastLen := LLabelLen;
      LLabelStart := LI + 1;
    end
    else
    begin
      LB := AName[LI];
      if not (((LB >= Ord('a')) and (LB <= Ord('z'))) or
        ((LB >= Ord('A')) and (LB <= Ord('Z'))) or
        ((LB >= Ord('0')) and (LB <= Ord('9'))) or (LB = Ord('-'))) then
        Exit(False);
    end;
    Inc(LI);
  end;
  Result := not IsAllDigitsOrHex(AName, LLastStart, LLastLen);
end;

{ TEchConfigList }

class function TEchConfigList.Parse(const AData: TBytes): TArray<TEchConfig>;
var
  LReader, LList: TWireReader;
  LCount: Int32;
begin
  Result := nil;
  LReader := TWireReader.Create(AData);
  LList := LReader.OpenVector(2);
  LReader.ExpectEnd;
  LCount := 0;
  while not LList.EndReached do
  begin
    SetLength(Result, LCount + 1);
    Result[LCount] := TEchConfig.Parse(LList);
    Inc(LCount);
  end;
  if LCount = 0 then
    raise EDecodeErrorTlsLibException.CreateRes(@SMalformedConfig);
end;

class function TEchConfigList.Encode(const AConfigs: TArray<TEchConfig>): TBytes;
var
  LWriter: IWireWriter;
  LMarker: TWireVectorMarker;
  LI: Int32;
begin
  LWriter := TWireWriter.Create;
  LMarker := LWriter.OpenVector(2);
  for LI := 0 to System.High(AConfigs) do
    // re-emit each config verbatim, so one of a version this library does not model survives intact
    LWriter.WriteBytes(AConfigs[LI].Raw);
  LWriter.CloseVector(LMarker);
  Result := LWriter.ToBytes;
end;

class function TEchConfigList.TrySelect(const AConfigs: TArray<TEchConfig>;
  const AProvider: ICryptoProvider; out AConfig: TEchConfig;
  out ASuite: IHpkeSuite): Boolean;
var
  LI: Int32;
begin
  Result := False;
  for LI := 0 to System.High(AConfigs) do
    if AConfigs[LI].IsStructurallyUsable(AProvider) and
      AConfigs[LI].TrySelectSuite(AProvider, ASuite) then
    begin
      AConfig := AConfigs[LI];
      Exit(True);
    end;
end;

end.
