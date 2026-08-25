{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpNegotiationPolicy;

{$I ..\Include\TlsLib.inc}

interface

uses
  SysUtils,
  TlpArrayUtilities,
  TlpTlsAlert,
  TlpTlsLibExceptions,
  TlpTlsVersion,
  TlpICryptoProvider,
  TlpINamedGroup,
  TlpNamedGroups,
  TlpCryptoAlgorithms,
  TlpNegotiationTypes,
  TlpINegotiation,
  TlpCipherSuiteRegistry,
  TlpSignatureSchemeRegistry;

type
  /// <summary>
  /// The pure TLS 1.3 negotiation policy. The server calls it to choose from a
  /// client's offers; the client calls the same routines to confirm the server
  /// picked only what was offered. Cipher-suite choice follows a server-preference
  /// backbone with the AEAD group reordered by the provider's HasHardwareAes -
  /// ChaCha20-Poly1305 ahead of AES-GCM only when there is no hardware AES (a
  /// performance ordering; the software AES-GCM path is constant-time either way).
  /// </summary>
  TNegotiationPolicy = class sealed(TInterfacedObject, INegotiationPolicy)
  strict private
  var
    FProvider: ICryptoProvider;
    FCipherSuites: ICipherSuiteRegistry;
    FGroups: INamedGroupRegistry;
    FSignatureSchemes: ISignatureSchemeRegistry;
    FPreferredGroups: TArray<UInt16>;
    FSupportedVersions: TArray<UInt16>;
    FCipherPreference: TServerCipherPreference;
    /// <summary>The offered suites for ANegotiatedVersion in preference order (the
    /// hardware-AES tiebreak applied), filtered to that version's protocol.</summary>
    function EffectiveSuiteOrder(ANegotiatedVersion: UInt16): TArray<UInt16>;
    class function ProtocolOf(ANegotiatedVersion: UInt16): TSuiteProtocol; static;
  public
    constructor Create(const AProvider: ICryptoProvider;
      const ACipherSuites: ICipherSuiteRegistry; const AGroups: INamedGroupRegistry;
      const ASignatureSchemes: ISignatureSchemeRegistry;
      const APreferredGroups, ASupportedVersions: TArray<UInt16>;
      ACipherPreference: TServerCipherPreference);

    function SelectVersion(const AClientVersions: TArray<UInt16>): UInt16;
    function SelectCipherSuite(const AClientSuites: TArray<UInt16>;
      ANegotiatedVersion: UInt16): UInt16;
    function SelectGroup(const AClientGroups: TArray<UInt16>;
      ANegotiatedVersion: UInt16): UInt16;
    function SelectSignatureScheme(const AClientSchemes: TArray<UInt16>): UInt16;

    /// <summary>A policy wired with the default registries and a 1.3-only version set.</summary>
    class function CreateDefault(const AProvider: ICryptoProvider)
      : INegotiationPolicy; static;

    /// <summary>The AProtocol suites in server-preference order with the hardware-AES
    /// tiebreak applied (ChaCha20-Poly1305 ahead of AES-GCM only without hardware AES).
    /// The one order the 1.3 fresh path, the 1.2 server, and the 1.3 PSK pick all share.</summary>
    class function SuitePreferenceOrder(const AProvider: ICryptoProvider;
      const ASuites: ICipherSuiteRegistry; AProtocol: TSuiteProtocol)
      : TArray<UInt16>; static;
  end;

  /// <summary>
  /// The HelloRetryRequest sentinel (RFC 8446 4.1.3): a HelloRetryRequest is a
  /// ServerHello whose random is the fixed SHA-256("HelloRetryRequest") value, so
  /// both roles recognize it by that random without a distinct message type.
  /// </summary>
  THelloRetryRequest = class sealed(TObject)
  public
    /// <summary>A fresh copy of the 32-byte sentinel random to place in a HelloRetryRequest.</summary>
    class function SentinelRandom: TBytes; static;
    /// <summary>Whether ARandom is the HelloRetryRequest sentinel.</summary>
    class function IsSentinel(const ARandom: TBytes): Boolean; static;
  end;

  /// <summary>
  /// The ServerHello.random downgrade sentinel (RFC 8446 4.1.3): a 1.3-capable
  /// server that negotiates a lower version stamps the last 8 bytes, and a
  /// 1.3-capable client aborts if it sees that stamp on a downgraded connection.
  /// </summary>
  TDowngradeProtection = class sealed(TObject)
  public
    /// <summary>The sentinel bytes to place, or nil when the negotiated version is 1.3.</summary>
    class function SentinelFor(ANegotiatedVersion: UInt16): TBytes; static;
    /// <summary>Whether AServerRandom's last 8 bytes carry the sentinel for ANegotiatedVersion.</summary>
    class function HasSentinel(const AServerRandom: TBytes;
      ANegotiatedVersion: UInt16): Boolean; static;
    /// <summary>Whether a 1.3-capable client should treat this as a downgrade attack.</summary>
    class function IsDowngradeAttack(const AServerRandom: TBytes;
      AClientSupportsTls13: Boolean; ANegotiatedVersion: UInt16): Boolean; static;
  end;

implementation

resourcestring
  SNoCommonVersion = 'no mutually supported protocol version';
  SNoCommonSuite = 'no mutually supported cipher suite';
  SNoCommonGroup = 'no mutually supported named group';
  SNoCommonScheme = 'no mutually supported signature scheme';

{ TNegotiationPolicy }

constructor TNegotiationPolicy.Create(const AProvider: ICryptoProvider;
  const ACipherSuites: ICipherSuiteRegistry; const AGroups: INamedGroupRegistry;
  const ASignatureSchemes: ISignatureSchemeRegistry;
  const APreferredGroups, ASupportedVersions: TArray<UInt16>;
  ACipherPreference: TServerCipherPreference);
begin
  inherited Create;
  FProvider := AProvider;
  FCipherSuites := ACipherSuites;
  FGroups := AGroups;
  FSignatureSchemes := ASignatureSchemes;
  FPreferredGroups := APreferredGroups;
  FSupportedVersions := ASupportedVersions;
  FCipherPreference := ACipherPreference;
end;

class function TNegotiationPolicy.ProtocolOf(
  ANegotiatedVersion: UInt16): TSuiteProtocol;
begin
  if ANegotiatedVersion = TlsWireVersionTls13 then
    Result := TSuiteProtocol.Tls13
  else
    Result := TSuiteProtocol.Tls12;
end;

class function TNegotiationPolicy.SuitePreferenceOrder(
  const AProvider: ICryptoProvider; const ASuites: ICipherSuiteRegistry;
  AProtocol: TSuiteProtocol): TArray<UInt16>;
var
  LAes, LChaCha: TArray<UInt16>;
  LSuite: TTlsCipherSuite;

  procedure Append(var ATarget: TArray<UInt16>; ACode: UInt16);
  var
    LLen: Int32;
  begin
    LLen := System.Length(ATarget);
    SetLength(ATarget, LLen + 1);
    ATarget[LLen] := ACode;
  end;

begin
  LAes := nil;
  LChaCha := nil;
  // only this protocol's suites are eligible, so a dual-version registry never crosses
  // a 1.2 suite onto a 1.3 handshake (or the reverse)
  for LSuite in ASuites.Items do
    if LSuite.Protocol = AProtocol then
      if LSuite.Common.Aead = TAeadAlgorithm.CHACHA20_POLY1305 then
        Append(LChaCha, LSuite.Common.Code)
      else
        Append(LAes, LSuite.Common.Code);
  // AES-GCM first when hardware AES is present; otherwise ChaCha20-Poly1305 first
  if AProvider.Primitives.HasHardwareAes then
    Result := System.Concat(LAes, LChaCha)
  else
    Result := System.Concat(LChaCha, LAes);
end;

function TNegotiationPolicy.EffectiveSuiteOrder(
  ANegotiatedVersion: UInt16): TArray<UInt16>;
begin
  Result := SuitePreferenceOrder(FProvider, FCipherSuites,
    ProtocolOf(ANegotiatedVersion));
end;

function TNegotiationPolicy.SelectVersion(
  const AClientVersions: TArray<UInt16>): UInt16;
var
  LVersion: UInt16;
begin
  // FSupportedVersions is highest-preference first
  for LVersion in FSupportedVersions do
    if TArrayUtilities.Contains<UInt16>(AClientVersions, LVersion) then
      Exit(LVersion);
  raise EFatalAlertTlsLibException.CreateRes(TTlsAlertDescription.ProtocolVersion,
    @SNoCommonVersion);
end;

function TNegotiationPolicy.SelectCipherSuite(
  const AClientSuites: TArray<UInt16>; ANegotiatedVersion: UInt16): UInt16;
var
  LCode: UInt16;
  LServerOrder: TArray<UInt16>;
begin
  LServerOrder := EffectiveSuiteOrder(ANegotiatedVersion);
  if FCipherPreference = TServerCipherPreference.ClientOrder then
  begin
    // honor the client's preference: the client's most-preferred suite the server also offers
    for LCode in AClientSuites do
      if TArrayUtilities.Contains<UInt16>(LServerOrder, LCode) then
        Exit(LCode);
  end
  else
  begin
    // server preference (default): the server's most-preferred suite the client also offered
    for LCode in LServerOrder do
      if TArrayUtilities.Contains<UInt16>(AClientSuites, LCode) then
        Exit(LCode);
  end;
  raise EFatalAlertTlsLibException.CreateRes(TTlsAlertDescription.HandshakeFailure,
    @SNoCommonSuite);
end;

function TNegotiationPolicy.SelectGroup(
  const AClientGroups: TArray<UInt16>; ANegotiatedVersion: UInt16): UInt16;
var
  LCode: UInt16;
  LGroup: INamedGroup;
  LEcdheOnly: Boolean;
begin
  // TLS 1.2 excludes KEM and hybrid groups: only classical ECDHE is eligible
  LEcdheOnly := ProtocolOf(ANegotiatedVersion) = TSuiteProtocol.Tls12;
  for LCode in FPreferredGroups do
    if (TArrayUtilities.Contains<UInt16>(AClientGroups, LCode)) and
      FGroups.TryGet(LCode, LGroup) and
      (not LEcdheOnly or (LGroup.Kind = TNamedGroupKind.Ecdhe)) then
      Exit(LCode);
  raise EFatalAlertTlsLibException.CreateRes(TTlsAlertDescription.HandshakeFailure,
    @SNoCommonGroup);
end;

function TNegotiationPolicy.SelectSignatureScheme(
  const AClientSchemes: TArray<UInt16>): UInt16;
var
  LScheme: TSignatureScheme;
begin
  for LScheme in FSignatureSchemes.Items do
    if TArrayUtilities.Contains<UInt16>(AClientSchemes, LScheme.ToCode) then
      Exit(LScheme.ToCode);
  raise EFatalAlertTlsLibException.CreateRes(TTlsAlertDescription.HandshakeFailure,
    @SNoCommonScheme);
end;

class function TNegotiationPolicy.CreateDefault(const AProvider: ICryptoProvider)
  : INegotiationPolicy;
begin
  Result := TNegotiationPolicy.Create(AProvider,
    TCipherSuiteRegistry.CreateDefault(AProvider),
    TNamedGroups.CreateDefaultRegistry(AProvider),
    TSignatureSchemeRegistry.CreateDefault,
    TArray<UInt16>.Create(TNamedGroupCatalog.X25519MlKem768, TNamedGroupCatalog.X25519, TNamedGroupCatalog.Secp256r1,
    TNamedGroupCatalog.Secp384r1, TNamedGroupCatalog.Secp521r1),
    TArray<UInt16>.Create(TlsWireVersionTls13), TServerCipherPreference.ServerOrder);
end;

{ THelloRetryRequest }

class function THelloRetryRequest.SentinelRandom: TBytes;
begin
  Result := nil;
  SetLength(Result, System.Length(HelloRetryRequestSentinel));
  Move(HelloRetryRequestSentinel[0], Result[0], System.Length(Result));
end;

class function THelloRetryRequest.IsSentinel(const ARandom: TBytes): Boolean;
var
  LI: Int32;
begin
  Result := System.Length(ARandom) = System.Length(HelloRetryRequestSentinel);
  if not Result then
    Exit;
  // the random is public data, so a plain compare is fine (like the downgrade sentinel)
  for LI := 0 to System.High(HelloRetryRequestSentinel) do
    if ARandom[LI] <> HelloRetryRequestSentinel[LI] then
      Exit(False);
end;

{ TDowngradeProtection }

class function TDowngradeProtection.SentinelFor(ANegotiatedVersion: UInt16): TBytes;
begin
  Result := nil;
  if ANegotiatedVersion >= TlsWireVersionTls13 then
    Exit;
  SetLength(Result, 8);
  if ANegotiatedVersion = TlsWireVersionTls12 then
    Move(Tls12DowngradeSentinel[0], Result[0], 8)
  else
    Move(Tls11DowngradeSentinel[0], Result[0], 8);
end;

class function TDowngradeProtection.HasSentinel(const AServerRandom: TBytes;
  ANegotiatedVersion: UInt16): Boolean;
var
  LSentinel: TBytes;
  LI: Int32;
begin
  Result := False;
  LSentinel := SentinelFor(ANegotiatedVersion);
  if (System.Length(LSentinel) <> 8) or (System.Length(AServerRandom) < 32) then
    Exit;
  // the sentinel occupies the last 8 of the 32-byte random; public data, plain compare
  for LI := 0 to 7 do
    if AServerRandom[24 + LI] <> LSentinel[LI] then
      Exit;
  Result := True;
end;

class function TDowngradeProtection.IsDowngradeAttack(const AServerRandom: TBytes;
  AClientSupportsTls13: Boolean; ANegotiatedVersion: UInt16): Boolean;
begin
  Result := AClientSupportsTls13 and (ANegotiatedVersion < TlsWireVersionTls13) and
    HasSentinel(AServerRandom, ANegotiatedVersion);
end;

end.
