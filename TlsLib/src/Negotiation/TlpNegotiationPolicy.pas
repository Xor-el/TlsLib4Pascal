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
  TlpCryptoDomainTypes,
  TlpNegotiationTypes,
  TlpINegotiation,
  TlpCipherSuiteRegistry;

type
  /// <summary>
  /// The server's pure negotiation policy. Cipher-suite choice follows the registry's order
  /// (server preference) unless the configured preference hands the order to the client.
  /// </summary>
  TNegotiationPolicy = class sealed(TInterfacedObject, INegotiationPolicy)
  strict private
  var
    FCipherSuites: ICipherSuiteRegistry;
    FGroups: INamedGroupRegistry;
    FPreferredGroups: TArray<UInt16>;
    FSupportedVersions: TArray<UInt16>;
    FCipherPreference: TServerCipherPreference;
    /// <summary>The offered suites for ANegotiatedVersion in registry order, filtered to that
    /// version's protocol.</summary>
    function EffectiveSuiteOrder(ANegotiatedVersion: UInt16): TArray<UInt16>;
  public
    constructor Create(const ACipherSuites: ICipherSuiteRegistry;
      const AGroups: INamedGroupRegistry;
      const APreferredGroups, ASupportedVersions: TArray<UInt16>;
      ACipherPreference: TServerCipherPreference);

    function SelectVersion(const AClientVersions: TArray<UInt16>): UInt16;
    function CandidateSuites(const AClientSuites: TArray<UInt16>;
      ANegotiatedVersion: UInt16): TArray<UInt16>;
    function SelectCipherSuite(const AClientSuites: TArray<UInt16>;
      ANegotiatedVersion: UInt16): UInt16;
    function TrySelectCipherSuiteWithHash(const AClientSuites: TArray<UInt16>;
      ANegotiatedVersion: UInt16; AHash: THashAlgorithm; out ASuite: UInt16): Boolean;
    function SelectGroup(const AClientGroups: TArray<UInt16>;
      ANegotiatedVersion: UInt16): UInt16;

    /// <summary>Test-support scaffolding: a policy wired with the default registries (holding
    /// both protocols' suites) and a 1.3-only version set. Production wires the policy from the
    /// configuration.</summary>
    class function CreateDefault(const ACryptoProvider: ICryptoProvider)
      : INegotiationPolicy; static;

    /// <summary>The suite protocol a negotiated wire version uses.</summary>
    class function ProtocolOf(ANegotiatedVersion: UInt16): TSuiteProtocol; static;
    /// <summary>The AProtocol suites of the registry, in registry order: a dual-version registry
    /// never crosses a 1.2 suite onto a 1.3 handshake (or the reverse). The backbone of every
    /// candidate list.</summary>
    class function SuiteOrder(const ASuites: ICipherSuiteRegistry; AProtocol: TSuiteProtocol)
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

{ TNegotiationPolicy }

constructor TNegotiationPolicy.Create(const ACipherSuites: ICipherSuiteRegistry;
  const AGroups: INamedGroupRegistry;
  const APreferredGroups, ASupportedVersions: TArray<UInt16>;
  ACipherPreference: TServerCipherPreference);
begin
  inherited Create;
  FCipherSuites := ACipherSuites;
  FGroups := AGroups;
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

class function TNegotiationPolicy.SuiteOrder(const ASuites: ICipherSuiteRegistry;
  AProtocol: TSuiteProtocol): TArray<UInt16>;
var
  LSuite: TTlsCipherSuite;
begin
  Result := nil;
  for LSuite in ASuites.Items do
    if LSuite.Protocol = AProtocol then
      TArrayUtilities.Append<UInt16>(Result, LSuite.Common.Code);
end;

function TNegotiationPolicy.EffectiveSuiteOrder(
  ANegotiatedVersion: UInt16): TArray<UInt16>;
begin
  Result := SuiteOrder(FCipherSuites, ProtocolOf(ANegotiatedVersion));
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

function TNegotiationPolicy.CandidateSuites(
  const AClientSuites: TArray<UInt16>; ANegotiatedVersion: UInt16): TArray<UInt16>;
var
  LCode: UInt16;
  LServerOrder: TArray<UInt16>;
begin
  Result := nil;
  LServerOrder := EffectiveSuiteOrder(ANegotiatedVersion);
  if FCipherPreference = TServerCipherPreference.ClientOrder then
  begin
    // the client's order, kept to what the server offers (a repeated client entry counts once)
    for LCode in AClientSuites do
      if (TArrayUtilities.Contains<UInt16>(LServerOrder, LCode)) and
        not (TArrayUtilities.Contains<UInt16>(Result, LCode)) then
        TArrayUtilities.Append<UInt16>(Result, LCode);
  end
  else
  begin
    // server preference (default): the server's order, kept to what the client offered
    for LCode in LServerOrder do
      if TArrayUtilities.Contains<UInt16>(AClientSuites, LCode) then
        TArrayUtilities.Append<UInt16>(Result, LCode);
  end;
end;

function TNegotiationPolicy.SelectCipherSuite(
  const AClientSuites: TArray<UInt16>; ANegotiatedVersion: UInt16): UInt16;
var
  LCandidates: TArray<UInt16>;
begin
  LCandidates := CandidateSuites(AClientSuites, ANegotiatedVersion);
  if System.Length(LCandidates) = 0 then
    raise EFatalAlertTlsLibException.CreateRes(TTlsAlertDescription.HandshakeFailure,
      @SNoCommonSuite);
  Result := LCandidates[0];
end;

function TNegotiationPolicy.TrySelectCipherSuiteWithHash(
  const AClientSuites: TArray<UInt16>; ANegotiatedVersion: UInt16;
  AHash: THashAlgorithm; out ASuite: UInt16): Boolean;
var
  LCode: UInt16;
  LSuite: TTlsCipherSuite;
begin
  Result := False;
  ASuite := 0;
  for LCode in CandidateSuites(AClientSuites, ANegotiatedVersion) do
    if FCipherSuites.TryGet(LCode, LSuite) and (LSuite.Common.Hash = AHash) then
    begin
      ASuite := LCode;
      Exit(True);
    end;
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

class function TNegotiationPolicy.CreateDefault(const ACryptoProvider: ICryptoProvider)
  : INegotiationPolicy;
begin
  Result := TNegotiationPolicy.Create(
    TCipherSuiteRegistry.CreateDualVersion(ACryptoProvider),
    TNamedGroups.CreateDefaultRegistry(ACryptoProvider),
    TArray<UInt16>.Create(TNamedGroupCatalog.X25519MlKem768, TNamedGroupCatalog.SecP256r1MlKem768,
    TNamedGroupCatalog.X25519, TNamedGroupCatalog.Secp256r1,
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
begin
  // the random is public data, so a plain compare is fine
  Result := (System.Length(ARandom) = System.Length(HelloRetryRequestSentinel)) and
    CompareMem(@ARandom[0], @HelloRetryRequestSentinel[0],
    System.Length(HelloRetryRequestSentinel));
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
begin
  LSentinel := SentinelFor(ANegotiatedVersion);
  // the sentinel occupies the last 8 of the 32-byte random; public data, plain compare
  Result := (System.Length(LSentinel) = 8) and (System.Length(AServerRandom) >= 32) and
    CompareMem(@AServerRandom[24], @LSentinel[0], 8);
end;

class function TDowngradeProtection.IsDowngradeAttack(const AServerRandom: TBytes;
  AClientSupportsTls13: Boolean; ANegotiatedVersion: UInt16): Boolean;
begin
  // a 1.3-capable client checks for both sentinels whatever lower version was negotiated
  // (RFC 8446 4.1.3): a server stamps either only when it answers below its own highest version
  Result := AClientSupportsTls13 and (ANegotiatedVersion < TlsWireVersionTls13) and
    (HasSentinel(AServerRandom, TlsWireVersionTls12) or
    HasSentinel(AServerRandom, TlsWireVersionTls11));
end;

end.
