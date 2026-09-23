{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlsConnectionTests;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
{$IFDEF FPC}
  fpcunit,
  testregistry,
{$ELSE}
  TestFramework,
{$ENDIF FPC}
  Classes,
  SysUtils,
  TlpTlsAlert,
  TlpTlsVersion,
  TlpEchConfig,
  TlpIPkixProvider,
  TlpDefaultCryptoProvider,
  TlpDefaultPkixProvider,
  TlpICertificateTrust,
  TlpTrustTypes,
  TlpCertificateVerifier,
  TlpServerName,
  TlpTrustPolicy,
  TlpTlsCredential,
  TlpITlsConfig,
  TlpITlsConfigBuilder,
  TlpITlsConfigMemo,
  TlpTlsConfigMemo,
  TlpITlsTransport,
  TlpTlsLibExceptions,
  TlpTlsConnection,
  TlsLibTestBase;

type
  TTestTlsConnection = class(TTlsLibAlgorithmTestCase)
  strict private
    function StubVerifyCallback(const AChain: TArray<TBytes>;
      const AHostName: string): Boolean;
    function StubResolver(const ACtx: TCertificateVerdictContext;
      out ARejectAlert: TTlsAlertDescription): Boolean;
    function StubResolverAlt(const ACtx: TCertificateVerdictContext;
      out ARejectAlert: TTlsAlertDescription): Boolean;
    function ServerCert: TBytes;
    function ServerKey: TBytes;
    function RootAnchor: TBytes;
    // client options with a trust source so the build always succeeds
    function ClientOptsWithStore: TTlsOptions;
    // server options with a valid credential so the build always succeeds
    function ServerOptsWithCredential: TTlsOptions;
    function RaisesStreamError(const AOpts: TTlsOptions;
      AIsClient: Boolean; out AMessage: string): Boolean;
  published
    // composer - client shape (a concern per assertion)
    procedure TestClientDefaultsToSharedProviders;
    procedure TestClientUsesInjectedProviders;
    procedure TestClientCustomStoreComposes;
    procedure TestClientNoSourceFailsClosedWithHint;
    procedure TestClientInsecureSkipVerifyBuildsWithSkipFlag;
    procedure TestClientVerifyPeerOffSetsSkipFlag;
    procedure TestClientCheckHostNameOffDisablesNameCheck;
    procedure TestClientAlpnForwarded;
    procedure TestClientVerifyCallbackForwarded;
    procedure TestClientVerdictResolverArmsLiveRevocation;
    procedure TestClientNoResolverLeavesInlineVerdict;
    procedure TestClientResumptionOnAddsCache;
    procedure TestClientResumptionOffDisablesCache;
    procedure TestClientSystemTrustInstallerCalledForClientRole;
    procedure TestClientVerifierComposesAndBuilds;
    procedure TestClientVerifierWithAnchorConflictPropagates;
    procedure TestClientRaisingInstallerPropagates;
    // composer - server shape
    procedure TestServerNoCredentialRaises;
    procedure TestServerCredentialBuilds;
    procedure TestServerNoClientSourceLeavesNoClientAuth;
    procedure TestServerClientSourceAppliesClientAuthMode;
    procedure TestServerVerdictResolverArmsLiveRevocation;
    procedure TestServerVerdictResolverNoSourceStaysInline;
    procedure TestServerVerifyPeerOffLeavesNoClientAuth;
    procedure TestServerSystemTrustInstallerCalledForServerRole;
    procedure TestServerResumptionMintsDefaultStek;
    // signatures
    procedure TestSignatureEqualOptionsEqualKeys;
    procedure TestSignatureEachConcernChangesKey;
    procedure TestSignatureExcludesResolverAndTimeout;
    procedure TestSignaturePasswordNotInClear;
    // resolve + memo + config-in + guard
    procedure TestResolveMemoisesBuildOnce;
    procedure TestResolveConfigInReturnedAsIs;
    procedure TestGuardConflictOnEachField;
    procedure TestGuardIncludesVerifyCallback;
    procedure TestGuardMessageNamesTheProperty;
    procedure TestGuardIgnoresResolverAndTimeout;
    procedure TestServerClientAuthRequestedWithoutSourceRaises;
    procedure TestServerGuardAllowsClientOnlyOptions;
    procedure TestClientGuardFlagsServerCertVerifier;
    // timed transport
    procedure TestTransportTimesOutWhenSilent;
    procedure TestTransportReturnsDataWhenReadable;
    procedure TestTransportCapZeroDoesNotWait;
    procedure TestTransportNegativeReceiveIsEof;
    procedure TestTransportWriteCompletesOverPartialSends;
    procedure TestTransportSetReadTimeoutIsObservable;
  end;

implementation

type
  // records which role method the composer invoked, and with which pkix; installs an (empty) store
  // so the surrounding build still succeeds. Optionally raises to prove propagation.
  TFakeSystemTrustInstaller = class(TInterfacedObject, ISystemTrustInstaller)
  strict private
    FRaise: Boolean;
  public
    ClientRoleCalled: Boolean;
    ServerRoleCalled: Boolean;
    ClientPkix: IPkixProvider;
    ServerPkix: IPkixProvider;
    constructor Create(ARaise: Boolean);
    procedure InstallClientTrust(const ABuilder: ITlsClientConfigBuilder;
      const APkix: IPkixProvider);
    procedure InstallClientAuthTrust(const ABuilder: ITlsServerConfigBuilder;
      const APkix: IPkixProvider);
  end;

  // an always-reject verifier - the composer only wires it; nothing here runs a handshake
  TFakeServerVerifier = class(TInterfacedObject, IServerCertificateVerifier)
  public
    function VerifyServerCertificate(const AChain: TArray<TBytes>;
      const AServerName: TServerName; const AOcspStaple: TBytes;
      out AVerified: TVerifiedChain; out AAlert: TTlsAlertDescription): Boolean;
  end;

  // a timed transport over an in-memory inbound buffer, with a switchable readiness answer and a
  // per-send cap so a partial-write loop can be exercised
  TTestMemoryTransport = class(TTlsTimedTransportBase)
  strict private
    FInbound: TBytes;
    FInPos: Int32;
    FReadable: Boolean;
    FReceiveNegative: Boolean;
    FMaxSend: Int32;
    FOutbound: TBytes;
  strict protected
    function WaitReadable(AMs: Int32): Boolean; override;
    function ReceiveRaw(var ABuffer: TBytes; AOffset, AMaxLength: Int32): Int32; override;
    function SendRaw(const ABuffer: TBytes; AOffset, ALength: Int32): Int32; override;
  public
    constructor Create(const AInbound: TBytes; AReadable: Boolean);
    function ArmedTimeout: Int32;
    property Outbound: TBytes read FOutbound;
    property ReceiveNegative: Boolean read FReceiveNegative write FReceiveNegative;
    property MaxSend: Int32 read FMaxSend write FMaxSend;
  end;

{ TFakeSystemTrustInstaller }

constructor TFakeSystemTrustInstaller.Create(ARaise: Boolean);
begin
  inherited Create;
  FRaise := ARaise;
end;

procedure TFakeSystemTrustInstaller.InstallClientTrust(
  const ABuilder: ITlsClientConfigBuilder; const APkix: IPkixProvider);
begin
  if FRaise then
    raise EInvalidOperationTlsLibException.Create('installer refused');
  ClientRoleCalled := True;
  ClientPkix := APkix;
  ABuilder.WithTrustStore(TTrustAnchorStore.Create(nil) as ITrustAnchorStore);
end;

procedure TFakeSystemTrustInstaller.InstallClientAuthTrust(
  const ABuilder: ITlsServerConfigBuilder; const APkix: IPkixProvider);
begin
  if FRaise then
    raise EInvalidOperationTlsLibException.Create('installer refused');
  ServerRoleCalled := True;
  ServerPkix := APkix;
  ABuilder.WithTrustStore(TTrustAnchorStore.Create(nil) as ITrustAnchorStore);
end;

{ TFakeServerVerifier }

function TFakeServerVerifier.VerifyServerCertificate(const AChain: TArray<TBytes>;
  const AServerName: TServerName; const AOcspStaple: TBytes;
  out AVerified: TVerifiedChain; out AAlert: TTlsAlertDescription): Boolean;
begin
  AAlert := TTlsAlertDescription.BadCertificate;
  Result := False;
end;

{ TTestMemoryTransport }

constructor TTestMemoryTransport.Create(const AInbound: TBytes; AReadable: Boolean);
begin
  inherited Create;
  FInbound := AInbound;
  FInPos := 0;
  FReadable := AReadable;
  FMaxSend := System.MaxInt;
end;

function TTestMemoryTransport.ArmedTimeout: Int32;
begin
  Result := ReadTimeoutMs;
end;

function TTestMemoryTransport.WaitReadable(AMs: Int32): Boolean;
begin
  Result := FReadable;
end;

function TTestMemoryTransport.ReceiveRaw(var ABuffer: TBytes; AOffset,
  AMaxLength: Int32): Int32;
var
  LN: Int32;
begin
  if FReceiveNegative then
    Exit(-1);
  LN := System.Length(FInbound) - FInPos;
  if LN > AMaxLength then
    LN := AMaxLength;
  if LN <= 0 then
    Exit(0);
  System.Move(FInbound[FInPos], ABuffer[AOffset], LN);
  Inc(FInPos, LN);
  Result := LN;
end;

function TTestMemoryTransport.SendRaw(const ABuffer: TBytes; AOffset,
  ALength: Int32): Int32;
var
  LN, LBase: Int32;
begin
  LN := ALength;
  if LN > FMaxSend then
    LN := FMaxSend;
  LBase := System.Length(FOutbound);
  SetLength(FOutbound, LBase + LN);
  System.Move(ABuffer[AOffset], FOutbound[LBase], LN);
  Result := LN;
end;

{ TTestTlsConnection }

function TTestTlsConnection.StubVerifyCallback(const AChain: TArray<TBytes>;
  const AHostName: string): Boolean;
begin
  Result := True;
end;

function TTestTlsConnection.StubResolver(const ACtx: TCertificateVerdictContext;
  out ARejectAlert: TTlsAlertDescription): Boolean;
begin
  ARejectAlert := TTlsAlertDescription.BadCertificate;
  Result := True;
end;

function TTestTlsConnection.StubResolverAlt(const ACtx: TCertificateVerdictContext;
  out ARejectAlert: TTlsAlertDescription): Boolean;
begin
  ARejectAlert := TTlsAlertDescription.BadCertificate;
  Result := False;
end;

function TTestTlsConnection.ServerCert: TBytes;
var
  LCerts: TStringList;
begin
  LCerts := LoadVectorFields('Certs/EcP256Chain.txt');
  try
    Result := DecodeHex(LCerts.Values['leaf_cert']);
  finally
    LCerts.Free;
  end;
end;

function TTestTlsConnection.ServerKey: TBytes;
var
  LCerts: TStringList;
begin
  LCerts := LoadVectorFields('Certs/EcP256Chain.txt');
  try
    Result := DecodeHex(LCerts.Values['leaf_key']);
  finally
    LCerts.Free;
  end;
end;

function TTestTlsConnection.RootAnchor: TBytes;
var
  LCerts: TStringList;
begin
  LCerts := LoadVectorFields('Certs/EcP256Chain.txt');
  try
    Result := DecodeHex(LCerts.Values['root_cert']);
  finally
    LCerts.Free;
  end;
end;

function TTestTlsConnection.ClientOptsWithStore: TTlsOptions;
begin
  Result := TTlsOptions.Default;
  Result.Crypto := Crypto;
  Result.Pkix := Pkix;
  Result.CustomTrustStore := TTrustAnchorStore.Create(nil) as ITrustAnchorStore;
  Result.TrustSourceHint := 'a trust anchor bundle, system trust, or a custom store';
end;

function TTestTlsConnection.ServerOptsWithCredential: TTlsOptions;
begin
  Result := TTlsOptions.Default;
  Result.Crypto := Crypto;
  Result.Pkix := Pkix;
  Result.Certificate := TTlsBlobSource.FromBytes(ServerCert);
  Result.PrivateKey := TTlsBlobSource.FromBytes(ServerKey);
  Result.TrustSourceHint := 'a client-CA bundle';
end;

function TTestTlsConnection.RaisesStreamError(const AOpts: TTlsOptions;
  AIsClient: Boolean; out AMessage: string): Boolean;
begin
  Result := False;
  AMessage := '';
  try
    if AIsClient then
      TTlsConfigComposer.BuildClientConfig(AOpts)
    else
      TTlsConfigComposer.BuildServerConfig(AOpts);
  except
    on E: ETlsStreamError do
    begin
      Result := True;
      AMessage := E.Message;
    end;
  end;
end;

procedure TTestTlsConnection.TestClientDefaultsToSharedProviders;
var
  LOpts: TTlsOptions;
  LConfig: ITlsClientConfig;
begin
  LOpts := TTlsOptions.Default;
  LOpts.CustomTrustStore := TTrustAnchorStore.Create(nil) as ITrustAnchorStore;
  LConfig := TTlsConfigComposer.BuildClientConfig(LOpts);
  CheckTrue(LConfig.Crypto = TDefaultCryptoProvider.Shared,
    'nil crypto falls back to the shared default');
  CheckTrue(LConfig.Pkix = TDefaultPkixProvider.Shared,
    'nil pkix falls back to the shared default');
end;

procedure TTestTlsConnection.TestClientUsesInjectedProviders;
var
  LConfig: ITlsClientConfig;
begin
  LConfig := TTlsConfigComposer.BuildClientConfig(ClientOptsWithStore);
  CheckTrue(LConfig.Crypto = Crypto, 'the injected crypto provider is used');
  CheckTrue(LConfig.Pkix = Pkix, 'the injected pkix provider is used');
end;

procedure TTestTlsConnection.TestClientCustomStoreComposes;
var
  LConfig: ITlsClientConfig;
begin
  LConfig := TTlsConfigComposer.BuildClientConfig(ClientOptsWithStore);
  CheckNotNull(LConfig.TrustStore, 'a custom store is composed into the trust source');
end;

procedure TTestTlsConnection.TestClientNoSourceFailsClosedWithHint;
var
  LOpts: TTlsOptions;
  LMsg: string;
begin
  LOpts := TTlsOptions.Default;
  LOpts.TrustSourceHint := 'a RootCertFile bundle';
  CheckTrue(RaisesStreamError(LOpts, True, LMsg),
    'verifying with no trust source fails closed');
  CheckTrue(Pos('a RootCertFile bundle', LMsg) > 0,
    'the message splices the host trust-source hint');
end;

procedure TTestTlsConnection.TestClientInsecureSkipVerifyBuildsWithSkipFlag;
var
  LOpts: TTlsOptions;
  LConfig: ITlsClientConfig;
begin
  LOpts := TTlsOptions.Default;
  LOpts.InsecureSkipVerify := True;
  LConfig := TTlsConfigComposer.BuildClientConfig(LOpts);
  CheckTrue(LConfig.DangerousTrust.InsecureSkipVerify, 'the loud skip flag is set');
  CheckNotNull(LConfig.TrustStore, 'skipping still supplies a store to satisfy the builder');
end;

procedure TTestTlsConnection.TestClientVerifyPeerOffSetsSkipFlag;
var
  LOpts: TTlsOptions;
  LConfig: ITlsClientConfig;
begin
  LOpts := TTlsOptions.Default;
  LOpts.VerifyPeer := False;
  LConfig := TTlsConfigComposer.BuildClientConfig(LOpts);
  CheckTrue(LConfig.DangerousTrust.InsecureSkipVerify,
    'VerifyPeer off maps onto the loud skip flag');
end;

procedure TTestTlsConnection.TestClientCheckHostNameOffDisablesNameCheck;
var
  LOpts: TTlsOptions;
begin
  LOpts := ClientOptsWithStore;
  LOpts.CheckHostName := False;
  CheckFalse(TTlsConfigComposer.BuildClientConfig(LOpts).CheckServerName,
    'CheckHostName off disables server-name checking');
end;

procedure TTestTlsConnection.TestClientAlpnForwarded;
var
  LOpts: TTlsOptions;
  LAlpn: TArray<string>;
begin
  LOpts := ClientOptsWithStore;
  LOpts.AlpnProtocols := TArray<string>.Create('h2', 'http/1.1');
  LAlpn := TTlsConfigComposer.BuildClientConfig(LOpts).AlpnProtocols;
  CheckEquals(2, System.Length(LAlpn), 'both ALPN protocols are forwarded');
  CheckEquals('h2', LAlpn[0], 'first ALPN protocol');
  CheckEquals('http/1.1', LAlpn[1], 'second ALPN protocol');
end;

procedure TTestTlsConnection.TestClientVerifyCallbackForwarded;
var
  LOpts: TTlsOptions;
  LConfig: ITlsClientConfig;
begin
  LOpts := ClientOptsWithStore;
  LOpts.VerifyCallback := StubVerifyCallback;
  LConfig := TTlsConfigComposer.BuildClientConfig(LOpts);
  CheckTrue(Assigned(LConfig.DangerousTrust.VerifyCallback),
    'the augment-only verify callback is forwarded');
end;

procedure TTestTlsConnection.TestClientVerdictResolverArmsLiveRevocation;
var
  LOpts: TTlsOptions;
  LConfig: ITlsClientConfig;
begin
  LOpts := ClientOptsWithStore;
  LOpts.ClientVerdictResolver := StubResolver;
  LOpts.ClientVerdictDeadlineMs := 1234;
  LConfig := TTlsConfigComposer.BuildClientConfig(LOpts);
  CheckEquals(Ord(TVerdictDeferral.LiveRevocation),
    Ord(LConfig.AsyncCertificateVerdict.Deferral),
    'a client resolver arms the live-revocation park');
  CheckEquals(1234, LConfig.AsyncCertificateVerdict.DeadlineMs, 'the deadline is carried');
end;

procedure TTestTlsConnection.TestClientNoResolverLeavesInlineVerdict;
begin
  CheckEquals(Ord(TVerdictDeferral.None),
    Ord(TTlsConfigComposer.BuildClientConfig(ClientOptsWithStore)
      .AsyncCertificateVerdict.Deferral),
    'no resolver keeps the verdict inline');
end;

procedure TTestTlsConnection.TestClientResumptionOnAddsCache;
var
  LConfig: ITlsClientConfig;
begin
  LConfig := TTlsConfigComposer.BuildClientConfig(ClientOptsWithStore);
  CheckTrue(LConfig.Resumption, 'resumption is engaged by default');
  CheckNotNull(LConfig.SessionCache, 'a session cache is provided');
end;

procedure TTestTlsConnection.TestClientResumptionOffDisablesCache;
var
  LOpts: TTlsOptions;
begin
  LOpts := ClientOptsWithStore;
  LOpts.SessionResumption := False;
  CheckFalse(TTlsConfigComposer.BuildClientConfig(LOpts).Resumption,
    'resumption is off when disabled');
end;

procedure TTestTlsConnection.TestClientSystemTrustInstallerCalledForClientRole;
var
  LOpts: TTlsOptions;
  LFake: TFakeSystemTrustInstaller;
  LInst: ISystemTrustInstaller;
begin
  LFake := TFakeSystemTrustInstaller.Create(False);
  LInst := LFake;
  LOpts := TTlsOptions.Default;
  LOpts.Pkix := Pkix;
  LOpts.SystemTrust := LInst;
  TTlsConfigComposer.BuildClientConfig(LOpts);
  CheckTrue(LFake.ClientRoleCalled, 'the installer client-role hook ran');
  CheckFalse(LFake.ServerRoleCalled, 'the server-role hook did not run on a client build');
  CheckTrue(LFake.ClientPkix = Pkix, 'the effective pkix was passed to the installer');
end;

procedure TTestTlsConnection.TestClientVerifierComposesAndBuilds;
var
  LOpts: TTlsOptions;
  LConfig: ITlsClientConfig;
begin
  LOpts := TTlsOptions.Default;
  LOpts.ServerCertificateVerifier := TFakeServerVerifier.Create as IServerCertificateVerifier;
  LConfig := TTlsConfigComposer.BuildClientConfig(LOpts);
  CheckNotNull(LConfig.ServerVerifierSource,
    'a whole-verifier composes into the verifier source');
end;

procedure TTestTlsConnection.TestClientVerifierWithAnchorConflictPropagates;
var
  LOpts: TTlsOptions;
  LRaised: Boolean;
begin
  LOpts := TTlsOptions.Default;
  LOpts.ServerCertificateVerifier := TFakeServerVerifier.Create as IServerCertificateVerifier;
  LOpts.CustomTrustStore := TTrustAnchorStore.Create(nil) as ITrustAnchorStore;
  LRaised := False;
  try
    TTlsConfigComposer.BuildClientConfig(LOpts);
  except
    on E: Exception do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a verifier plus an anchor source is the builder''s typed conflict');
end;

procedure TTestTlsConnection.TestClientRaisingInstallerPropagates;
var
  LOpts: TTlsOptions;
  LInst: ISystemTrustInstaller;
  LRaised: Boolean;
begin
  LInst := TFakeSystemTrustInstaller.Create(True);
  LOpts := TTlsOptions.Default;
  LOpts.Pkix := Pkix;
  LOpts.SystemTrust := LInst;
  LRaised := False;
  try
    TTlsConfigComposer.BuildClientConfig(LOpts);
  except
    on E: EInvalidOperationTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a raising installer propagates out of the build');
end;

procedure TTestTlsConnection.TestServerNoCredentialRaises;
var
  LOpts: TTlsOptions;
  LMsg: string;
begin
  LOpts := TTlsOptions.Default;
  CheckTrue(RaisesStreamError(LOpts, False, LMsg),
    'a server without a certificate fails closed');
end;

procedure TTestTlsConnection.TestServerCredentialBuilds;
var
  LConfig: ITlsServerConfig;
begin
  LConfig := TTlsConfigComposer.BuildServerConfig(ServerOptsWithCredential);
  CheckNotNull(LConfig, 'a server config builds from the credential');
  CheckEquals(Ord(TClientAuthMode.None), Ord(LConfig.ClientAuth),
    'no client-trust source means no client authentication');
end;

procedure TTestTlsConnection.TestServerNoClientSourceLeavesNoClientAuth;
var
  LOpts: TTlsOptions;
begin
  // a server resolver set but no client-trust source: the park is not armed
  LOpts := ServerOptsWithCredential;
  LOpts.ServerVerdictResolver := StubResolver;
  CheckEquals(Ord(TClientAuthMode.None),
    Ord(TTlsConfigComposer.BuildServerConfig(LOpts).ClientAuth),
    'a resolver without a client-trust source requests no client auth');
end;

procedure TTestTlsConnection.TestServerClientSourceAppliesClientAuthMode;
var
  LOpts: TTlsOptions;
begin
  LOpts := ServerOptsWithCredential;
  LOpts.TrustAnchors := TArray<TTlsBlobSource>.Create(
    TTlsBlobSource.FromBytes(RootAnchor));
  LOpts.ClientAuth := TClientAuthMode.Requested;
  CheckEquals(Ord(TClientAuthMode.Requested),
    Ord(TTlsConfigComposer.BuildServerConfig(LOpts).ClientAuth),
    'a client-trust source applies the configured client-auth mode');
end;

procedure TTestTlsConnection.TestServerVerdictResolverArmsLiveRevocation;
var
  LOpts: TTlsOptions;
  LConfig: ITlsServerConfig;
begin
  // a client-CA source plus a server-role resolver arms the client-cert verdict park
  LOpts := ServerOptsWithCredential;
  LOpts.TrustAnchors := TArray<TTlsBlobSource>.Create(
    TTlsBlobSource.FromBytes(RootAnchor));
  LOpts.ServerVerdictResolver := StubResolver;
  LOpts.ServerVerdictDeadlineMs := 777;
  LConfig := TTlsConfigComposer.BuildServerConfig(LOpts);
  CheckEquals(Ord(TVerdictDeferral.LiveRevocation),
    Ord(LConfig.AsyncCertificateVerdict.Deferral),
    'the server-role resolver arms the live-revocation park');
  CheckEquals(777, LConfig.AsyncCertificateVerdict.DeadlineMs, 'the server deadline is carried');
end;

procedure TTestTlsConnection.TestServerVerdictResolverNoSourceStaysInline;
var
  LOpts: TTlsOptions;
begin
  LOpts := ServerOptsWithCredential;
  LOpts.ServerVerdictResolver := StubResolver;
  CheckEquals(Ord(TVerdictDeferral.None),
    Ord(TTlsConfigComposer.BuildServerConfig(LOpts).AsyncCertificateVerdict.Deferral),
    'a server resolver without a client-trust source does not arm the park');
end;

procedure TTestTlsConnection.TestServerVerifyPeerOffLeavesNoClientAuth;
var
  LOpts: TTlsOptions;
begin
  LOpts := ServerOptsWithCredential;
  LOpts.TrustAnchors := TArray<TTlsBlobSource>.Create(
    TTlsBlobSource.FromBytes(RootAnchor));
  LOpts.VerifyPeer := False;
  CheckEquals(Ord(TClientAuthMode.None),
    Ord(TTlsConfigComposer.BuildServerConfig(LOpts).ClientAuth),
    'VerifyPeer off leaves no client authentication even with a source');
end;

procedure TTestTlsConnection.TestServerSystemTrustInstallerCalledForServerRole;
var
  LOpts: TTlsOptions;
  LFake: TFakeSystemTrustInstaller;
  LInst: ISystemTrustInstaller;
begin
  LFake := TFakeSystemTrustInstaller.Create(False);
  LInst := LFake;
  LOpts := ServerOptsWithCredential;
  LOpts.SystemTrust := LInst;
  TTlsConfigComposer.BuildServerConfig(LOpts);
  CheckTrue(LFake.ServerRoleCalled, 'the installer server-role hook ran');
  CheckFalse(LFake.ClientRoleCalled, 'the client-role hook did not run on a server build');
  CheckTrue(LFake.ServerPkix = Pkix, 'the effective pkix was passed to the installer');
end;

procedure TTestTlsConnection.TestServerResumptionMintsDefaultStek;
var
  LOpts: TTlsOptions;
begin
  CheckTrue(TTlsConfigComposer.BuildServerConfig(ServerOptsWithCredential).Resumption,
    'resumption is engaged by default');
  LOpts := ServerOptsWithCredential;
  LOpts.SessionResumption := False;
  CheckFalse(TTlsConfigComposer.BuildServerConfig(LOpts).Resumption,
    'resumption is off when disabled');
end;

procedure TTestTlsConnection.TestSignatureEqualOptionsEqualKeys;
var
  LA, LB: TTlsOptions;
begin
  LA := ClientOptsWithStore;
  LB := ClientOptsWithStore;
  LB.CustomTrustStore := LA.CustomTrustStore; // same store identity
  CheckEquals(TTlsConfigComposer.ClientSignature(LA),
    TTlsConfigComposer.ClientSignature(LB),
    'equal options produce equal client signatures');
end;

procedure TTestTlsConnection.TestSignatureEachConcernChangesKey;
var
  LBase, LMut: TTlsOptions;
  LBaseSig: string;
begin
  LBase := ClientOptsWithStore;
  LBaseSig := TTlsConfigComposer.ClientSignature(LBase);

  LMut := LBase;
  LMut.SessionResumption := not LBase.SessionResumption;
  CheckFalse(TTlsConfigComposer.ClientSignature(LMut) = LBaseSig,
    'flipping resumption changes the key');

  LMut := LBase;
  LMut.VerifyPeer := not LBase.VerifyPeer;
  CheckFalse(TTlsConfigComposer.ClientSignature(LMut) = LBaseSig,
    'flipping VerifyPeer changes the key');

  LMut := LBase;
  LMut.CheckHostName := not LBase.CheckHostName;
  CheckFalse(TTlsConfigComposer.ClientSignature(LMut) = LBaseSig,
    'flipping CheckHostName changes the key');

  LMut := LBase;
  LMut.KeyPassword := 'changed';
  CheckFalse(TTlsConfigComposer.ClientSignature(LMut) = LBaseSig,
    'changing the key password changes the key');

  LMut := LBase;
  LMut.AlpnProtocols := TArray<string>.Create('h2');
  CheckFalse(TTlsConfigComposer.ClientSignature(LMut) = LBaseSig,
    'adding ALPN changes the key');

  LMut := LBase;
  LMut.Certificate := TTlsBlobSource.FromBytes(ServerCert);
  CheckFalse(TTlsConfigComposer.ClientSignature(LMut) = LBaseSig,
    'a credential blob changes the key');
end;

procedure TTestTlsConnection.TestSignatureExcludesResolverAndTimeout;
var
  LBase, LMut: TTlsOptions;
  LBaseSig: string;
begin
  LBase := ClientOptsWithStore;
  LBaseSig := TTlsConfigComposer.ClientSignature(LBase);

  LMut := LBase;
  LMut.HandshakeTimeoutMs := 5000;
  CheckEquals(LBaseSig, TTlsConfigComposer.ClientSignature(LMut),
    'the handshake timeout is not part of the config identity');

  // a different resolver instance keeps the key: only assigned-or-not participates
  LBase.ClientVerdictResolver := StubResolver;
  LMut := LBase;
  LMut.ClientVerdictResolver := StubResolverAlt;
  CheckEquals(TTlsConfigComposer.ClientSignature(LBase),
    TTlsConfigComposer.ClientSignature(LMut),
    'a different resolver pointer does not change the key');
end;

procedure TTestTlsConnection.TestSignaturePasswordNotInClear;
var
  LOpts: TTlsOptions;
begin
  LOpts := ClientOptsWithStore;
  LOpts.KeyPassword := 'sup3r-s3cret-passphrase';
  CheckTrue(Pos('sup3r-s3cret-passphrase',
    TTlsConfigComposer.ClientSignature(LOpts)) = 0,
    'the key password never appears in clear in the signature');
end;

procedure TTestTlsConnection.TestResolveMemoisesBuildOnce;
var
  LOpts: TTlsOptions;
  LMemo: ITlsClientConfigMemo;
  LFirst, LSecond: ITlsClientConfig;
begin
  LOpts := ClientOptsWithStore;
  LMemo := NewTlsClientConfigMemo;
  LFirst := TTlsConfigComposer.ResolveClientConfig(LOpts, LMemo, 'ClientConfig');
  LSecond := TTlsConfigComposer.ResolveClientConfig(LOpts, LMemo, 'ClientConfig');
  CheckTrue(LFirst = LSecond, 'a memo hit reuses the same config identity');
end;

procedure TTestTlsConnection.TestResolveConfigInReturnedAsIs;
var
  LOpts: TTlsOptions;
  LMemo: ITlsClientConfigMemo;
  LSupplied, LResolved: ITlsClientConfig;
  LProbe: ITlsClientConfig;
begin
  LSupplied := TTlsConfigComposer.BuildClientConfig(ClientOptsWithStore);
  // a config-in with no conflicting options is returned verbatim, and the memo stays empty
  LOpts := TTlsOptions.Default;
  LOpts.ClientConfig := LSupplied;
  LMemo := NewTlsClientConfigMemo;
  LResolved := TTlsConfigComposer.ResolveClientConfig(LOpts, LMemo, 'ClientConfig');
  CheckTrue(LResolved = LSupplied, 'the supplied config is returned as-is');
  CheckFalse(LMemo.TryGet(TTlsConfigComposer.ClientSignature(LOpts), LProbe),
    'the memo is untouched when a config is supplied');
end;

procedure TTestTlsConnection.TestGuardConflictOnEachField;

  procedure ExpectConflict(const AOpts: TTlsOptions; const AWhat: string);
  var
    LOpts: TTlsOptions;
    LMemo: ITlsClientConfigMemo;
    LRaised: Boolean;
  begin
    LOpts := AOpts;
    LOpts.ClientConfig := TTlsConfigComposer.BuildClientConfig(ClientOptsWithStore);
    LMemo := NewTlsClientConfigMemo;
    LRaised := False;
    try
      TTlsConfigComposer.ResolveClientConfig(LOpts, LMemo, 'ClientConfig');
    except
      on E: ETlsStreamError do
        LRaised := True;
    end;
    CheckTrue(LRaised, 'a config supplied alongside ' + AWhat + ' fails loud');
  end;

var
  LOpts: TTlsOptions;
begin
  LOpts := TTlsOptions.Default;
  LOpts.Certificate := TTlsBlobSource.FromBytes(ServerCert);
  ExpectConflict(LOpts, 'a certificate');

  LOpts := TTlsOptions.Default;
  LOpts.CustomTrustStore := TTrustAnchorStore.Create(nil) as ITrustAnchorStore;
  ExpectConflict(LOpts, 'a custom store');

  LOpts := TTlsOptions.Default;
  LOpts.TrustAnchors := TArray<TTlsBlobSource>.Create(
    TTlsBlobSource.FromBytes(RootAnchor));
  ExpectConflict(LOpts, 'trust anchors');

  LOpts := TTlsOptions.Default;
  LOpts.Crypto := Crypto;
  ExpectConflict(LOpts, 'an injected crypto provider');

  LOpts := TTlsOptions.Default;
  LOpts.SystemTrust := TFakeSystemTrustInstaller.Create(False) as ISystemTrustInstaller;
  ExpectConflict(LOpts, 'system trust');
end;

procedure TTestTlsConnection.TestGuardIncludesVerifyCallback;
var
  LOpts: TTlsOptions;
  LMemo: ITlsClientConfigMemo;
  LRaised: Boolean;
begin
  LOpts := TTlsOptions.Default;
  LOpts.VerifyCallback := StubVerifyCallback;
  LOpts.ClientConfig := TTlsConfigComposer.BuildClientConfig(ClientOptsWithStore);
  LMemo := NewTlsClientConfigMemo;
  LRaised := False;
  try
    TTlsConfigComposer.ResolveClientConfig(LOpts, LMemo, 'ClientConfig');
  except
    on E: ETlsStreamError do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a VerifyCallback conflicts with a supplied config');
end;

procedure TTestTlsConnection.TestGuardMessageNamesTheProperty;
var
  LOpts: TTlsOptions;
  LMsg: string;
begin
  LOpts := TTlsOptions.Default;
  LOpts.CustomTrustStore := TTrustAnchorStore.Create(nil) as ITrustAnchorStore;
  LMsg := '';
  try
    TTlsConfigComposer.GuardNoConflict(LOpts, False, 'ServerConfig');
  except
    on E: ETlsStreamError do
      LMsg := E.Message;
  end;
  CheckTrue(Pos('ServerConfig', LMsg) > 0, 'the conflict message names the config property');
end;

procedure TTestTlsConnection.TestGuardIgnoresResolverAndTimeout;
var
  LOpts: TTlsOptions;
begin
  // resolvers and the handshake timeout are runtime hooks - never a config-in conflict
  LOpts := TTlsOptions.Default;
  LOpts.HandshakeTimeoutMs := 5000;
  LOpts.ClientVerdictResolver := StubResolver;
  LOpts.ServerVerdictResolver := StubResolver;
  // no raise expected
  TTlsConfigComposer.GuardNoConflict(LOpts, True, 'ClientConfig');
  CheckTrue(True, 'a resolver or timeout alone does not conflict');
end;

procedure TTestTlsConnection.TestServerClientAuthRequestedWithoutSourceRaises;
var
  LOpts: TTlsOptions;
  LMsg: string;
begin
  // an explicit request for client authentication with no client-trust source must fail loud, not
  // fall through to a server that quietly asks for no certificate
  LOpts := ServerOptsWithCredential;
  LOpts.ClientAuthRequested := True;
  CheckTrue(RaisesStreamError(LOpts, False, LMsg),
    'requested client auth without a client-trust source fails closed');
end;

procedure TTestTlsConnection.TestServerGuardAllowsClientOnlyOptions;
var
  LOpts: TTlsOptions;
  LRaised: Boolean;
begin
  // the augment callback and the server-cert verifier are client-only reads, so they do not conflict
  // with a supplied server config; a shared option (a certificate) still does
  LOpts := TTlsOptions.Default;
  LOpts.VerifyCallback := StubVerifyCallback;
  LOpts.ServerCertificateVerifier := TFakeServerVerifier.Create as IServerCertificateVerifier;
  LOpts.ServerConfig := TTlsConfigComposer.BuildServerConfig(ServerOptsWithCredential);
  CheckNotNull(TTlsConfigComposer.ResolveServerConfig(LOpts, NewTlsServerConfigMemo,
    'ServerConfig'), 'client-only options do not conflict with a server config-in');
  LOpts.Certificate := TTlsBlobSource.FromBytes(ServerCert);
  LRaised := False;
  try
    TTlsConfigComposer.ResolveServerConfig(LOpts, NewTlsServerConfigMemo, 'ServerConfig');
  except
    on E: ETlsStreamError do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a shared cert/trust option still conflicts with a server config-in');
end;

procedure TTestTlsConnection.TestClientGuardFlagsServerCertVerifier;
var
  LOpts: TTlsOptions;
  LRaised: Boolean;
begin
  // the server-cert verifier is a client-role read, so it conflicts with a supplied client config
  LOpts := TTlsOptions.Default;
  LOpts.ServerCertificateVerifier := TFakeServerVerifier.Create as IServerCertificateVerifier;
  LOpts.ClientConfig := TTlsConfigComposer.BuildClientConfig(ClientOptsWithStore);
  LRaised := False;
  try
    TTlsConfigComposer.ResolveClientConfig(LOpts, NewTlsClientConfigMemo, 'ClientConfig');
  except
    on E: ETlsStreamError do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a server-cert verifier conflicts with a client config-in');
end;

procedure TTestTlsConnection.TestTransportTimesOutWhenSilent;
var
  LTransport: TTestMemoryTransport;
  LTimed: ITlsTransport;
  LBuf: TBytes;
  LRaised: Boolean;
  LMsg: string;
begin
  LTransport := TTestMemoryTransport.Create(nil, False); // never readable
  LTimed := LTransport as ITlsTransport;
  LTransport.SetReadTimeout(150);
  SetLength(LBuf, 16);
  LRaised := False;
  LMsg := '';
  try
    LTimed.Read(LBuf, 0, 16);
  except
    on E: ETlsHandshakeTimeout do
    begin
      LRaised := True;
      LMsg := E.Message;
    end;
  end;
  CheckTrue(LRaised, 'a silent peer under an armed cap raises a handshake timeout');
  CheckTrue(Pos('150', LMsg) > 0, 'the timeout message carries the elapsed cap');
end;

procedure TTestTlsConnection.TestTransportReturnsDataWhenReadable;
var
  LTransport: TTestMemoryTransport;
  LTimed: ITlsTransport;
  LBuf: TBytes;
  LN: Int32;
begin
  LTransport := TTestMemoryTransport.Create(TBytes.Create(1, 2, 3, 4), True);
  LTimed := LTransport as ITlsTransport;
  LTransport.SetReadTimeout(1000);
  SetLength(LBuf, 16);
  LN := LTimed.Read(LBuf, 0, 16);
  CheckEquals(4, LN, 'the available bytes are read within the cap');
end;

procedure TTestTlsConnection.TestTransportCapZeroDoesNotWait;
var
  LTransport: TTestMemoryTransport;
  LTimed: ITlsTransport;
  LBuf: TBytes;
begin
  // WaitReadable would answer False, but cap 0 must not consult it - reads block/return data
  LTransport := TTestMemoryTransport.Create(TBytes.Create(9), False);
  LTimed := LTransport as ITlsTransport;
  LTransport.SetReadTimeout(0);
  SetLength(LBuf, 8);
  CheckEquals(1, LTimed.Read(LBuf, 0, 8), 'cap 0 does not consult the readiness wait');
end;

procedure TTestTlsConnection.TestTransportNegativeReceiveIsEof;
var
  LTransport: TTestMemoryTransport;
  LTimed: ITlsTransport;
  LBuf: TBytes;
begin
  LTransport := TTestMemoryTransport.Create(nil, True);
  LTransport.ReceiveNegative := True;
  LTimed := LTransport as ITlsTransport;
  SetLength(LBuf, 8);
  CheckEquals(0, LTimed.Read(LBuf, 0, 8), 'a negative host receive is normalized to end-of-stream');
end;

procedure TTestTlsConnection.TestTransportWriteCompletesOverPartialSends;
var
  LTransport: TTestMemoryTransport;
  LTimed: ITlsTransport;
  LData: TBytes;
  LI: Int32;
begin
  LTransport := TTestMemoryTransport.Create(nil, True);
  LTransport.MaxSend := 3; // force the write loop to iterate
  LTimed := LTransport as ITlsTransport;
  SetLength(LData, 10);
  for LI := 0 to 9 do
    LData[LI] := Byte(LI + 1);
  LTimed.Write(LData, 0, 10);
  CheckEquals(10, System.Length(LTransport.Outbound), 'the write loop sends every byte');
  for LI := 0 to 9 do
    CheckEquals(LI + 1, LTransport.Outbound[LI], 'byte order is preserved across partial sends');
end;

procedure TTestTlsConnection.TestTransportSetReadTimeoutIsObservable;
var
  LTransport: TTestMemoryTransport;
begin
  LTransport := TTestMemoryTransport.Create(nil, True);
  try
    CheckEquals(0, LTransport.ArmedTimeout, 'the cap starts cleared');
    LTransport.SetReadTimeout(30000);
    CheckEquals(30000, LTransport.ArmedTimeout, 'the armed cap is observable');
    LTransport.SetReadTimeout(0);
    CheckEquals(0, LTransport.ArmedTimeout, 'the cap clears back to blocking');
  finally
    LTransport.Free;
  end;
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestTlsConnection);
{$ELSE}
  RegisterTest(TTestTlsConnection.Suite);
{$ENDIF FPC}

end.
