{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit AdapterCoreTests;

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
  TlpTlsAdapterCore,
  TlsLibTestBase;

type
  TTestAdapterCore = class(TTlsLibAlgorithmTestCase)
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
    function ClientOptsWithStore: TTlsAdapterOptions;
    // server options with a valid credential so the build always succeeds
    function ServerOptsWithCredential: TTlsAdapterOptions;
    function RaisesStreamError(const AOpts: TTlsAdapterOptions;
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

{ TTestAdapterCore }

function TTestAdapterCore.StubVerifyCallback(const AChain: TArray<TBytes>;
  const AHostName: string): Boolean;
begin
  Result := True;
end;

function TTestAdapterCore.StubResolver(const ACtx: TCertificateVerdictContext;
  out ARejectAlert: TTlsAlertDescription): Boolean;
begin
  ARejectAlert := TTlsAlertDescription.BadCertificate;
  Result := True;
end;

function TTestAdapterCore.StubResolverAlt(const ACtx: TCertificateVerdictContext;
  out ARejectAlert: TTlsAlertDescription): Boolean;
begin
  ARejectAlert := TTlsAlertDescription.BadCertificate;
  Result := False;
end;

function TTestAdapterCore.ServerCert: TBytes;
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

function TTestAdapterCore.ServerKey: TBytes;
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

function TTestAdapterCore.RootAnchor: TBytes;
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

function TTestAdapterCore.ClientOptsWithStore: TTlsAdapterOptions;
begin
  Result := TTlsAdapterOptions.Default;
  Result.Crypto := Crypto;
  Result.Pkix := Pkix;
  Result.CustomTrustStore := TTrustAnchorStore.Create(nil) as ITrustAnchorStore;
  Result.TrustSourceHint := 'a trust anchor bundle, system trust, or a custom store';
end;

function TTestAdapterCore.ServerOptsWithCredential: TTlsAdapterOptions;
begin
  Result := TTlsAdapterOptions.Default;
  Result.Crypto := Crypto;
  Result.Pkix := Pkix;
  Result.Certificate := TTlsAdapterBlobSource.FromBytes(ServerCert);
  Result.PrivateKey := TTlsAdapterBlobSource.FromBytes(ServerKey);
  Result.TrustSourceHint := 'a client-CA bundle';
end;

function TTestAdapterCore.RaisesStreamError(const AOpts: TTlsAdapterOptions;
  AIsClient: Boolean; out AMessage: string): Boolean;
begin
  Result := False;
  AMessage := '';
  try
    if AIsClient then
      TTlsAdapterConfigComposer.BuildClientConfig(AOpts)
    else
      TTlsAdapterConfigComposer.BuildServerConfig(AOpts);
  except
    on E: ETlsStreamError do
    begin
      Result := True;
      AMessage := E.Message;
    end;
  end;
end;

procedure TTestAdapterCore.TestClientDefaultsToSharedProviders;
var
  LOpts: TTlsAdapterOptions;
  LConfig: ITlsClientConfig;
begin
  LOpts := TTlsAdapterOptions.Default;
  LOpts.CustomTrustStore := TTrustAnchorStore.Create(nil) as ITrustAnchorStore;
  LConfig := TTlsAdapterConfigComposer.BuildClientConfig(LOpts);
  CheckTrue(LConfig.Crypto = TDefaultCryptoProvider.Shared,
    'nil crypto falls back to the shared default');
  CheckTrue(LConfig.Pkix = TDefaultPkixProvider.Shared,
    'nil pkix falls back to the shared default');
end;

procedure TTestAdapterCore.TestClientUsesInjectedProviders;
var
  LConfig: ITlsClientConfig;
begin
  LConfig := TTlsAdapterConfigComposer.BuildClientConfig(ClientOptsWithStore);
  CheckTrue(LConfig.Crypto = Crypto, 'the injected crypto provider is used');
  CheckTrue(LConfig.Pkix = Pkix, 'the injected pkix provider is used');
end;

procedure TTestAdapterCore.TestClientCustomStoreComposes;
var
  LConfig: ITlsClientConfig;
begin
  LConfig := TTlsAdapterConfigComposer.BuildClientConfig(ClientOptsWithStore);
  CheckNotNull(LConfig.TrustStore, 'a custom store is composed into the trust source');
end;

procedure TTestAdapterCore.TestClientNoSourceFailsClosedWithHint;
var
  LOpts: TTlsAdapterOptions;
  LMsg: string;
begin
  LOpts := TTlsAdapterOptions.Default;
  LOpts.TrustSourceHint := 'a RootCertFile bundle';
  CheckTrue(RaisesStreamError(LOpts, True, LMsg),
    'verifying with no trust source fails closed');
  CheckTrue(Pos('a RootCertFile bundle', LMsg) > 0,
    'the message splices the host trust-source hint');
end;

procedure TTestAdapterCore.TestClientInsecureSkipVerifyBuildsWithSkipFlag;
var
  LOpts: TTlsAdapterOptions;
  LConfig: ITlsClientConfig;
begin
  LOpts := TTlsAdapterOptions.Default;
  LOpts.InsecureSkipVerify := True;
  LConfig := TTlsAdapterConfigComposer.BuildClientConfig(LOpts);
  CheckTrue(LConfig.DangerousTrust.InsecureSkipVerify, 'the loud skip flag is set');
  CheckNotNull(LConfig.TrustStore, 'skipping still supplies a store to satisfy the builder');
end;

procedure TTestAdapterCore.TestClientVerifyPeerOffSetsSkipFlag;
var
  LOpts: TTlsAdapterOptions;
  LConfig: ITlsClientConfig;
begin
  LOpts := TTlsAdapterOptions.Default;
  LOpts.VerifyPeer := False;
  LConfig := TTlsAdapterConfigComposer.BuildClientConfig(LOpts);
  CheckTrue(LConfig.DangerousTrust.InsecureSkipVerify,
    'VerifyPeer off maps onto the loud skip flag');
end;

procedure TTestAdapterCore.TestClientCheckHostNameOffDisablesNameCheck;
var
  LOpts: TTlsAdapterOptions;
begin
  LOpts := ClientOptsWithStore;
  LOpts.CheckHostName := False;
  CheckFalse(TTlsAdapterConfigComposer.BuildClientConfig(LOpts).CheckServerName,
    'CheckHostName off disables server-name checking');
end;

procedure TTestAdapterCore.TestClientAlpnForwarded;
var
  LOpts: TTlsAdapterOptions;
  LAlpn: TArray<string>;
begin
  LOpts := ClientOptsWithStore;
  LOpts.AlpnProtocols := TArray<string>.Create('h2', 'http/1.1');
  LAlpn := TTlsAdapterConfigComposer.BuildClientConfig(LOpts).AlpnProtocols;
  CheckEquals(2, System.Length(LAlpn), 'both ALPN protocols are forwarded');
  CheckEquals('h2', LAlpn[0], 'first ALPN protocol');
  CheckEquals('http/1.1', LAlpn[1], 'second ALPN protocol');
end;

procedure TTestAdapterCore.TestClientVerifyCallbackForwarded;
var
  LOpts: TTlsAdapterOptions;
  LConfig: ITlsClientConfig;
begin
  LOpts := ClientOptsWithStore;
  LOpts.VerifyCallback := StubVerifyCallback;
  LConfig := TTlsAdapterConfigComposer.BuildClientConfig(LOpts);
  CheckTrue(Assigned(LConfig.DangerousTrust.VerifyCallback),
    'the augment-only verify callback is forwarded');
end;

procedure TTestAdapterCore.TestClientVerdictResolverArmsLiveRevocation;
var
  LOpts: TTlsAdapterOptions;
  LConfig: ITlsClientConfig;
begin
  LOpts := ClientOptsWithStore;
  LOpts.ClientVerdictResolver := StubResolver;
  LOpts.ClientVerdictDeadlineMs := 1234;
  LConfig := TTlsAdapterConfigComposer.BuildClientConfig(LOpts);
  CheckEquals(Ord(TVerdictDeferral.LiveRevocation),
    Ord(LConfig.AsyncCertificateVerdict.Deferral),
    'a client resolver arms the live-revocation park');
  CheckEquals(1234, LConfig.AsyncCertificateVerdict.DeadlineMs, 'the deadline is carried');
end;

procedure TTestAdapterCore.TestClientNoResolverLeavesInlineVerdict;
begin
  CheckEquals(Ord(TVerdictDeferral.None),
    Ord(TTlsAdapterConfigComposer.BuildClientConfig(ClientOptsWithStore)
      .AsyncCertificateVerdict.Deferral),
    'no resolver keeps the verdict inline');
end;

procedure TTestAdapterCore.TestClientResumptionOnAddsCache;
var
  LConfig: ITlsClientConfig;
begin
  LConfig := TTlsAdapterConfigComposer.BuildClientConfig(ClientOptsWithStore);
  CheckTrue(LConfig.Resumption, 'resumption is engaged by default');
  CheckNotNull(LConfig.SessionCache, 'a session cache is provided');
end;

procedure TTestAdapterCore.TestClientResumptionOffDisablesCache;
var
  LOpts: TTlsAdapterOptions;
begin
  LOpts := ClientOptsWithStore;
  LOpts.SessionResumption := False;
  CheckFalse(TTlsAdapterConfigComposer.BuildClientConfig(LOpts).Resumption,
    'resumption is off when disabled');
end;

procedure TTestAdapterCore.TestClientSystemTrustInstallerCalledForClientRole;
var
  LOpts: TTlsAdapterOptions;
  LFake: TFakeSystemTrustInstaller;
  LInst: ISystemTrustInstaller;
begin
  LFake := TFakeSystemTrustInstaller.Create(False);
  LInst := LFake;
  LOpts := TTlsAdapterOptions.Default;
  LOpts.Pkix := Pkix;
  LOpts.SystemTrust := LInst;
  TTlsAdapterConfigComposer.BuildClientConfig(LOpts);
  CheckTrue(LFake.ClientRoleCalled, 'the installer client-role hook ran');
  CheckFalse(LFake.ServerRoleCalled, 'the server-role hook did not run on a client build');
  CheckTrue(LFake.ClientPkix = Pkix, 'the effective pkix was passed to the installer');
end;

procedure TTestAdapterCore.TestClientVerifierComposesAndBuilds;
var
  LOpts: TTlsAdapterOptions;
  LConfig: ITlsClientConfig;
begin
  LOpts := TTlsAdapterOptions.Default;
  LOpts.ServerCertificateVerifier := TFakeServerVerifier.Create as IServerCertificateVerifier;
  LConfig := TTlsAdapterConfigComposer.BuildClientConfig(LOpts);
  CheckNotNull(LConfig.ServerVerifierSource,
    'a whole-verifier composes into the verifier source');
end;

procedure TTestAdapterCore.TestClientVerifierWithAnchorConflictPropagates;
var
  LOpts: TTlsAdapterOptions;
  LRaised: Boolean;
begin
  LOpts := TTlsAdapterOptions.Default;
  LOpts.ServerCertificateVerifier := TFakeServerVerifier.Create as IServerCertificateVerifier;
  LOpts.CustomTrustStore := TTrustAnchorStore.Create(nil) as ITrustAnchorStore;
  LRaised := False;
  try
    TTlsAdapterConfigComposer.BuildClientConfig(LOpts);
  except
    on E: Exception do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a verifier plus an anchor source is the builder''s typed conflict');
end;

procedure TTestAdapterCore.TestClientRaisingInstallerPropagates;
var
  LOpts: TTlsAdapterOptions;
  LInst: ISystemTrustInstaller;
  LRaised: Boolean;
begin
  LInst := TFakeSystemTrustInstaller.Create(True);
  LOpts := TTlsAdapterOptions.Default;
  LOpts.Pkix := Pkix;
  LOpts.SystemTrust := LInst;
  LRaised := False;
  try
    TTlsAdapterConfigComposer.BuildClientConfig(LOpts);
  except
    on E: EInvalidOperationTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a raising installer propagates out of the build');
end;

procedure TTestAdapterCore.TestServerNoCredentialRaises;
var
  LOpts: TTlsAdapterOptions;
  LMsg: string;
begin
  LOpts := TTlsAdapterOptions.Default;
  CheckTrue(RaisesStreamError(LOpts, False, LMsg),
    'a server without a certificate fails closed');
end;

procedure TTestAdapterCore.TestServerCredentialBuilds;
var
  LConfig: ITlsServerConfig;
begin
  LConfig := TTlsAdapterConfigComposer.BuildServerConfig(ServerOptsWithCredential);
  CheckNotNull(LConfig, 'a server config builds from the credential');
  CheckEquals(Ord(TClientAuthMode.None), Ord(LConfig.ClientAuth),
    'no client-trust source means no client authentication');
end;

procedure TTestAdapterCore.TestServerNoClientSourceLeavesNoClientAuth;
var
  LOpts: TTlsAdapterOptions;
begin
  // a server resolver set but no client-trust source: the park is not armed (today's rule)
  LOpts := ServerOptsWithCredential;
  LOpts.ServerVerdictResolver := StubResolver;
  CheckEquals(Ord(TClientAuthMode.None),
    Ord(TTlsAdapterConfigComposer.BuildServerConfig(LOpts).ClientAuth),
    'a resolver without a client-trust source requests no client auth');
end;

procedure TTestAdapterCore.TestServerClientSourceAppliesClientAuthMode;
var
  LOpts: TTlsAdapterOptions;
begin
  LOpts := ServerOptsWithCredential;
  LOpts.TrustAnchors := TArray<TTlsAdapterBlobSource>.Create(
    TTlsAdapterBlobSource.FromBytes(RootAnchor));
  LOpts.ClientAuth := TClientAuthMode.Requested;
  CheckEquals(Ord(TClientAuthMode.Requested),
    Ord(TTlsAdapterConfigComposer.BuildServerConfig(LOpts).ClientAuth),
    'a client-trust source applies the configured client-auth mode');
end;

procedure TTestAdapterCore.TestServerVerdictResolverArmsLiveRevocation;
var
  LOpts: TTlsAdapterOptions;
  LConfig: ITlsServerConfig;
begin
  // the A-3 pin: a client-CA source plus a server-role resolver arms the client-cert verdict park
  LOpts := ServerOptsWithCredential;
  LOpts.TrustAnchors := TArray<TTlsAdapterBlobSource>.Create(
    TTlsAdapterBlobSource.FromBytes(RootAnchor));
  LOpts.ServerVerdictResolver := StubResolver;
  LOpts.ServerVerdictDeadlineMs := 777;
  LConfig := TTlsAdapterConfigComposer.BuildServerConfig(LOpts);
  CheckEquals(Ord(TVerdictDeferral.LiveRevocation),
    Ord(LConfig.AsyncCertificateVerdict.Deferral),
    'the server-role resolver arms the live-revocation park');
  CheckEquals(777, LConfig.AsyncCertificateVerdict.DeadlineMs, 'the server deadline is carried');
end;

procedure TTestAdapterCore.TestServerVerdictResolverNoSourceStaysInline;
var
  LOpts: TTlsAdapterOptions;
begin
  LOpts := ServerOptsWithCredential;
  LOpts.ServerVerdictResolver := StubResolver;
  CheckEquals(Ord(TVerdictDeferral.None),
    Ord(TTlsAdapterConfigComposer.BuildServerConfig(LOpts).AsyncCertificateVerdict.Deferral),
    'a server resolver without a client-trust source does not arm the park');
end;

procedure TTestAdapterCore.TestServerVerifyPeerOffLeavesNoClientAuth;
var
  LOpts: TTlsAdapterOptions;
begin
  LOpts := ServerOptsWithCredential;
  LOpts.TrustAnchors := TArray<TTlsAdapterBlobSource>.Create(
    TTlsAdapterBlobSource.FromBytes(RootAnchor));
  LOpts.VerifyPeer := False;
  CheckEquals(Ord(TClientAuthMode.None),
    Ord(TTlsAdapterConfigComposer.BuildServerConfig(LOpts).ClientAuth),
    'VerifyPeer off leaves no client authentication even with a source');
end;

procedure TTestAdapterCore.TestServerSystemTrustInstallerCalledForServerRole;
var
  LOpts: TTlsAdapterOptions;
  LFake: TFakeSystemTrustInstaller;
  LInst: ISystemTrustInstaller;
begin
  LFake := TFakeSystemTrustInstaller.Create(False);
  LInst := LFake;
  LOpts := ServerOptsWithCredential;
  LOpts.SystemTrust := LInst;
  TTlsAdapterConfigComposer.BuildServerConfig(LOpts);
  CheckTrue(LFake.ServerRoleCalled, 'the installer server-role hook ran');
  CheckFalse(LFake.ClientRoleCalled, 'the client-role hook did not run on a server build');
  CheckTrue(LFake.ServerPkix = Pkix, 'the effective pkix was passed to the installer');
end;

procedure TTestAdapterCore.TestServerResumptionMintsDefaultStek;
var
  LOpts: TTlsAdapterOptions;
begin
  CheckTrue(TTlsAdapterConfigComposer.BuildServerConfig(ServerOptsWithCredential).Resumption,
    'resumption is engaged by default');
  LOpts := ServerOptsWithCredential;
  LOpts.SessionResumption := False;
  CheckFalse(TTlsAdapterConfigComposer.BuildServerConfig(LOpts).Resumption,
    'resumption is off when disabled');
end;

procedure TTestAdapterCore.TestSignatureEqualOptionsEqualKeys;
var
  LA, LB: TTlsAdapterOptions;
begin
  LA := ClientOptsWithStore;
  LB := ClientOptsWithStore;
  LB.CustomTrustStore := LA.CustomTrustStore; // same store identity
  CheckEquals(TTlsAdapterConfigComposer.ClientSignature(LA),
    TTlsAdapterConfigComposer.ClientSignature(LB),
    'equal options produce equal client signatures');
end;

procedure TTestAdapterCore.TestSignatureEachConcernChangesKey;
var
  LBase, LMut: TTlsAdapterOptions;
  LBaseSig: string;
begin
  LBase := ClientOptsWithStore;
  LBaseSig := TTlsAdapterConfigComposer.ClientSignature(LBase);

  LMut := LBase;
  LMut.SessionResumption := not LBase.SessionResumption;
  CheckFalse(TTlsAdapterConfigComposer.ClientSignature(LMut) = LBaseSig,
    'flipping resumption changes the key');

  LMut := LBase;
  LMut.VerifyPeer := not LBase.VerifyPeer;
  CheckFalse(TTlsAdapterConfigComposer.ClientSignature(LMut) = LBaseSig,
    'flipping VerifyPeer changes the key');

  LMut := LBase;
  LMut.CheckHostName := not LBase.CheckHostName;
  CheckFalse(TTlsAdapterConfigComposer.ClientSignature(LMut) = LBaseSig,
    'flipping CheckHostName changes the key');

  LMut := LBase;
  LMut.KeyPassword := 'changed';
  CheckFalse(TTlsAdapterConfigComposer.ClientSignature(LMut) = LBaseSig,
    'changing the key password changes the key');

  LMut := LBase;
  LMut.AlpnProtocols := TArray<string>.Create('h2');
  CheckFalse(TTlsAdapterConfigComposer.ClientSignature(LMut) = LBaseSig,
    'adding ALPN changes the key');

  LMut := LBase;
  LMut.Certificate := TTlsAdapterBlobSource.FromBytes(ServerCert);
  CheckFalse(TTlsAdapterConfigComposer.ClientSignature(LMut) = LBaseSig,
    'a credential blob changes the key');
end;

procedure TTestAdapterCore.TestSignatureExcludesResolverAndTimeout;
var
  LBase, LMut: TTlsAdapterOptions;
  LBaseSig: string;
begin
  LBase := ClientOptsWithStore;
  LBaseSig := TTlsAdapterConfigComposer.ClientSignature(LBase);

  LMut := LBase;
  LMut.HandshakeTimeoutMs := 5000;
  CheckEquals(LBaseSig, TTlsAdapterConfigComposer.ClientSignature(LMut),
    'the handshake timeout is not part of the config identity');

  // a different resolver instance keeps the key: only assigned-or-not participates
  LBase.ClientVerdictResolver := StubResolver;
  LMut := LBase;
  LMut.ClientVerdictResolver := StubResolverAlt;
  CheckEquals(TTlsAdapterConfigComposer.ClientSignature(LBase),
    TTlsAdapterConfigComposer.ClientSignature(LMut),
    'a different resolver pointer does not change the key');
end;

procedure TTestAdapterCore.TestSignaturePasswordNotInClear;
var
  LOpts: TTlsAdapterOptions;
begin
  LOpts := ClientOptsWithStore;
  LOpts.KeyPassword := 'sup3r-s3cret-passphrase';
  CheckTrue(Pos('sup3r-s3cret-passphrase',
    TTlsAdapterConfigComposer.ClientSignature(LOpts)) = 0,
    'the key password never appears in clear in the signature');
end;

procedure TTestAdapterCore.TestResolveMemoisesBuildOnce;
var
  LOpts: TTlsAdapterOptions;
  LMemo: ITlsClientConfigMemo;
  LFirst, LSecond: ITlsClientConfig;
begin
  LOpts := ClientOptsWithStore;
  LMemo := NewTlsClientConfigMemo;
  LFirst := TTlsAdapterConfigComposer.ResolveClientConfig(LOpts, LMemo, 'ClientConfig');
  LSecond := TTlsAdapterConfigComposer.ResolveClientConfig(LOpts, LMemo, 'ClientConfig');
  CheckTrue(LFirst = LSecond, 'a memo hit reuses the same config identity');
end;

procedure TTestAdapterCore.TestResolveConfigInReturnedAsIs;
var
  LOpts: TTlsAdapterOptions;
  LMemo: ITlsClientConfigMemo;
  LSupplied, LResolved: ITlsClientConfig;
  LProbe: ITlsClientConfig;
begin
  LSupplied := TTlsAdapterConfigComposer.BuildClientConfig(ClientOptsWithStore);
  // a config-in with no conflicting options is returned verbatim, and the memo stays empty
  LOpts := TTlsAdapterOptions.Default;
  LOpts.ClientConfig := LSupplied;
  LMemo := NewTlsClientConfigMemo;
  LResolved := TTlsAdapterConfigComposer.ResolveClientConfig(LOpts, LMemo, 'ClientConfig');
  CheckTrue(LResolved = LSupplied, 'the supplied config is returned as-is');
  CheckFalse(LMemo.TryGet(TTlsAdapterConfigComposer.ClientSignature(LOpts), LProbe),
    'the memo is untouched when a config is supplied');
end;

procedure TTestAdapterCore.TestGuardConflictOnEachField;

  procedure ExpectConflict(const AOpts: TTlsAdapterOptions; const AWhat: string);
  var
    LOpts: TTlsAdapterOptions;
    LMemo: ITlsClientConfigMemo;
    LRaised: Boolean;
  begin
    LOpts := AOpts;
    LOpts.ClientConfig := TTlsAdapterConfigComposer.BuildClientConfig(ClientOptsWithStore);
    LMemo := NewTlsClientConfigMemo;
    LRaised := False;
    try
      TTlsAdapterConfigComposer.ResolveClientConfig(LOpts, LMemo, 'ClientConfig');
    except
      on E: ETlsStreamError do
        LRaised := True;
    end;
    CheckTrue(LRaised, 'a config supplied alongside ' + AWhat + ' fails loud');
  end;

var
  LOpts: TTlsAdapterOptions;
begin
  LOpts := TTlsAdapterOptions.Default;
  LOpts.Certificate := TTlsAdapterBlobSource.FromBytes(ServerCert);
  ExpectConflict(LOpts, 'a certificate');

  LOpts := TTlsAdapterOptions.Default;
  LOpts.CustomTrustStore := TTrustAnchorStore.Create(nil) as ITrustAnchorStore;
  ExpectConflict(LOpts, 'a custom store');

  LOpts := TTlsAdapterOptions.Default;
  LOpts.TrustAnchors := TArray<TTlsAdapterBlobSource>.Create(
    TTlsAdapterBlobSource.FromBytes(RootAnchor));
  ExpectConflict(LOpts, 'trust anchors');

  LOpts := TTlsAdapterOptions.Default;
  LOpts.Crypto := Crypto;
  ExpectConflict(LOpts, 'an injected crypto provider');

  LOpts := TTlsAdapterOptions.Default;
  LOpts.SystemTrust := TFakeSystemTrustInstaller.Create(False) as ISystemTrustInstaller;
  ExpectConflict(LOpts, 'system trust');
end;

procedure TTestAdapterCore.TestGuardIncludesVerifyCallback;
var
  LOpts: TTlsAdapterOptions;
  LMemo: ITlsClientConfigMemo;
  LRaised: Boolean;
begin
  LOpts := TTlsAdapterOptions.Default;
  LOpts.VerifyCallback := StubVerifyCallback;
  LOpts.ClientConfig := TTlsAdapterConfigComposer.BuildClientConfig(ClientOptsWithStore);
  LMemo := NewTlsClientConfigMemo;
  LRaised := False;
  try
    TTlsAdapterConfigComposer.ResolveClientConfig(LOpts, LMemo, 'ClientConfig');
  except
    on E: ETlsStreamError do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a VerifyCallback conflicts with a supplied config');
end;

procedure TTestAdapterCore.TestGuardMessageNamesTheProperty;
var
  LOpts: TTlsAdapterOptions;
  LMsg: string;
begin
  LOpts := TTlsAdapterOptions.Default;
  LOpts.CustomTrustStore := TTrustAnchorStore.Create(nil) as ITrustAnchorStore;
  LMsg := '';
  try
    TTlsAdapterConfigComposer.GuardNoConflict(LOpts, 'ServerConfig');
  except
    on E: ETlsStreamError do
      LMsg := E.Message;
  end;
  CheckTrue(Pos('ServerConfig', LMsg) > 0, 'the conflict message names the config property');
end;

procedure TTestAdapterCore.TestGuardIgnoresResolverAndTimeout;
var
  LOpts: TTlsAdapterOptions;
begin
  // resolvers and the handshake timeout are runtime hooks - never a config-in conflict
  LOpts := TTlsAdapterOptions.Default;
  LOpts.HandshakeTimeoutMs := 5000;
  LOpts.ClientVerdictResolver := StubResolver;
  LOpts.ServerVerdictResolver := StubResolver;
  // no raise expected
  TTlsAdapterConfigComposer.GuardNoConflict(LOpts, 'ClientConfig');
  CheckTrue(True, 'a resolver or timeout alone does not conflict');
end;

procedure TTestAdapterCore.TestTransportTimesOutWhenSilent;
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

procedure TTestAdapterCore.TestTransportReturnsDataWhenReadable;
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

procedure TTestAdapterCore.TestTransportCapZeroDoesNotWait;
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

procedure TTestAdapterCore.TestTransportNegativeReceiveIsEof;
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

procedure TTestAdapterCore.TestTransportWriteCompletesOverPartialSends;
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

procedure TTestAdapterCore.TestTransportSetReadTimeoutIsObservable;
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
  RegisterTest(TTestAdapterCore);
{$ELSE}
  RegisterTest(TTestAdapterCore.Suite);
{$ENDIF FPC}

end.
