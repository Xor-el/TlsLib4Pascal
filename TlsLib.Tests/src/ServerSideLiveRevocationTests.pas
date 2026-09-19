{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit ServerSideLiveRevocationTests;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  SysUtils,
  Classes,
{$IFDEF FPC}
  fpcunit,
  testregistry,
{$ELSE}
  TestFramework,
{$ENDIF FPC}
  TlpTlsVersion,
  TlpTlsAlert,
  TlpIClock,
  TlpClock,
  TlpIHttpFetcher,
  TlpTrustPolicy,
  TlpTlsCredential,
  TlpITlsConfig,
  TlpITlsConfigBuilder,
  TlpTlsPresets,
  TlpTlsEngineFactory,
  TlpITlsTransport,
  TlpTlsStream,
  TlpTlsLibExceptions,
  TlpLiveRevocation,
  TlsStreamLoopbackTests, // TMemoryPipe / TMemoryTransport - the loopback duplex
  LiveRevocationTests,    // TFakeHttpFetcher - the no-network OCSP/CRL double
  TlsLibTestBase;

type
  /// <summary>Runs the mTLS server side of a loopback on its own thread, verifying the client
  /// certificate through the async verdict park with the supplied resolver. Captures whether the
  /// handshake completed, the client-chain size, and any fatal alert the server itself emitted
  /// (a rejected client-cert verdict aborts with that alert).</summary>
  TMtlsLiveServerRunner = class(TThread)
  strict private
  var
    FStream: TTlsStream;
    FTransport: TMemoryTransport;
    FResolver: TCertificateVerdictResolver;
    FEcho: Boolean;
    FError: string;
    FHandshakeOk: Boolean;
    FHasAlert: Boolean;
    FAlert: TTlsAlertDescription;
    FPeerCertCount: Int32;
  protected
    procedure Execute; override;
  public
    constructor Create(const AStream: TTlsStream; const ATransport: TMemoryTransport;
      const AResolver: TCertificateVerdictResolver; AEcho: Boolean);
    destructor Destroy; override;
    property Error: string read FError;
    property HandshakeOk: Boolean read FHandshakeOk;
    property HasAlert: Boolean read FHasAlert;
    property Alert: TTlsAlertDescription read FAlert;
    property PeerCertCount: Int32 read FPeerCertCount;
  end;

  /// <summary>
  /// End-to-end mutual-TLS live client-certificate revocation over the blocking stream/pump:
  /// a server requiring client auth parks on the client chain and resolves the verdict with a
  /// real TLiveRevocationChecker (live OCSP/CRL over a fake fetcher). Proves the server direction
  /// of the async verdict seam, the portable issuer recovery for a leaf-only client credential
  /// (the CA is a configured anchor, not sent on the wire), and the fail-closed matrix -
  /// certificate_revoked reaching the peer, indeterminate gated by posture - on TLS 1.3 and 1.2.
  /// </summary>
  TTestServerSideLiveRevocation = class(TTlsLibAlgorithmTestCase)
  strict private
    FFetcher: TFakeHttpFetcher; // one primed fetcher per test, referenced by the checker
    function CertField(const AName: string): TBytes;
    function ServerRoot: TBytes;
    function ServerLeaf: TBytes;
    function ServerKey: TBytes;
    function ClientCa: TBytes;
    function ClientLeaf: TBytes;
    function ClientKey: TBytes;
    function ServerConfig(APosture: TRevocationPosture; AForce12: Boolean): ITlsServerConfig;
    function ClientConfig(AForce12: Boolean): ITlsClientConfig;
    function NewClientStream(const ATransport: ITlsTransport;
      const AConfig: ITlsClientConfig): TTlsStream;
    function NewServerStream(const ATransport: ITlsTransport;
      const AConfig: ITlsServerConfig): TTlsStream;
    procedure RunLoopback(const AClientConfig: ITlsClientConfig;
      const AServerConfig: ITlsServerConfig;
      const AResolver: TCertificateVerdictResolver; AEcho: Boolean;
      out AClient: TTlsStream; out AServer: TMtlsLiveServerRunner;
      out AClientTransport: TMemoryTransport);
    /// <summary>A live checker over the primed fetcher, given the client-CA as the issuer
    /// candidate so a leaf-only client chain resolves its issuer.</summary>
    function NewChecker(APosture: TRevocationPosture;
      AWithCandidates: Boolean): TLiveRevocationChecker;
    function StubAccept(const ACtx: TCertificateVerdictContext;
      out ARejectAlert: TTlsAlertDescription): Boolean;
    function StubReject(const ACtx: TCertificateVerdictContext;
      out ARejectAlert: TTlsAlertDescription): Boolean;
    /// <summary>Drives the client to completion then reads once, surfacing whatever fatal alert
    /// the server sent (during the handshake on 1.2, or post-handshake on 1.3). Returns the alert
    /// or raises the test-failure if the client saw no fatal alert.</summary>
    function ClientFatalAlert(const AClient: TTlsStream): TTlsAlertDescription;
    procedure ExchangePingEcho(const AClient: TTlsStream);
  protected
    procedure TearDown; override;
  published
    procedure TestLiveGoodClientCompletesTls13;
    procedure TestLiveRevokedClientRejectedTls13;
    procedure TestLiveIndeterminateHardRejectsTls13;
    procedure TestLiveIndeterminateSoftAcceptsTls13;
    procedure TestLiveGoodClientCompletesTls12;
    procedure TestLiveRevokedClientRejectedTls12;
    procedure TestStubResolverAcceptCompletes;
    procedure TestStubResolverRejectAborts;
    procedure TestLeafOnlyWithoutIssuerCandidateRejectsUnderHard;
  end;

implementation

const
  // "ping from the client"
  PingHex = '70696e672066726f6d2074686520636c69656e74';

{ TMtlsLiveServerRunner }

constructor TMtlsLiveServerRunner.Create(const AStream: TTlsStream;
  const ATransport: TMemoryTransport; const AResolver: TCertificateVerdictResolver;
  AEcho: Boolean);
begin
  inherited Create(True);
  FStream := AStream;
  FTransport := ATransport;
  FResolver := AResolver;
  FEcho := AEcho;
  FreeOnTerminate := False;
end;

destructor TMtlsLiveServerRunner.Destroy;
begin
  // inherited waits for Execute to finish; then free the server stream we own (it releases the
  // engine and the transport)
  inherited Destroy;
  FStream.Free;
end;

procedure TMtlsLiveServerRunner.Execute;
var
  LChunk: TBytes;
  LGot: Int32;
begin
  try
    if System.Assigned(FResolver) then
      FStream.SetCertificateVerdictResolver(FResolver);
    FStream.Handshake;
    FHandshakeOk := True;
    FPeerCertCount := System.Length(FStream.ConnectionInfo.PeerCertificates);
    if FEcho then
    begin
      SetLength(LChunk, 4096);
      LGot := FStream.Read(LChunk[0], System.Length(LChunk));
      if LGot > 0 then
        FStream.Write(LChunk[0], LGot);
      FStream.CloseNotify;
    end;
  except
    on E: ETlsStreamError do
    begin
      FError := E.Message;
      if E.HasAlert then
      begin
        FHasAlert := True;
        FAlert := E.Alert;
      end;
    end;
    on E: Exception do
      FError := E.ClassName + ': ' + E.Message;
  end;
end;

{ TTestServerSideLiveRevocation }

procedure TTestServerSideLiveRevocation.TearDown;
begin
  FFetcher := nil; // an interface reference; the checker held the only other one
  inherited TearDown;
end;

function TTestServerSideLiveRevocation.CertField(const AName: string): TBytes;
var
  LV: TStringList;
begin
  LV := LoadVectorFields('Certs/LiveRevocation.txt');
  try
    Result := DecodeHex(LV.Values[AName]);
  finally
    LV.Free;
  end;
end;

function TTestServerSideLiveRevocation.ServerRoot: TBytes;
var
  LV: TStringList;
begin
  LV := LoadVectorFields('Certs/EcP256Chain.txt');
  try
    Result := DecodeHex(LV.Values['root_cert']);
  finally
    LV.Free;
  end;
end;

function TTestServerSideLiveRevocation.ServerLeaf: TBytes;
var
  LV: TStringList;
begin
  LV := LoadVectorFields('Certs/EcP256Chain.txt');
  try
    Result := DecodeHex(LV.Values['leaf_cert']);
  finally
    LV.Free;
  end;
end;

function TTestServerSideLiveRevocation.ServerKey: TBytes;
var
  LV: TStringList;
begin
  LV := LoadVectorFields('Certs/EcP256Chain.txt');
  try
    Result := DecodeHex(LV.Values['leaf_key']);
  finally
    LV.Free;
  end;
end;

function TTestServerSideLiveRevocation.ClientCa: TBytes;
begin
  Result := CertField('ca_cert');
end;

function TTestServerSideLiveRevocation.ClientLeaf: TBytes;
begin
  // the LiveRevocation leaf carries no EKU (so it is acceptable as a client certificate) and an
  // AIA OCSP + CRL DP with matching good/revoked responses in the same vector file
  Result := CertField('leaf_cert');
end;

function TTestServerSideLiveRevocation.ClientKey: TBytes;
begin
  Result := CertField('leaf_key');
end;

function TTestServerSideLiveRevocation.ServerConfig(APosture: TRevocationPosture;
  AForce12: Boolean): ITlsServerConfig;
var
  LServer: ITlsServerConfigBuilder;
begin
  LServer := TTlsPresets.Compatible(Provider).Server
    .WithCredential(ServerLeaf, ServerKey)
    .WithPeerAuth(TClientAuthMode.Required)
    .WithTrustAnchors(ClientCa) // the private client CA (issues the client leaf)
    .WithRevocation(APosture)
    .WithAsyncCertificateVerdict(True, 0); // arm the park so the resolver runs off the engine
  if AForce12 then
    LServer.WithSupportedVersions(TArray<UInt16>.Create(TlsWireVersionTls12));
  Result := LServer.Build;
end;

function TTestServerSideLiveRevocation.ClientConfig(AForce12: Boolean): ITlsClientConfig;
var
  LClient: ITlsClientConfigBuilder;
begin
  LClient := TTlsPresets.Compatible(Provider).Client
    .WithTrustAnchors(ServerRoot)
    .WithCredential(ClientLeaf, ClientKey); // present the client certificate (leaf only)
  if AForce12 then
    LClient.WithSupportedVersions(TArray<UInt16>.Create(TlsWireVersionTls12));
  Result := LClient.Build;
end;

function TTestServerSideLiveRevocation.NewClientStream(const ATransport: ITlsTransport;
  const AConfig: ITlsClientConfig): TTlsStream;
begin
  Result := TTlsStream.Create(ATransport,
    TTlsEngineFactory.CreateClientEngine(AConfig, 'localhost'), True, 'localhost');
end;

function TTestServerSideLiveRevocation.NewServerStream(const ATransport: ITlsTransport;
  const AConfig: ITlsServerConfig): TTlsStream;
begin
  Result := TTlsStream.Create(ATransport,
    TTlsEngineFactory.CreateServerEngine(AConfig), False, '');
end;

procedure TTestServerSideLiveRevocation.RunLoopback(const AClientConfig: ITlsClientConfig;
  const AServerConfig: ITlsServerConfig;
  const AResolver: TCertificateVerdictResolver; AEcho: Boolean;
  out AClient: TTlsStream; out AServer: TMtlsLiveServerRunner;
  out AClientTransport: TMemoryTransport);
var
  LC2S, LS2C: TMemoryPipe;
  LServerTransport: TMemoryTransport;
  LServerStream: TTlsStream;
begin
  LC2S := TMemoryPipe.Create;
  LS2C := TMemoryPipe.Create;
  AClientTransport := TMemoryTransport.Create(LS2C, LC2S);
  LServerTransport := TMemoryTransport.Create(LC2S, LS2C);
  AClient := NewClientStream(AClientTransport as ITlsTransport, AClientConfig);
  LServerStream := NewServerStream(LServerTransport as ITlsTransport, AServerConfig);
  AServer := TMtlsLiveServerRunner.Create(LServerStream, LServerTransport, AResolver, AEcho);
  AServer.Start;
end;

function TTestServerSideLiveRevocation.NewChecker(APosture: TRevocationPosture;
  AWithCandidates: Boolean): TLiveRevocationChecker;
begin
  if AWithCandidates then
    Result := TLiveRevocationChecker.Create(Provider, TSystemClock.Create as ITlsClock,
      FFetcher, APosture, TLiveRevocationMethod.OcspThenCrl, 0,
      TArray<TBytes>.Create(ClientCa))
  else
    Result := TLiveRevocationChecker.Create(Provider, TSystemClock.Create as ITlsClock,
      FFetcher, APosture, TLiveRevocationMethod.OcspThenCrl, 0);
end;

function TTestServerSideLiveRevocation.StubAccept(
  const ACtx: TCertificateVerdictContext;
  out ARejectAlert: TTlsAlertDescription): Boolean;
begin
  ARejectAlert := TTlsAlertDescription.BadCertificate;
  Result := System.Length(ACtx.Chain) > 0;
end;

function TTestServerSideLiveRevocation.StubReject(
  const ACtx: TCertificateVerdictContext;
  out ARejectAlert: TTlsAlertDescription): Boolean;
begin
  ARejectAlert := TTlsAlertDescription.CertificateRevoked;
  Result := False;
end;

function TTestServerSideLiveRevocation.ClientFatalAlert(
  const AClient: TTlsStream): TTlsAlertDescription;
var
  LBuf: TBytes;
begin
  Result := TTlsAlertDescription.InternalError;
  try
    AClient.Handshake;
    // TLS 1.3: the client completes before the server's post-verify alert; a read surfaces it
    SetLength(LBuf, 256);
    AClient.Read(LBuf[0], System.Length(LBuf));
    Fail('the client did not observe the server abort');
  except
    on E: ETlsStreamError do
    begin
      CheckTrue(E.HasAlert, 'the client observed a fatal alert from the server');
      Result := E.Alert;
    end;
  end;
end;

procedure TTestServerSideLiveRevocation.ExchangePingEcho(const AClient: TTlsStream);
var
  LPing, LEcho: TBytes;
  LGot: Int32;
begin
  LPing := DecodeHex(PingHex);
  AClient.Write(LPing[0], System.Length(LPing));
  SetLength(LEcho, 4096);
  LGot := AClient.Read(LEcho[0], System.Length(LEcho));
  CheckEqualBytes('the server echoed the client message', LPing,
    System.Copy(LEcho, 0, LGot));
end;

procedure TTestServerSideLiveRevocation.TestLiveGoodClientCompletesTls13;
var
  LClient: TTlsStream;
  LServer: TMtlsLiveServerRunner;
  LTransport: TMemoryTransport;
  LChecker: TLiveRevocationChecker;
begin
  FFetcher := TFakeHttpFetcher.Create;
  FFetcher.SetPost(True, CertField('ocsp_good'));
  LChecker := NewChecker(TRevocationPosture.Hard, True);
  try
    RunLoopback(ClientConfig(False), ServerConfig(TRevocationPosture.Hard, False),
      LChecker.ResolveVerdict, True, LClient, LServer, LTransport);
    try
      LClient.Handshake;
      CheckTrue(LClient.IsHandshakeComplete, 'the client completed the mTLS handshake');
      ExchangePingEcho(LClient);
      LClient.CloseNotify;
      LServer.WaitFor;
      CheckTrue(LServer.HandshakeOk, 'the server accepted the live-good client certificate');
      CheckTrue(LServer.PeerCertCount >= 1, 'the server surfaced the client certificate');
      CheckEquals('', LServer.Error, 'the server side ran without error');
      CheckEquals(1, FFetcher.PostCount, 'the live OCSP responder was queried once');
    finally
      LServer.Free;
      LClient.Free;
    end;
  finally
    LChecker.Free;
  end;
end;

procedure TTestServerSideLiveRevocation.TestLiveRevokedClientRejectedTls13;
var
  LClient: TTlsStream;
  LServer: TMtlsLiveServerRunner;
  LTransport: TMemoryTransport;
  LChecker: TLiveRevocationChecker;
  LAlert: TTlsAlertDescription;
begin
  FFetcher := TFakeHttpFetcher.Create;
  FFetcher.SetPost(True, CertField('ocsp_revoked'));
  LChecker := NewChecker(TRevocationPosture.Hard, True);
  try
    RunLoopback(ClientConfig(False), ServerConfig(TRevocationPosture.Hard, False),
      LChecker.ResolveVerdict, False, LClient, LServer, LTransport);
    try
      LAlert := ClientFatalAlert(LClient);
      CheckEquals(Int64(Ord(TTlsAlertDescription.CertificateRevoked)), Int64(Ord(LAlert)),
        'the client receives certificate_revoked for the revoked client certificate');
      LServer.WaitFor;
      CheckFalse(LServer.HandshakeOk, 'the server rejected the revoked client certificate');
      CheckTrue(LServer.HasAlert, 'the server aborted with an alert');
      CheckEquals(Int64(Ord(TTlsAlertDescription.CertificateRevoked)),
        Int64(Ord(LServer.Alert)), 'the server emitted certificate_revoked');
    finally
      LServer.Free;
      LClient.Free;
    end;
  finally
    LChecker.Free;
  end;
end;

procedure TTestServerSideLiveRevocation.TestLiveIndeterminateHardRejectsTls13;
var
  LClient: TTlsStream;
  LServer: TMtlsLiveServerRunner;
  LTransport: TMemoryTransport;
  LChecker: TLiveRevocationChecker;
  LAlert: TTlsAlertDescription;
begin
  // the responder is unreachable (fetch fails) -> indeterminate; under Hard the server rejects
  FFetcher := TFakeHttpFetcher.Create;
  FFetcher.SetPost(False, nil);
  FFetcher.SetGet(False, nil);
  LChecker := NewChecker(TRevocationPosture.Hard, True);
  try
    RunLoopback(ClientConfig(False), ServerConfig(TRevocationPosture.Hard, False),
      LChecker.ResolveVerdict, False, LClient, LServer, LTransport);
    try
      LAlert := ClientFatalAlert(LClient);
      CheckEquals(Int64(Ord(TTlsAlertDescription.BadCertificateStatusResponse)),
        Int64(Ord(LAlert)),
        'an unreachable responder under Hard rejects with bad_certificate_status_response');
      LServer.WaitFor;
      CheckFalse(LServer.HandshakeOk, 'the server rejected the indeterminate client under Hard');
    finally
      LServer.Free;
      LClient.Free;
    end;
  finally
    LChecker.Free;
  end;
end;

procedure TTestServerSideLiveRevocation.TestLiveIndeterminateSoftAcceptsTls13;
var
  LClient: TTlsStream;
  LServer: TMtlsLiveServerRunner;
  LTransport: TMemoryTransport;
  LChecker: TLiveRevocationChecker;
begin
  // same unreachable responder, but Soft accepts an indeterminate result
  FFetcher := TFakeHttpFetcher.Create;
  FFetcher.SetPost(False, nil);
  FFetcher.SetGet(False, nil);
  LChecker := NewChecker(TRevocationPosture.Soft, True);
  try
    RunLoopback(ClientConfig(False), ServerConfig(TRevocationPosture.Soft, False),
      LChecker.ResolveVerdict, True, LClient, LServer, LTransport);
    try
      LClient.Handshake;
      CheckTrue(LClient.IsHandshakeComplete,
        'Soft accepts an indeterminate live result and completes the handshake');
      ExchangePingEcho(LClient);
      LClient.CloseNotify;
      LServer.WaitFor;
      CheckTrue(LServer.HandshakeOk, 'the server accepted the client under Soft');
      CheckEquals('', LServer.Error, 'the server side ran without error');
    finally
      LServer.Free;
      LClient.Free;
    end;
  finally
    LChecker.Free;
  end;
end;

procedure TTestServerSideLiveRevocation.TestLiveGoodClientCompletesTls12;
var
  LClient: TTlsStream;
  LServer: TMtlsLiveServerRunner;
  LTransport: TMemoryTransport;
  LChecker: TLiveRevocationChecker;
begin
  // the TLS 1.2 server machine also parks on the client-chain verdict; a live-good client completes
  FFetcher := TFakeHttpFetcher.Create;
  FFetcher.SetPost(True, CertField('ocsp_good'));
  LChecker := NewChecker(TRevocationPosture.Hard, True);
  try
    RunLoopback(ClientConfig(True), ServerConfig(TRevocationPosture.Hard, True),
      LChecker.ResolveVerdict, True, LClient, LServer, LTransport);
    try
      LClient.Handshake;
      CheckEquals(Integer(TlsWireVersionTls12),
        Integer(LClient.ConnectionInfo.NegotiatedVersion.WireValue),
        'the handshake negotiated TLS 1.2');
      CheckTrue(LClient.IsHandshakeComplete, 'the client completed the 1.2 mTLS handshake');
      ExchangePingEcho(LClient);
      LClient.CloseNotify;
      LServer.WaitFor;
      CheckTrue(LServer.HandshakeOk, 'the 1.2 server accepted the live-good client certificate');
      CheckEquals('', LServer.Error, 'the server side ran without error');
    finally
      LServer.Free;
      LClient.Free;
    end;
  finally
    LChecker.Free;
  end;
end;

procedure TTestServerSideLiveRevocation.TestLiveRevokedClientRejectedTls12;
var
  LClient: TTlsStream;
  LServer: TMtlsLiveServerRunner;
  LTransport: TMemoryTransport;
  LChecker: TLiveRevocationChecker;
  LAlert: TTlsAlertDescription;
begin
  // the 1.2 server parks on the client chain, the live checker reports Revoked, and the server
  // aborts with certificate_revoked before it sends its ChangeCipherSpec. The client reads that
  // plaintext alert under the right epoch (its read epoch stays plaintext until the server's CCS)
  // and surfaces the exact code, matching the TLS 1.3 sibling.
  FFetcher := TFakeHttpFetcher.Create;
  FFetcher.SetPost(True, CertField('ocsp_revoked'));
  LChecker := NewChecker(TRevocationPosture.Hard, True);
  try
    RunLoopback(ClientConfig(True), ServerConfig(TRevocationPosture.Hard, True),
      LChecker.ResolveVerdict, False, LClient, LServer, LTransport);
    try
      LAlert := ClientFatalAlert(LClient);
      CheckEquals(Int64(Ord(TTlsAlertDescription.CertificateRevoked)), Int64(Ord(LAlert)),
        'the 1.2 client receives certificate_revoked for the revoked client certificate');
      LServer.WaitFor;
      CheckFalse(LServer.HandshakeOk, 'the 1.2 server rejected the revoked client certificate');
      CheckTrue(LServer.HasAlert, 'the 1.2 server aborted with an alert');
      CheckEquals(Int64(Ord(TTlsAlertDescription.CertificateRevoked)),
        Int64(Ord(LServer.Alert)), 'the 1.2 server emitted certificate_revoked');
    finally
      LServer.Free;
      LClient.Free;
    end;
  finally
    LChecker.Free;
  end;
end;

procedure TTestServerSideLiveRevocation.TestStubResolverAcceptCompletes;
var
  LClient: TTlsStream;
  LServer: TMtlsLiveServerRunner;
  LTransport: TMemoryTransport;
begin
  // the server park -> resolve -> resume wiring, independent of the live checker
  RunLoopback(ClientConfig(False), ServerConfig(TRevocationPosture.Hard, False),
    StubAccept, True, LClient, LServer, LTransport);
  try
    LClient.Handshake;
    CheckTrue(LClient.IsHandshakeComplete, 'an accepted server verdict completes the handshake');
    ExchangePingEcho(LClient);
    LClient.CloseNotify;
    LServer.WaitFor;
    CheckTrue(LServer.HandshakeOk, 'the server accepted the client via the stub resolver');
    CheckEquals('', LServer.Error, 'the server side ran without error');
  finally
    LServer.Free;
    LClient.Free;
  end;
end;

procedure TTestServerSideLiveRevocation.TestStubResolverRejectAborts;
var
  LClient: TTlsStream;
  LServer: TMtlsLiveServerRunner;
  LTransport: TMemoryTransport;
  LAlert: TTlsAlertDescription;
begin
  RunLoopback(ClientConfig(False), ServerConfig(TRevocationPosture.Hard, False),
    StubReject, False, LClient, LServer, LTransport);
  try
    LAlert := ClientFatalAlert(LClient);
    CheckEquals(Int64(Ord(TTlsAlertDescription.CertificateRevoked)), Int64(Ord(LAlert)),
      'a rejected server verdict aborts the handshake with the resolver alert');
    LServer.WaitFor;
    CheckFalse(LServer.HandshakeOk, 'the server rejected the client via the stub resolver');
  finally
    LServer.Free;
    LClient.Free;
  end;
end;

procedure TTestServerSideLiveRevocation.TestLeafOnlyWithoutIssuerCandidateRejectsUnderHard;
var
  LClient: TTlsStream;
  LServer: TMtlsLiveServerRunner;
  LTransport: TMemoryTransport;
  LChecker: TLiveRevocationChecker;
  LAlert: TTlsAlertDescription;
begin
  // a good OCSP is primed, but the checker is given NO issuer candidates: a leaf-only client chain
  // then has no issuer to authenticate a response, so the live check is indeterminate and never even
  // fetches - under Hard the server rejects. This locks the documented recovery-required behaviour.
  FFetcher := TFakeHttpFetcher.Create;
  FFetcher.SetPost(True, CertField('ocsp_good'));
  LChecker := NewChecker(TRevocationPosture.Hard, False);
  try
    RunLoopback(ClientConfig(False), ServerConfig(TRevocationPosture.Hard, False),
      LChecker.ResolveVerdict, False, LClient, LServer, LTransport);
    try
      LAlert := ClientFatalAlert(LClient);
      CheckEquals(Int64(Ord(TTlsAlertDescription.BadCertificateStatusResponse)),
        Int64(Ord(LAlert)),
        'a leaf-only client with no recoverable issuer is indeterminate -> Hard rejects');
      LServer.WaitFor;
      CheckFalse(LServer.HandshakeOk, 'the server rejected the unrecoverable-issuer client');
      CheckEquals(0, FFetcher.PostCount,
        'no OCSP fetch is attempted when the issuer cannot be recovered');
    finally
      LServer.Free;
      LClient.Free;
    end;
  finally
    LChecker.Free;
  end;
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestServerSideLiveRevocation);
{$ELSE}
  RegisterTest(TTestServerSideLiveRevocation.Suite);
{$ENDIF FPC}

end.
