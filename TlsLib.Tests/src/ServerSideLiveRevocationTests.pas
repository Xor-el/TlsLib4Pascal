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
  TlpTrustPolicy,
  TlpTlsCredential,
  TlpITlsConfig,
  TlpITlsConfigBuilder,
  TlpCertificateVerifierSource,
  TlpTlsPresets,
  TlpTlsEngineFactory,
  TlpITlsTransport,
  TlpTlsStream,
  TlpTlsLibExceptions,
  TlpLiveRevocation,
  MockTransport,
  MockHttpFetcher,
  MockVerifyHooks,
  TlsLibTestCertificates,
  TlsLibTestBase;

type
  /// <summary>Runs the mTLS server side of a loopback on its own thread, verifying the client
  /// certificate through the async verdict park with the supplied resolver. Captures whether the
  /// handshake completed, the client-chain size, and any fatal alert the server itself emitted
  /// (a rejected client-cert verdict aborts with that alert).</summary>
  TMtlsLiveServerRunner = class(TLoopbackServerThread)
  strict private
  var
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
    constructor Create(const AStream: TTlsStream; const ATransport,
      AClientTransport: TMemoryTransport; const AResolver: TCertificateVerdictResolver;
      AEcho: Boolean);
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
    FFetcher: TMockHttpFetcher; // one primed fetcher per test, referenced by the checker
    function ServerConfig(APosture: TRevocationPosture; AForce12: Boolean): ITlsServerConfig;
    function ClientConfig(AForce12: Boolean): ITlsClientConfig;
    procedure RunLoopback(const AClientConfig: ITlsClientConfig;
      const AServerConfig: ITlsServerConfig;
      const AResolver: TCertificateVerdictResolver; AEcho: Boolean;
      out AClient: TTlsStream; out AServer: TMtlsLiveServerRunner;
      out AClientTransport: TMemoryTransport);
    /// <summary>A live checker over the primed fetcher, given the client-CA as the issuer
    /// candidate so a leaf-only client chain resolves its issuer.</summary>
    function NewChecker(APosture: TRevocationPosture;
      AWithCandidates: Boolean): TLiveRevocationChecker;
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
    procedure TestLeafOnlyClientResolvesIssuerFromValidatedPathWithoutCandidates;
    procedure TestLeafOnlyClientBadResponseRejectsUnderHardWithoutCandidates;
  end;

implementation

const
  // "ping from the client"
  PingHex = '70696e672066726f6d2074686520636c69656e74';

{ TMtlsLiveServerRunner }

constructor TMtlsLiveServerRunner.Create(const AStream: TTlsStream;
  const ATransport, AClientTransport: TMemoryTransport;
  const AResolver: TCertificateVerdictResolver; AEcho: Boolean);
begin
  inherited Create(AStream, ATransport, AClientTransport);
  FResolver := AResolver;
  FEcho := AEcho;
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
    end;
    // closing even when not echoing lets a client wrongly accepted here read EOF, not block
    FStream.CloseNotify;
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
  // a server that ended has nothing more to send: release a client blocked on its read
  FTransport.CloseWrite;
end;

{ TTestServerSideLiveRevocation }

procedure TTestServerSideLiveRevocation.TearDown;
begin
  FFetcher := nil; // an interface reference; the checker held the only other one
  inherited TearDown;
end;

function TTestServerSideLiveRevocation.ServerConfig(APosture: TRevocationPosture;
  AForce12: Boolean): ITlsServerConfig;
var
  LServer: ITlsServerConfigBuilder;
begin
  LServer := TTlsPresets.Compatible(Crypto, Pkix).Server
    .WithCredential(TTlsCredential.Load(Crypto, Pkix,
      TTlsLibTestCertificates.Field('Certs/EcP256Chain.txt', 'leaf_cert'),
      TTlsLibTestCertificates.Field('Certs/EcP256Chain.txt', 'leaf_key')))
    .WithPeerAuth(TClientAuthMode.Required)
    // the private client CA (issues the client leaf)
    .WithClientVerification(TClientVerification.WebPki(
      TTlsLibTestCertificates.Field('Certs/LiveRevocation.txt', 'ca_cert'))
      .WithRevocation(APosture).Build)
    .WithLiveRevocationVerdict(0); // arm the park so the live resolver runs off the engine
  if AForce12 then
    LServer.WithSupportedVersions(TArray<UInt16>.Create(TlsWireVersionTls12));
  Result := LServer.Build;
end;

function TTestServerSideLiveRevocation.ClientConfig(AForce12: Boolean): ITlsClientConfig;
var
  LClient: ITlsClientConfigBuilder;
begin
  LClient := TTlsPresets.Compatible(Crypto, Pkix).Client
    .WithServerVerification(TServerVerification.WebPki(
      TTlsLibTestCertificates.Field('Certs/EcP256Chain.txt', 'root_cert')).Build)
    // the LiveRevocation leaf alone: no EKU, so client-auth capable, with OCSP/CRL vectors
    .WithCredential(TTlsCredential.Load(Crypto, Pkix,
      TTlsLibTestCertificates.Field('Certs/LiveRevocation.txt', 'leaf_cert'),
      TTlsLibTestCertificates.Field('Certs/LiveRevocation.txt', 'leaf_key')));
  if AForce12 then
    LClient.WithSupportedVersions(TArray<UInt16>.Create(TlsWireVersionTls12));
  Result := LClient.Build;
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
  AClient := TTlsStream.Create(AClientTransport as ITlsTransport,
    TTlsEngineFactory.CreateClientEngine(AClientConfig, 'localhost'), True, 'localhost');
  LServerStream := TTlsStream.Create(LServerTransport as ITlsTransport,
    TTlsEngineFactory.CreateServerEngine(AServerConfig), False, '');
  AServer := TMtlsLiveServerRunner.Create(LServerStream, LServerTransport, AClientTransport,
    AResolver, AEcho);
  AServer.Start;
end;

function TTestServerSideLiveRevocation.NewChecker(APosture: TRevocationPosture;
  AWithCandidates: Boolean): TLiveRevocationChecker;
var
  LOptions: TLiveRevocationOptions;
begin
  if AWithCandidates then
  begin
    LOptions.IssuerCandidates := TArray<TBytes>.Create(
      TTlsLibTestCertificates.Field('Certs/LiveRevocation.txt', 'ca_cert'));
    Result := TLiveRevocationChecker.Create(Pkix, TSystemClock.Create as ITlsClock,
      TSystemMonotonicClock.Create as ITlsMonotonicClock, FFetcher, APosture,
      TLiveRevocationMethod.OcspThenCrl, 0, LOptions);
  end
  else
    Result := TLiveRevocationChecker.Create(Pkix, TSystemClock.Create as ITlsClock,
      TSystemMonotonicClock.Create as ITlsMonotonicClock, FFetcher, APosture,
      TLiveRevocationMethod.OcspThenCrl, 0);
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
  FFetcher := TMockHttpFetcher.Create;
  FFetcher.SetPost(True,
    TTlsLibTestCertificates.Field('Certs/LiveRevocation.txt', 'ocsp_good'));
  LChecker := NewChecker(TRevocationPosture.Hard, True);
  try
    RunLoopback(ClientConfig(False), ServerConfig(TRevocationPosture.Hard, False),
      LChecker.ResolveVerdict, True, LClient, LServer, LTransport);
    try
      LClient.Handshake;
      CheckTrue(LClient.IsHandshakeComplete, 'the client completed the mTLS handshake');
      ExchangePingEcho(LClient);
      LClient.CloseNotify;
      LServer.Finish;
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
  FFetcher := TMockHttpFetcher.Create;
  FFetcher.SetPost(True,
    TTlsLibTestCertificates.Field('Certs/LiveRevocation.txt', 'ocsp_revoked'));
  LChecker := NewChecker(TRevocationPosture.Hard, True);
  try
    RunLoopback(ClientConfig(False), ServerConfig(TRevocationPosture.Hard, False),
      LChecker.ResolveVerdict, False, LClient, LServer, LTransport);
    try
      LAlert := ClientFatalAlert(LClient);
      CheckEquals(Int64(Ord(TTlsAlertDescription.CertificateRevoked)), Int64(Ord(LAlert)),
        'the client receives certificate_revoked for the revoked client certificate');
      LServer.Finish;
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
  FFetcher := TMockHttpFetcher.Create;
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
      LServer.Finish;
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
  FFetcher := TMockHttpFetcher.Create;
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
      LServer.Finish;
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
  FFetcher := TMockHttpFetcher.Create;
  FFetcher.SetPost(True,
    TTlsLibTestCertificates.Field('Certs/LiveRevocation.txt', 'ocsp_good'));
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
      LServer.Finish;
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
  FFetcher := TMockHttpFetcher.Create;
  FFetcher.SetPost(True,
    TTlsLibTestCertificates.Field('Certs/LiveRevocation.txt', 'ocsp_revoked'));
  LChecker := NewChecker(TRevocationPosture.Hard, True);
  try
    RunLoopback(ClientConfig(True), ServerConfig(TRevocationPosture.Hard, True),
      LChecker.ResolveVerdict, False, LClient, LServer, LTransport);
    try
      LAlert := ClientFatalAlert(LClient);
      CheckEquals(Int64(Ord(TTlsAlertDescription.CertificateRevoked)), Int64(Ord(LAlert)),
        'the 1.2 client receives certificate_revoked for the revoked client certificate');
      LServer.Finish;
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
  LSpy: TVerdictResolverSpy;
begin
  // the server park -> resolve -> resume wiring, independent of the live checker
  LSpy := Own<TVerdictResolverSpy>(TVerdictResolverSpy.Create);
  RunLoopback(ClientConfig(False), ServerConfig(TRevocationPosture.Hard, False),
    LSpy.Resolve, True, LClient, LServer, LTransport);
  try
    LClient.Handshake;
    CheckTrue(LClient.IsHandshakeComplete, 'an accepted server verdict completes the handshake');
    ExchangePingEcho(LClient);
    LClient.CloseNotify;
    LServer.Finish;
    CheckTrue(LServer.HandshakeOk, 'the server accepted the client via the stub resolver');
    CheckEquals('', LServer.Error, 'the server side ran without error');
    // the server park concerns the mTLS client's chain (WaitFor is the memory barrier)
    CheckEquals(Ord(TPeerRole.Client), Ord(LSpy.PeerRole),
      'a server park attributes the parked chain to the client role');
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
    LServer.Finish;
    CheckFalse(LServer.HandshakeOk, 'the server rejected the client via the stub resolver');
  finally
    LServer.Free;
    LClient.Free;
  end;
end;

procedure TTestServerSideLiveRevocation.TestLeafOnlyClientResolvesIssuerFromValidatedPathWithoutCandidates;
var
  LClient: TTlsStream;
  LServer: TMtlsLiveServerRunner;
  LTransport: TMemoryTransport;
  LChecker: TLiveRevocationChecker;
begin
  // the client presents a leaf-only chain and the checker is given NO issuer candidates, yet the
  // handshake park carries the pipeline-VALIDATED path (issuer at index 1), so the checker resolves
  // the issuer from there and authenticates a Good response. The live check fetches once and the
  // handshake completes - the issuer comes from PKIX, not from configured candidates.
  FFetcher := TMockHttpFetcher.Create;
  FFetcher.SetPost(True,
    TTlsLibTestCertificates.Field('Certs/LiveRevocation.txt', 'ocsp_good'));
  LChecker := NewChecker(TRevocationPosture.Hard, False);
  try
    RunLoopback(ClientConfig(False), ServerConfig(TRevocationPosture.Hard, False),
      LChecker.ResolveVerdict, True, LClient, LServer, LTransport);
    try
      LClient.Handshake;
      CheckTrue(LClient.IsHandshakeComplete,
        'the leaf-only client completed: the issuer came from the validated path');
      ExchangePingEcho(LClient);
      LClient.CloseNotify;
      LServer.Finish;
      CheckTrue(LServer.HandshakeOk, 'the server accepted the live-good leaf-only client');
      CheckEquals('', LServer.Error, 'the server side ran without error');
      CheckEquals(1, FFetcher.PostCount,
        'the responder was queried once - the validated path supplied the issuer');
    finally
      LServer.Free;
      LClient.Free;
    end;
  finally
    LChecker.Free;
  end;
end;

procedure TTestServerSideLiveRevocation.TestLeafOnlyClientBadResponseRejectsUnderHardWithoutCandidates;
var
  LClient: TTlsStream;
  LServer: TMtlsLiveServerRunner;
  LTransport: TMemoryTransport;
  LChecker: TLiveRevocationChecker;
  LAlert: TTlsAlertDescription;
begin
  // the mirror of the accept case: leaf-only client, no candidates, but the responder returns an
  // unusable answer. The validated path still lets the checker fetch (so the responder IS queried),
  // and an unauthenticated/indeterminate answer under Hard rejects with bad_certificate_status_response.
  FFetcher := TMockHttpFetcher.Create;
  FFetcher.SetPost(False, nil); // the responder was reached, but no usable OCSP came back
  LChecker := NewChecker(TRevocationPosture.Hard, False);
  try
    RunLoopback(ClientConfig(False), ServerConfig(TRevocationPosture.Hard, False),
      LChecker.ResolveVerdict, False, LClient, LServer, LTransport);
    try
      LAlert := ClientFatalAlert(LClient);
      CheckEquals(Int64(Ord(TTlsAlertDescription.BadCertificateStatusResponse)),
        Int64(Ord(LAlert)),
        'an indeterminate live outcome under Hard rejects');
      LServer.Finish;
      CheckFalse(LServer.HandshakeOk, 'the server rejected the indeterminate client');
      CheckEquals(1, FFetcher.PostCount,
        'the responder was still queried - the validated path supplied the issuer');
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
