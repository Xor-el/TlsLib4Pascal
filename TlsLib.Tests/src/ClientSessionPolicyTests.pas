{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit ClientSessionPolicyTests;

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
  TlpCryptoDomainTypes,
  TlpNegotiationTypes,
  TlpISecretBuffer,
  TlpSecretBuffer,
  TlpISession,
  TlpSession,
  TlpServerName,
  TlpTrustTypes,
  TlpICertificateTrust,
  TlpTlsAlert,
  TlpTlsLibExceptions,
  TlpExtensionVector,
  TlpHandshakeMessage,
  TlpHandshakeMessages,
  TlpClientSessionPolicy,
  TlsLibTestBase;

type
  TTestClientSessionPolicy = class(TTlsLibAlgorithmTestCase)
  private
    // a 1.3 session carrying the given lifetime hint and wall-clock issue time; the offerability
    // rules read only those two fields, so the rest is filler
    function MakeSession(ALifetime: UInt32;
      AIssuedAtMillis: UInt64): IResumableSession;
    // as MakeSession, authenticated at its own time apart from the issue time
    function MakeAuthenticatedSession(ALifetime: UInt32;
      AIssuedAtMillis, AAuthenticatedAtMillis: UInt64): IResumableSession;
    function MakeAuthenticatedTls12Session(ALifetime: UInt32;
      AIssuedAtMillis, AAuthenticatedAtMillis: UInt64): IResumableSession;
    // a framed ClientHello (4-byte handshake header + body) whose extensions field carries the
    // given types in order, each with a single filler byte
    function MakeFramedHello(const ATypes: array of UInt16): TBytes;
    // asserts ReverifyResumedServer over the given inputs raised a fatal alert of the expected
    // description
    procedure CheckReverifyRaises(const APrimary,
      AResume: IServerCertificateVerifier; const AChain: TArray<TBytes>;
      AExpected: TTlsAlertDescription; const AName: string);
  published
    procedure TestClampBelowCapIsUnchanged;
    procedure TestClampAtCapIsUnchanged;
    procedure TestClampAboveCapIsClamped;
    procedure TestZeroLifetimeOfferabilityDivergence;
    procedure TestOfferableWithinCappedLifetime;
    procedure TestNotOfferablePastLifetime;
    procedure TestOfferabilityHonorsSevenDayCap;
    procedure TestAuthenticationLapsesPastSevenDays;
    procedure TestAuthenticationClockBehindIsNotLapsed;
    procedure TestRenewedLifetimeIsCutToTheRemainingChain;
    procedure TestRenewedLifetimeKeepsAShorterConfiguredValue;
    procedure TestRenewedLifetimeRoundsUpAndNeverZeroWhileLive;
    procedure TestRenewedLifetimeIsZeroOnceLapsed;
    procedure TestTls13NotOfferableOnceAuthenticationLapsed;
    procedure TestTls12NotOfferableOnceAuthenticationLapsed;
    procedure TestOfferableAtTheAuthenticationEdge;
    procedure TestCacheIdentityPrefersIdentityOverName;
    procedure TestCacheIdentityFallsBackToServerName;
    procedure TestCacheIdentityFoldsScopeDeterministically;
    procedure TestOfferedExtensionTypesFromClientHello;
    procedure TestReverifyNoVerifierRaisesInternalError;
    procedure TestReverifyEmptyChainRaisesBadCertificate;
    procedure TestReverifyFailurePropagatesVerifierAlert;
    procedure TestReverifySuccessSetsValidatedPath;
    procedure TestReverifyPrefersResumeVerifier;
    procedure TestReverifyFallsBackToPrimaryVerifier;
  end;

implementation

type
  // accepts every chain, returning a fixed one-element path so a caller can prove the out path
  // was taken from the verifier's result
  TAcceptingServerVerifier = class(TInterfacedObject, IServerCertificateVerifier)
  public
    function VerifyServerCertificate(const AChain: TArray<TBytes>;
      const AServerName: TServerName; const AOcspStaple: TBytes;
      out AVerified: TVerifiedChain;
      out AAlert: TTlsAlertDescription): Boolean;
  end;

  // rejects every chain with a caller-chosen alert so a test can prove the alert is propagated
  TRejectingServerVerifier = class(TInterfacedObject, IServerCertificateVerifier)
  private
    FAlert: TTlsAlertDescription;
  public
    constructor Create(AAlert: TTlsAlertDescription);
    function VerifyServerCertificate(const AChain: TArray<TBytes>;
      const AServerName: TServerName; const AOcspStaple: TBytes;
      out AVerified: TVerifiedChain;
      out AAlert: TTlsAlertDescription): Boolean;
  end;

const
  // the fixed path an accepting verifier returns (a single one-byte "certificate")
  AcceptedPathByte = $5A;

function TAcceptingServerVerifier.VerifyServerCertificate(
  const AChain: TArray<TBytes>; const AServerName: TServerName;
  const AOcspStaple: TBytes; out AVerified: TVerifiedChain;
  out AAlert: TTlsAlertDescription): Boolean;
begin
  AVerified := Default(TVerifiedChain);
  AVerified.Path := TArray<TBytes>.Create(TBytes.Create(AcceptedPathByte));
  AAlert := TTlsAlertDescription.BadCertificate;
  Result := True;
end;

constructor TRejectingServerVerifier.Create(AAlert: TTlsAlertDescription);
begin
  inherited Create;
  FAlert := AAlert;
end;

function TRejectingServerVerifier.VerifyServerCertificate(
  const AChain: TArray<TBytes>; const AServerName: TServerName;
  const AOcspStaple: TBytes; out AVerified: TVerifiedChain;
  out AAlert: TTlsAlertDescription): Boolean;
begin
  AVerified := Default(TVerifiedChain);
  AAlert := FAlert;
  Result := False;
end;

{ TTestClientSessionPolicy }

function TTestClientSessionPolicy.MakeSession(ALifetime: UInt32;
  AIssuedAtMillis: UInt64): IResumableSession;
var
  LSecret: ISecretBuffer;
begin
  LSecret := TSecretBuffer.From(TBytes.Create(1, 2, 3, 4));
  Result := TTls13ResumableSession.Create(TCipherSuites13.Aes128GcmSha256,
    THashAlgorithm.SHA_256, LSecret, nil, '',
    TBytes.Create($AB), ALifetime, 0, AIssuedAtMillis, 0, nil, nil);
end;

function TTestClientSessionPolicy.MakeAuthenticatedSession(ALifetime: UInt32;
  AIssuedAtMillis, AAuthenticatedAtMillis: UInt64): IResumableSession;
begin
  Result := TTls13ResumableSession.Create(TCipherSuites13.Aes128GcmSha256,
    THashAlgorithm.SHA_256, TSecretBuffer.From(TBytes.Create(1, 2, 3, 4)), nil, '',
    TBytes.Create($AB), ALifetime, 0, AIssuedAtMillis, 0, nil, nil, nil, nil, 0,
    AAuthenticatedAtMillis);
end;

function TTestClientSessionPolicy.MakeAuthenticatedTls12Session(ALifetime: UInt32;
  AIssuedAtMillis, AAuthenticatedAtMillis: UInt64): IResumableSession;
begin
  Result := TTls12ResumableSession.Create(TCipherSuites12.EcdheEcdsaAes128GcmSha256,
    THashAlgorithm.SHA_256, TSecretBuffer.From(TBytes.Create(1, 2, 3, 4)), nil,
    TBytes.Create($AB), True, nil, '', ALifetime, AIssuedAtMillis, nil, nil, nil, nil, 0, 0,
    AAuthenticatedAtMillis);
end;

function TTestClientSessionPolicy.MakeFramedHello(
  const ATypes: array of UInt16): TBytes;
var
  LHello: TTlsClientHello;
  LVector: TExtensionVector;
  LI: Int32;
begin
  LVector := TExtensionVector.Empty;
  // indexed loop: FPC 3.2.2 misiterates for..in over an inline open array
  for LI := 0 to System.Length(ATypes) - 1 do
    LVector.Append(TExtensionEntry.Create(ATypes[LI], TBytes.Create($FF)));
  LHello := Default(TTlsClientHello);
  LHello.Random := TBytes.Create(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13,
    14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31);
  LHello.CipherSuites := TArray<UInt16>.Create(TCipherSuites13.Aes128GcmSha256);
  LHello.Extensions := LVector.Encode;
  Result := THandshakeFraming.Frame(TTlsHandshakeType.ClientHello,
    THandshakeMessages.EncodeClientHello(LHello));
end;

procedure TTestClientSessionPolicy.CheckReverifyRaises(const APrimary,
  AResume: IServerCertificateVerifier; const AChain: TArray<TBytes>;
  AExpected: TTlsAlertDescription; const AName: string);
var
  LRaised: Boolean;
  LPath: TArray<TBytes>;
begin
  LRaised := False;
  try
    TClientSessionPolicy.ReverifyResumedServer(APrimary, AResume, AChain,
      Default(TServerName), LPath);
  except
    on E: EFatalAlertTlsLibException do
    begin
      LRaised := True;
      CheckTrue(E.AlertDescription = AExpected, AName + ': alert description');
    end;
  end;
  CheckTrue(LRaised, AName + ': a fatal alert is raised');
end;

procedure TTestClientSessionPolicy.TestClampBelowCapIsUnchanged;
begin
  CheckTrue(TClientSessionPolicy.ClampTicketLifetime(0) = 0, 'zero is unchanged');
  CheckTrue(TClientSessionPolicy.ClampTicketLifetime(100) = 100,
    'a lifetime below the cap is unchanged');
end;

procedure TTestClientSessionPolicy.TestClampAtCapIsUnchanged;
begin
  // RFC 9846 4.7.1: 604800 seconds (7 days) is the ceiling, and the boundary itself is kept
  CheckTrue(TClientSessionPolicy.ClampTicketLifetime(604800) = 604800,
    'the boundary lifetime is kept');
end;

procedure TTestClientSessionPolicy.TestClampAboveCapIsClamped;
begin
  CheckTrue(TClientSessionPolicy.ClampTicketLifetime(604801) = 604800,
    'one second past the cap is clamped');
  CheckTrue(TClientSessionPolicy.ClampTicketLifetime(High(UInt32)) = 604800,
    'a huge out-of-band lifetime is clamped to the cap');
end;

procedure TTestClientSessionPolicy.TestZeroLifetimeOfferabilityDivergence;
var
  LSession: IResumableSession;
begin
  // a zero-lifetime ticket is discarded by a 1.3 client (RFC 9846 4.7.1); a 1.2 hint of 0 is
  // unspecified (RFC 5077 3.3), so it is offered only up to the same seven-day ceiling
  LSession := MakeSession(0, 0);
  CheckFalse(TClientSessionPolicy.IsOfferableTls13(LSession, 0),
    '1.3 discards a zero-lifetime ticket');
  CheckTrue(TClientSessionPolicy.IsOfferableTls12(LSession, 0),
    '1.2 offers a zero-hint ticket inside the ceiling');
  CheckTrue(TClientSessionPolicy.IsOfferableTls12(LSession, UInt64(604800) * 1000),
    '1.2 offers a zero-hint ticket at the ceiling edge');
  CheckFalse(TClientSessionPolicy.IsOfferableTls12(LSession, UInt64(604800) * 1000 + 1),
    '1.2 drops a zero-hint ticket past the ceiling');
end;

procedure TTestClientSessionPolicy.TestOfferableWithinCappedLifetime;
var
  LSession: IResumableSession;
begin
  // lifetime 100 s, issued at t=0; both versions offer it up to and including the 100_000 ms edge
  LSession := MakeSession(100, 0);
  CheckTrue(TClientSessionPolicy.IsOfferableTls13(LSession, 50000),
    '1.3 offers a ticket inside its lifetime');
  CheckTrue(TClientSessionPolicy.IsOfferableTls12(LSession, 50000),
    '1.2 offers a ticket inside its lifetime');
  CheckTrue(TClientSessionPolicy.IsOfferableTls13(LSession, 100000),
    '1.3 offers a ticket at the exact lifetime edge');
  CheckTrue(TClientSessionPolicy.IsOfferableTls12(LSession, 100000),
    '1.2 offers a ticket at the exact lifetime edge');
end;

procedure TTestClientSessionPolicy.TestNotOfferablePastLifetime;
var
  LSession: IResumableSession;
begin
  // one millisecond past the 100_000 ms window: neither version offers it
  LSession := MakeSession(100, 0);
  CheckFalse(TClientSessionPolicy.IsOfferableTls13(LSession, 100001),
    '1.3 drops a ticket past its lifetime');
  CheckFalse(TClientSessionPolicy.IsOfferableTls12(LSession, 100001),
    '1.2 drops a ticket past its (non-zero) lifetime');
end;

procedure TTestClientSessionPolicy.TestOfferabilityHonorsSevenDayCap;
var
  LSession: IResumableSession;
  LCapMs: UInt64;
begin
  // an out-of-band lifetime beyond the seven-day ceiling is bounded to the cap when judging age,
  // so the ticket is not offerable past cap*1000 ms even though its stored hint is far larger
  LSession := MakeSession(High(UInt32), 0);
  LCapMs := UInt64(604800) * 1000;
  CheckTrue(TClientSessionPolicy.IsOfferableTls13(LSession, LCapMs),
    'offerable at the seven-day edge');
  CheckFalse(TClientSessionPolicy.IsOfferableTls13(LSession, LCapMs + 1),
    'not offerable one millisecond past the seven-day cap');
end;

procedure TTestClientSessionPolicy.TestAuthenticationLapsesPastSevenDays;
const
  CapMs = UInt64(604800) * 1000;
begin
  CheckFalse(TClientSessionPolicy.AuthenticationLapsed(1000, 1000 + CapMs),
    'the seventh day itself still counts');
  CheckTrue(TClientSessionPolicy.AuthenticationLapsed(1000, 1000 + CapMs + 1),
    'one millisecond past seven days has lapsed');
end;

procedure TTestClientSessionPolicy.TestAuthenticationClockBehindIsNotLapsed;
begin
  CheckFalse(TClientSessionPolicy.AuthenticationLapsed(5000, 1000),
    'a clock behind the authentication time is not lapsed');
end;

procedure TTestClientSessionPolicy.TestRenewedLifetimeIsCutToTheRemainingChain;
const
  DayMs = UInt64(86400) * 1000;
begin
  // six days into the chain, a seven-day configured lifetime shrinks to the one day left
  CheckEquals(86400, Integer(TClientSessionPolicy.RenewedTicketLifetime(604800, 0, 6 * DayMs)),
    'the lifetime is cut to what remains of the seven days');
  CheckEquals(604800, Integer(TClientSessionPolicy.RenewedTicketLifetime(High(UInt32), 0, 0)),
    'a fresh chain keeps the seven-day ceiling');
end;

procedure TTestClientSessionPolicy.TestRenewedLifetimeKeepsAShorterConfiguredValue;
const
  DayMs = UInt64(86400) * 1000;
begin
  CheckEquals(7200, Integer(TClientSessionPolicy.RenewedTicketLifetime(7200, 0, 6 * DayMs)),
    'a configured lifetime below the remainder is kept');
end;

procedure TTestClientSessionPolicy.TestRenewedLifetimeRoundsUpAndNeverZeroWhileLive;
const
  CapMs = UInt64(604800) * 1000;
begin
  CheckEquals(1, Integer(TClientSessionPolicy.RenewedTicketLifetime(604800, 0, CapMs - 1)),
    'one millisecond left advertises one second');
  CheckEquals(2, Integer(TClientSessionPolicy.RenewedTicketLifetime(604800, 0, CapMs - 1001)),
    'a partial second rounds up');
end;

procedure TTestClientSessionPolicy.TestRenewedLifetimeIsZeroOnceLapsed;
const
  CapMs = UInt64(604800) * 1000;
begin
  CheckEquals(0, Integer(TClientSessionPolicy.RenewedTicketLifetime(604800, 0, CapMs + 1)),
    'a lapsed chain advertises no lifetime');
  CheckEquals(604800, Integer(TClientSessionPolicy.RenewedTicketLifetime(604800, 5000, 1000)),
    'a clock behind the authentication time keeps the full lifetime');
end;

procedure TTestClientSessionPolicy.TestTls13NotOfferableOnceAuthenticationLapsed;
const
  CapMs = UInt64(604800) * 1000;
begin
  // freshly issued, long lifetime, but authenticated more than seven days ago
  CheckFalse(TClientSessionPolicy.IsOfferableTls13(
    MakeAuthenticatedSession(604800, CapMs, 0), CapMs + 1), '1.3 does not offer a lapsed chain');
end;

procedure TTestClientSessionPolicy.TestTls12NotOfferableOnceAuthenticationLapsed;
const
  CapMs = UInt64(604800) * 1000;
begin
  CheckFalse(TClientSessionPolicy.IsOfferableTls12(
    MakeAuthenticatedTls12Session(604800, CapMs, 0), CapMs + 1),
    '1.2 does not offer a lapsed chain');
end;

procedure TTestClientSessionPolicy.TestOfferableAtTheAuthenticationEdge;
const
  CapMs = UInt64(604800) * 1000;
begin
  CheckTrue(TClientSessionPolicy.IsOfferableTls13(
    MakeAuthenticatedSession(604800, CapMs, 0), CapMs), '1.3 offers at the edge');
  CheckTrue(TClientSessionPolicy.IsOfferableTls12(
    MakeAuthenticatedTls12Session(604800, CapMs, 0), CapMs), '1.2 offers at the edge');
end;

procedure TTestClientSessionPolicy.TestCacheIdentityPrefersIdentityOverName;
begin
  CheckEquals('id.example', TClientSessionPolicy.CacheIdentity('id.example',
    'sni.example', nil), 'an explicit identity is preferred over the SNI host');
end;

procedure TTestClientSessionPolicy.TestCacheIdentityFallsBackToServerName;
begin
  CheckEquals('sni.example', TClientSessionPolicy.CacheIdentity('',
    'sni.example', nil), 'the SNI host is used when no identity is set');
end;

procedure TTestClientSessionPolicy.TestCacheIdentityFoldsScopeDeterministically;
var
  LScopeA, LScopeB: TBytes;
begin
  LScopeA := TBytes.Create(1, 2, 3);
  LScopeB := TBytes.Create(4, 5, 6);
  // determinism: the same inputs always produce the same key
  CheckEquals(TClientSessionPolicy.CacheIdentity('id', 'sni', LScopeA),
    TClientSessionPolicy.CacheIdentity('id', 'sni', LScopeA),
    'the key is deterministic for identical inputs');
  // a different scope yields a different key so two configurations do not share cached sessions
  CheckFalse(TClientSessionPolicy.CacheIdentity('id', 'sni', LScopeA) =
    TClientSessionPolicy.CacheIdentity('id', 'sni', LScopeB),
    'a different scope yields a different key');
  // an empty scope adds no separator, so the bare identity stands alone
  CheckEquals('id', TClientSessionPolicy.CacheIdentity('id', 'sni', nil),
    'an empty scope leaves the identity unadorned');
  // a folded key begins with the identity and is longer than it
  CheckTrue(System.Length(TClientSessionPolicy.CacheIdentity('id', 'sni',
    LScopeA)) > System.Length('id'), 'a non-empty scope lengthens the key');
end;

procedure TTestClientSessionPolicy.TestOfferedExtensionTypesFromClientHello;
var
  LOffered: TArray<UInt16>;
begin
  // a hello offering two extensions (server_name 0, supported_versions 43): the census returns
  // both types in wire order
  LOffered := TClientSessionPolicy.OfferedExtensionTypes(MakeFramedHello([0, 43]));
  CheckEquals(2, System.Length(LOffered), 'two extension types are reported');
  CheckTrue((LOffered[0] = 0) and (LOffered[1] = 43),
    'the types are returned in wire order');
end;

procedure TTestClientSessionPolicy.TestReverifyNoVerifierRaisesInternalError;
begin
  // neither a primary nor a resumption verifier is configured: fail closed with internal_error
  CheckReverifyRaises(nil, nil, TArray<TBytes>.Create(TBytes.Create(1)),
    TTlsAlertDescription.InternalError, 'no verifier');
end;

procedure TTestClientSessionPolicy.TestReverifyEmptyChainRaisesBadCertificate;
begin
  // an empty stored chain cannot be re-verified: fail closed with bad_certificate before the
  // verifier is ever consulted (an accepting verifier still must not rescue it)
  CheckReverifyRaises(TAcceptingServerVerifier.Create as IServerCertificateVerifier,
    nil, nil, TTlsAlertDescription.BadCertificate, 'empty chain');
end;

procedure TTestClientSessionPolicy.TestReverifyFailurePropagatesVerifierAlert;
begin
  // the verifier's own alert (here certificate_expired) is the one that surfaces
  CheckReverifyRaises(
    TRejectingServerVerifier.Create(TTlsAlertDescription.CertificateExpired)
    as IServerCertificateVerifier, nil, TArray<TBytes>.Create(TBytes.Create(1)),
    TTlsAlertDescription.CertificateExpired, 'verifier rejection');
end;

procedure TTestClientSessionPolicy.TestReverifySuccessSetsValidatedPath;
var
  LPath: TArray<TBytes>;
  LVerifier: IServerCertificateVerifier;
begin
  LVerifier := TAcceptingServerVerifier.Create;
  LPath := nil;
  TClientSessionPolicy.ReverifyResumedServer(LVerifier, nil,
    TArray<TBytes>.Create(TBytes.Create(1)), Default(TServerName), LPath);
  CheckEquals(1, System.Length(LPath), 'the validated path is the verifier''s result');
  CheckTrue((System.Length(LPath[0]) = 1) and (LPath[0][0] = AcceptedPathByte),
    'the validated path carries the verifier''s certificate');
end;

procedure TTestClientSessionPolicy.TestReverifyPrefersResumeVerifier;
var
  LPath: TArray<TBytes>;
  LPrimary, LResume: IServerCertificateVerifier;
begin
  // a rejecting primary with an accepting resumption verifier must succeed: the resumption-occasion
  // verifier is preferred
  LPrimary := TRejectingServerVerifier.Create(TTlsAlertDescription.BadCertificate);
  LResume := TAcceptingServerVerifier.Create;
  LPath := nil;
  TClientSessionPolicy.ReverifyResumedServer(LPrimary, LResume,
    TArray<TBytes>.Create(TBytes.Create(1)), Default(TServerName), LPath);
  CheckEquals(1, System.Length(LPath),
    'the resumption verifier accepted and set the path');
end;

procedure TTestClientSessionPolicy.TestReverifyFallsBackToPrimaryVerifier;
var
  LPath: TArray<TBytes>;
  LPrimary: IServerCertificateVerifier;
begin
  // no resumption verifier wired: fall back to the primary
  LPrimary := TAcceptingServerVerifier.Create;
  LPath := nil;
  TClientSessionPolicy.ReverifyResumedServer(LPrimary, nil,
    TArray<TBytes>.Create(TBytes.Create(1)), Default(TServerName), LPath);
  CheckEquals(1, System.Length(LPath), 'the primary verifier accepted and set the path');
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestClientSessionPolicy);
{$ELSE}
  RegisterTest(TTestClientSessionPolicy.Suite);
{$ENDIF FPC}

end.
