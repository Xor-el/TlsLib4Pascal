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
  TlpTlsCredential,
  TlpExtensionVector,
  TlpHandshakeMessage,
  TlpHandshakeMessages,
  TlpClientSessionPolicy,
  MockCertificateVerifiers,
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
    // a session holding AChain, or authenticated by the PSK APskIdentity when that is set
    function MakeChainSession(const AChain: TArray<TBytes>;
      const APskIdentity: TBytes): IResumableSession;
    // asserts the Reverify offer check over a session of AChain is False and leaves the path empty
    procedure CheckOfferRefused(const APrimary,
      AResume: IServerCertificateVerifier; const AChain: TArray<TBytes>;
      const AName: string);
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
    procedure TestOfferNoVerifierIsRefused;
    procedure TestOfferEmptyChainIsRefused;
    procedure TestOfferRejectedByVerifierIsRefused;
    procedure TestOfferSuccessSetsValidatedPath;
    procedure TestOfferPrefersResumeVerifier;
    procedure TestOfferFallsBackToPrimaryVerifier;
    procedure TestOfferUnderReuseOriginalSkipsTheVerifier;
    procedure TestOfferOfPskSessionSkipsTheVerifier;
  end;

implementation

const
  // the fixed path an accepting verifier returns (a single one-byte "certificate")
  AcceptedPathByte = $5A;

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

function TTestClientSessionPolicy.MakeChainSession(const AChain: TArray<TBytes>;
  const APskIdentity: TBytes): IResumableSession;
begin
  Result := TTls13ResumableSession.Create(TCipherSuites13.Aes128GcmSha256,
    THashAlgorithm.SHA_256, TSecretBuffer.From(TBytes.Create(1, 2, 3, 4)), nil, '',
    TBytes.Create($AB), 100, 0, 0, 0, AChain, nil, APskIdentity, nil, 0, 0);
end;

procedure TTestClientSessionPolicy.CheckOfferRefused(const APrimary,
  AResume: IServerCertificateVerifier; const AChain: TArray<TBytes>;
  const AName: string);
var
  LPath: TArray<TBytes>;
begin
  LPath := TArray<TBytes>.Create(TBytes.Create(1));
  CheckFalse(TClientSessionPolicy.SessionTrustedForOffer(TResumeVerification.Reverify,
    MakeChainSession(AChain, nil), APrimary, AResume, Default(TServerName), LPath),
    AName + ': the session is not offered');
  CheckEquals(0, System.Length(LPath), AName + ': no validated path is reported');
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

procedure TTestClientSessionPolicy.TestOfferNoVerifierIsRefused;
begin
  // neither a primary nor a resumption verifier is configured: the session is not offered
  CheckOfferRefused(nil, nil, TArray<TBytes>.Create(TBytes.Create(1)), 'no verifier');
end;

procedure TTestClientSessionPolicy.TestOfferEmptyChainIsRefused;
begin
  // an empty stored chain cannot be checked, and an accepting verifier must not rescue it
  CheckOfferRefused(TFixedVerdictVerifier.CreateReporting(
    TArray<TBytes>.Create(TBytes.Create(AcceptedPathByte)), TVerificationOutcome.Trusted)
    as IServerCertificateVerifier, nil, nil, 'empty chain');
end;

procedure TTestClientSessionPolicy.TestOfferRejectedByVerifierIsRefused;
begin
  CheckOfferRefused(
    TFixedVerdictVerifier.CreateRejecting(TTlsAlertDescription.CertificateExpired)
    as IServerCertificateVerifier, nil, TArray<TBytes>.Create(TBytes.Create(1)),
    'verifier rejection');
end;

procedure TTestClientSessionPolicy.TestOfferSuccessSetsValidatedPath;
var
  LPath: TArray<TBytes>;
begin
  CheckTrue(TClientSessionPolicy.SessionTrustedForOffer(TResumeVerification.Reverify,
    MakeChainSession(TArray<TBytes>.Create(TBytes.Create(1)), nil),
    TFixedVerdictVerifier.CreateReporting(
    TArray<TBytes>.Create(TBytes.Create(AcceptedPathByte)), TVerificationOutcome.Trusted)
    as IServerCertificateVerifier, nil,
    Default(TServerName), LPath), 'a chain the verifier accepts is offered');
  CheckEquals(1, System.Length(LPath), 'the validated path is the verifier''s result');
  CheckTrue((System.Length(LPath[0]) = 1) and (LPath[0][0] = AcceptedPathByte),
    'the validated path carries the verifier''s certificate');
end;

procedure TTestClientSessionPolicy.TestOfferPrefersResumeVerifier;
var
  LPath: TArray<TBytes>;
begin
  // a rejecting primary with an accepting resumption verifier must succeed: the resumption-occasion
  // verifier is preferred
  CheckTrue(TClientSessionPolicy.SessionTrustedForOffer(TResumeVerification.Reverify,
    MakeChainSession(TArray<TBytes>.Create(TBytes.Create(1)), nil),
    TFixedVerdictVerifier.CreateRejecting(TTlsAlertDescription.BadCertificate)
    as IServerCertificateVerifier,
    TFixedVerdictVerifier.CreateReporting(
    TArray<TBytes>.Create(TBytes.Create(AcceptedPathByte)), TVerificationOutcome.Trusted)
    as IServerCertificateVerifier,
    Default(TServerName), LPath), 'the resumption verifier decides');
  CheckEquals(1, System.Length(LPath), 'the resumption verifier accepted and set the path');
end;

procedure TTestClientSessionPolicy.TestOfferFallsBackToPrimaryVerifier;
var
  LPath: TArray<TBytes>;
begin
  // no resumption verifier wired: fall back to the primary
  CheckTrue(TClientSessionPolicy.SessionTrustedForOffer(TResumeVerification.Reverify,
    MakeChainSession(TArray<TBytes>.Create(TBytes.Create(1)), nil),
    TFixedVerdictVerifier.CreateReporting(
    TArray<TBytes>.Create(TBytes.Create(AcceptedPathByte)), TVerificationOutcome.Trusted)
    as IServerCertificateVerifier, nil,
    Default(TServerName), LPath), 'the primary verifier decides');
  CheckEquals(1, System.Length(LPath), 'the primary verifier accepted and set the path');
end;

procedure TTestClientSessionPolicy.TestOfferUnderReuseOriginalSkipsTheVerifier;
var
  LRejecting: TFixedVerdictVerifier;
  LVerifier: IServerCertificateVerifier;
  LPath: TArray<TBytes>;
begin
  LRejecting := TFixedVerdictVerifier.CreateRejecting(TTlsAlertDescription.BadCertificate);
  LVerifier := LRejecting;
  CheckTrue(TClientSessionPolicy.SessionTrustedForOffer(TResumeVerification.ReuseOriginal,
    MakeChainSession(TArray<TBytes>.Create(TBytes.Create(1)), nil), LVerifier, nil,
    Default(TServerName), LPath), 'the original authentication is reused');
  CheckEquals(0, LRejecting.Calls, 'no verification ran');
  CheckEquals(0, System.Length(LPath), 'no path was validated');
end;

procedure TTestClientSessionPolicy.TestOfferOfPskSessionSkipsTheVerifier;
var
  LRejecting: TFixedVerdictVerifier;
  LVerifier: IServerCertificateVerifier;
  LPath: TArray<TBytes>;
begin
  // a PSK-authenticated session has no chain to judge
  LRejecting := TFixedVerdictVerifier.CreateRejecting(TTlsAlertDescription.BadCertificate);
  LVerifier := LRejecting;
  CheckTrue(TClientSessionPolicy.SessionTrustedForOffer(TResumeVerification.Reverify,
    MakeChainSession(nil, TBytes.Create(7)), LVerifier, nil, Default(TServerName), LPath),
    'a PSK session is offered under Reverify');
  CheckEquals(0, LRejecting.Calls, 'no verification ran');
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestClientSessionPolicy);
{$ELSE}
  RegisterTest(TTestClientSessionPolicy.Suite);
{$ENDIF FPC}

end.
