{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

/// <summary>Covers the Apple delegate's errSec->alert decode: a pure mapping test
/// over TAppleAlertMap.OsStatusToAlert, plus a best-effort macOS-only leg that
/// checks the live delegate rejects an untrusted/expired chain. The whole unit is
/// guarded to Apple targets.</summary>
unit AppleAlertMapTests;

{$I ..\..\TlsLib\src\Include\TlsLib.inc}

interface

{$IF DEFINED(TLSLIB_MACOS) OR DEFINED(TLSLIB_IOS)}

uses
  SysUtils,
  Classes,
{$IFDEF FPC}
  fpcunit,
  testregistry,
{$ELSE}
  TestFramework,
{$ENDIF FPC}
{$IFDEF TLSLIB_MACOS}
  TlpICertificateTrust,
  TlpTrustTypes,
  TlpServerName,
  TlpTrustPolicy,
  TlpCertificateLimits,
  TlpCertificateStrengthPolicy,
  TlpIPlatformChainEngine,
  TlpOSDelegateVerifier,
  TlpIClock,
  TlpITrustAnchorStore,
  TlpTrustAnchorStore,
  TlpNegotiationTypes,
  MockClock,
  TlsLibTestCertificates,
{$ENDIF TLSLIB_MACOS}
  TlpTlsAlert,
  TlpAppleSystemTrust,
  TlpSystemTrustBase,
  TlsLibTestBase;

type
  TTestAppleAlertMap = class(TTlsLibAlgorithmTestCase)
  strict private
    procedure CheckMap(AStatus: Int32; AExpected: TTlsAlertDescription);
  published
    procedure TestOsStatusToAlertMapping;
{$IFDEF TLSLIB_MACOS}
    procedure TestDelegateRejectsUntrustedExpiredChain;
    procedure TestAnchorNameConstraintsAreEnforcedByTheServerDelegate;
{$ENDIF TLSLIB_MACOS}
  end;

{$IFEND}

implementation

{$IF DEFINED(TLSLIB_MACOS) OR DEFINED(TLSLIB_IOS)}

{ TTestAppleAlertMap }

procedure TTestAppleAlertMap.CheckMap(AStatus: Int32;
  AExpected: TTlsAlertDescription);
begin
  CheckEquals(Ord(AExpected), Ord(TAppleAlertMap.OsStatusToAlert(AStatus)),
    Format('OsStatusToAlert(%d)', [AStatus]));
end;

procedure TTestAppleAlertMap.TestOsStatusToAlertMapping;
begin
  CheckMap(-67818, TTlsAlertDescription.CertificateExpired);     // errSecCertificateExpired
  CheckMap(-67819, TTlsAlertDescription.CertificateExpired);     // errSecCertificateNotValidYet
  CheckMap(-67820, TTlsAlertDescription.CertificateRevoked);     // errSecCertificateRevoked
  CheckMap(-67609, TTlsAlertDescription.UnsupportedCertificate); // errSecInvalidExtendedKeyUsage
  CheckMap(-67602, TTlsAlertDescription.BadCertificate);         // errSecHostNameMismatch
  CheckMap(-67603, TTlsAlertDescription.CertificateUnknown);     // errSecUnknownCriticalExtensionFlag
  CheckMap(-67689, TTlsAlertDescription.CertificateUnknown);     // errSecInvalidName
  CheckMap(-67843, TTlsAlertDescription.UnknownCa);              // errSecNotTrusted
  CheckMap(-67654, TTlsAlertDescription.UnknownCa);              // errSecTrustSettingDeny
  CheckMap(-25318, TTlsAlertDescription.UnknownCa);              // errSecCreateChainFailed
  CheckMap(0, TTlsAlertDescription.UnknownCa);                   // out of table (success)
  CheckMap(12345, TTlsAlertDescription.UnknownCa);               // arbitrary out of table
end;

{$IFDEF TLSLIB_MACOS}
procedure TTestAppleAlertMap.TestDelegateRejectsUntrustedExpiredChain;
var
  LVectors: TStringList;
  LChain: TArray<TBytes>;
  LVerifier: IServerCertificateVerifier;
  LAlert: TTlsAlertDescription;
  LVerified: TVerifiedChain;
  LPolicy: TOSDelegatePolicy;
begin
  // Best-effort: our test root is not in the macOS system store, so SecTrust rejects
  // the chain as untrusted (unknown_ca). We assert only that it IS rejected - a granular
  // non-unknown_ca alert would need a system-trusted-but-invalid cert, which cannot be
  // synthesized offline. The pure mapping test above covers the errSec->alert decode.
  LVectors := LoadVectorFields('Certs/EcP256Chain.txt');
  try
    SetLength(LChain, 2);
    LChain[0] := DecodeHex(LVectors.Values['expired_cert']);
    LChain[1] := DecodeHex(LVectors.Values['root_cert']);
  finally
    LVectors.Free;
  end;
  // the untrusted root makes SecTrust reject before the policy runs; a real provider + default
  // policy keep the construction valid regardless
  LPolicy := Default(TOSDelegatePolicy);
  LPolicy.ChainLimits := TCertificateChainLimits.Defaults;
  LPolicy.Pkix := Pkix;
  LPolicy.Clock := nil;
  LPolicy.Posture := TRevocationPosture.Soft;
  LPolicy.Fetch := TSystemTrustFetch.CacheOnly;
  LPolicy.Deferral := TVerdictDeferral.None;
  LPolicy.StrengthPolicy := TCertificateStrengthPolicy.Defaults;
  LPolicy.AdvertisedSchemes := nil;
  LPolicy.Anchors := nil;
  LPolicy.DeadlineMs := 0;
  LVerifier := TOSDelegateServerVerifier.Create(
    TAppleChainEngine.Create as IPlatformChainEngine, LPolicy) as IServerCertificateVerifier;
  LAlert := TTlsAlertDescription.InternalError;
  CheckFalse(LVerifier.VerifyServerCertificate(LChain, TServerName.DnsName('localhost'), nil,
    LVerified, LAlert),
    'an untrusted/expired chain must be rejected by the OS delegate');
end;

procedure TTestAppleAlertMap.TestAnchorNameConstraintsAreEnforcedByTheServerDelegate;
var
  LRoot: TBytes;
  LPolicy: TOSDelegatePolicy;
  LVerifier: IServerCertificateVerifier;
  LAlert: TTlsAlertDescription;
  LVerified: TVerifiedChain;
begin
  LRoot := TTlsLibTestCertificates.Field('Certs/NameConstrainedChain.txt', 'root_cert');
  LPolicy := Default(TOSDelegatePolicy);
  LPolicy.ChainLimits := TCertificateChainLimits.Defaults;
  LPolicy.Pkix := Pkix;
  // inside the 790-day window of the Apple leaves
  LPolicy.Clock := TMockClock.Create(1609459200000) as ITlsClock;
  LPolicy.Posture := TRevocationPosture.Off;
  LPolicy.Fetch := TSystemTrustFetch.CacheOnly;
  LPolicy.Deferral := TVerdictDeferral.None;
  LPolicy.StrengthPolicy := TCertificateStrengthPolicy.Defaults;
  LPolicy.AdvertisedSchemes := TArray<UInt16>.Create(TSignatureSchemes.EcdsaSecp256r1Sha256);
  LPolicy.Anchors := TArray<TBytes>.Create(LRoot);
  LPolicy.AnchorStore := TTrustAnchorStore.Create(LPolicy.Anchors) as ITrustAnchorStore;
  LPolicy.CheckHostName := False;
  LPolicy.DeadlineMs := 2000;
  LVerifier := TOSDelegateServerVerifier.Create(
    TAppleChainEngine.Create as IPlatformChainEngine, LPolicy) as IServerCertificateVerifier;
  CheckTrue(LVerifier.VerifyServerCertificate(TArray<TBytes>.Create(
    TTlsLibTestCertificates.Field('Certs/NameConstrainedChain.txt', 'apple_in_scope_leaf_cert'),
    LRoot), TServerName.DnsName('mac.corp.example'), nil, LVerified, LAlert),
    'a leaf inside the anchor name constraints is accepted');
  // the status trustd reports for a violation is unverifiable offline, so only the refusal is pinned
  CheckFalse(LVerifier.VerifyServerCertificate(TArray<TBytes>.Create(
    TTlsLibTestCertificates.Field('Certs/NameConstrainedChain.txt', 'apple_out_of_scope_leaf_cert'),
    LRoot), TServerName.DnsName('bank.example'), nil, LVerified, LAlert),
    'a leaf outside the anchor name constraints is refused');
  CheckTrue(LAlert in [TTlsAlertDescription.CertificateUnknown, TTlsAlertDescription.UnknownCa],
    'alert ' + IntToStr(Ord(LAlert)));
end;
{$ENDIF TLSLIB_MACOS}

initialization

{$IFDEF FPC}
  RegisterTest(TTestAppleAlertMap);
{$ELSE}
  RegisterTest(TTestAppleAlertMap.Suite);
{$ENDIF FPC}

{$IFEND}

end.
