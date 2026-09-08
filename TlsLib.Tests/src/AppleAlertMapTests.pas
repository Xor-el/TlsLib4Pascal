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
  TlpServerName,
{$ENDIF TLSLIB_MACOS}
  TlpTlsAlert,
  TlpAppleSystemTrust,
  TlsLibTestBase;

type
  TTestAppleAlertMap = class(TTlsLibAlgorithmTestCase)
  strict private
    procedure CheckMap(AStatus: Int32; AExpected: TTlsAlertDescription);
  published
    procedure TestOsStatusToAlertMapping;
{$IFDEF TLSLIB_MACOS}
    procedure TestDelegateRejectsUntrustedExpiredChain;
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
  LVerifier := TAppleDelegateVerifier.Create as IServerCertificateVerifier;
  LAlert := TTlsAlertDescription.InternalError;
  CheckFalse(LVerifier.VerifyServerCertificate(LChain, TServerName.DnsName('localhost'), nil, LAlert),
    'an untrusted/expired chain must be rejected by the OS delegate');
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
