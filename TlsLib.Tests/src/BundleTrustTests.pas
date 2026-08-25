{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

/// <summary>Round-trip tests for the optional TlsLib.Trust.Bundle package: a
/// caller-supplied CA bundle becomes an ITrustAnchorStore via TBundleTrust.FromPem
/// / FromPemFile (both delegate to the provider's LoadCertificateChain, which
/// accepts DER or PEM, then wrap the result in a TTrustAnchorStore).</summary>
unit BundleTrustTests;

{$IFDEF FPC}
{$MODE DELPHI}
{$H+}
{$ENDIF FPC}

interface

uses
  SysUtils,
  Classes,
{$IFDEF FPC}
  fpcunit,
  testregistry,
{$ELSE}
  TestFramework,
{$ENDIF FPC}
  TlpICryptoProvider,
  TlpDefaultCryptoProvider,
  TlpICertificateTrust,
  TlpBundleTrust,
  TlsLibTestBase;

type
  TTestBundleTrust = class(TTlsLibAlgorithmTestCase)
  strict private
    FProvider: ICryptoProvider;
    FRootDer: TBytes;
  protected
    procedure SetUp; override;
  published
    procedure TestFromPemLoadsRoot;
    procedure TestFromPemFileLoadsRoot;
  end;

implementation

{ TTestBundleTrust }

procedure TTestBundleTrust.SetUp;
var
  LVectors: TStringList;
begin
  inherited SetUp;
  FProvider := TDefaultCryptoProvider.Create as ICryptoProvider;
  // reuse the shared EC P-256 test root (its DER form; LoadCertificateChain accepts it)
  LVectors := LoadVectorFields('Certs/EcP256Chain.txt');
  try
    FRootDer := DecodeHex(LVectors.Values['root_cert']);
  finally
    LVectors.Free;
  end;
end;

procedure TTestBundleTrust.TestFromPemLoadsRoot;
var
  LStore: ITrustAnchorStore;
begin
  LStore := TBundleTrust.FromPem(FProvider, FRootDer);
  CheckTrue(LStore <> nil, 'FromPem returns an anchor store');
  CheckEquals(1, Length(LStore.RootCertificates),
    'the one-cert bundle yields exactly one anchor');
  CheckTrue(FProvider.Certificates.IsWellFormed(LStore.RootCertificates[0]),
    'the harvested anchor is a well-formed certificate');
end;

procedure TTestBundleTrust.TestFromPemFileLoadsRoot;
var
  LStore: ITrustAnchorStore;
  LPath: string;
  LStream: TFileStream;
begin
  LPath := IncludeTrailingPathDelimiter(GetCurrentDir) + 'bundle_fixture.der';
  LStream := TFileStream.Create(LPath, fmCreate);
  try
    LStream.WriteBuffer(FRootDer[0], Length(FRootDer));
  finally
    LStream.Free;
  end;
  try
    LStore := TBundleTrust.FromPemFile(FProvider, LPath);
    CheckTrue(LStore <> nil, 'FromPemFile returns an anchor store');
    CheckEquals(1, Length(LStore.RootCertificates),
      'the bundle file yields exactly one anchor');
  finally
    SysUtils.DeleteFile(LPath);
  end;
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestBundleTrust);
{$ELSE}
  RegisterTest(TTestBundleTrust.Suite);
{$ENDIF FPC}

end.
