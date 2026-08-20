{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

/// <summary>Exercises the trust-composition rules the config builder enforces: anchor sources
/// UNION (multiple WithTrustStore/WithTrustAnchors calls accumulate), while a whole
/// certificate verifier is EXCLUSIVE (it replaces the pipeline and cannot be combined with any
/// anchor source, nor set twice) - the invariant the OS system-trust sources rely on.</summary>
unit TrustCompositionTests;

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
  TlpTlsLibExceptions,
  TlpTlsAlert,
  TlpICertificateTrust,
  TlpCertificateVerifier,
  TlpITlsConfig,
  TlpITlsConfigBuilder,
  TlpTlsPresets,
  TlsLibTestBase;

type
  TTestTrustComposition = class(TTlsLibAlgorithmTestCase)
  private
    FCerts: TStringList;
    function StoreOf(const AFieldName: string): ITrustAnchorStore;
  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestTwoAnchorStoresUnionIntoComposedStore;
    procedure TestCertificateVerifierLandsInFrozenConfig;
    procedure TestVerifierCombinedWithAnchorSourceIsRejected;
    procedure TestTwoVerifiersAreRejected;
  end;

implementation

type
  /// <summary>A whole-verifier stub: it accepts everything and carries no anchors, standing in
  /// for an OS delegate so the composition rules can be exercised without real PKIX.</summary>
  TStubCertificateVerifier = class(TInterfacedObject, ICertificateVerifier)
  public
    function Verify(const AChain: TArray<TBytes>; const AHostName: string;
      const AOcspStaple: TBytes; out AAlert: TTlsAlertDescription): Boolean;
  end;

function TStubCertificateVerifier.Verify(const AChain: TArray<TBytes>;
  const AHostName: string; const AOcspStaple: TBytes;
  out AAlert: TTlsAlertDescription): Boolean;
begin
  AAlert := TTlsAlertDescription.CertificateUnknown;
  Result := True;
end;

{ TTestTrustComposition }

procedure TTestTrustComposition.SetUp;
begin
  inherited SetUp;
  FCerts := LoadVectorFields('Certs/EcP256Chain.txt');
end;

procedure TTestTrustComposition.TearDown;
begin
  FCerts.Free;
  inherited TearDown;
end;

function TTestTrustComposition.StoreOf(const AFieldName: string): ITrustAnchorStore;
begin
  Result := TTrustAnchorStore.Create(
    TArray<TBytes>.Create(DecodeHex(FCerts.Values[AFieldName]))) as ITrustAnchorStore;
end;

procedure TTestTrustComposition.TestTwoAnchorStoresUnionIntoComposedStore;
var
  LConfig: ITlsClientConfig;
begin
  // two distinct single-anchor stores added separately must both survive into the frozen config
  LConfig := TTlsPresets.Compatible(Provider).Client
    .WithTrustStore(StoreOf('root_cert'))
    .WithTrustStore(StoreOf('leaf_cert'))
    .Build;
  CheckEquals(2, System.Length(LConfig.TrustStore.RootCertificates),
    'both anchor sources union into the composed trust store');
  CheckTrue(LConfig.CertificateVerifier = nil,
    'no whole-verifier was set, so the built-in pipeline is used');
end;

procedure TTestTrustComposition.TestCertificateVerifierLandsInFrozenConfig;
var
  LConfig: ITlsClientConfig;
begin
  // a whole-verifier is a valid, self-sufficient trust source (no anchors needed)
  LConfig := TTlsPresets.Compatible(Provider).Client
    .WithCertificateVerifier(TStubCertificateVerifier.Create as ICertificateVerifier)
    .Build;
  CheckTrue(LConfig.CertificateVerifier <> nil,
    'the injected whole-verifier lands in the frozen config');
end;

procedure TTestTrustComposition.TestVerifierCombinedWithAnchorSourceIsRejected;
var
  LRaised: Boolean;
begin
  // verifier + anchor source is the exclusivity conflict: refused at Build, fail-closed
  LRaised := False;
  try
    TTlsPresets.Compatible(Provider).Client
      .WithCertificateVerifier(TStubCertificateVerifier.Create as ICertificateVerifier)
      .WithTrustStore(StoreOf('root_cert'))
      .Build;
  except
    on E: EInvalidOperationTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised,
    'a whole-verifier combined with an anchor source is refused at Build');
end;

procedure TTestTrustComposition.TestTwoVerifiersAreRejected;
var
  LRaised: Boolean;
begin
  // two whole-verifiers is the dual-verifier conflict: refused at Build
  LRaised := False;
  try
    TTlsPresets.Compatible(Provider).Client
      .WithCertificateVerifier(TStubCertificateVerifier.Create as ICertificateVerifier)
      .WithCertificateVerifier(TStubCertificateVerifier.Create as ICertificateVerifier)
      .Build;
  except
    on E: EInvalidOperationTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'setting two whole-verifiers is refused at Build');
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestTrustComposition);
{$ELSE}
  RegisterTest(TTestTrustComposition.Suite);
{$ENDIF FPC}

end.
