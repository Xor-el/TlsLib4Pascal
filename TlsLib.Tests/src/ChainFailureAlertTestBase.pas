{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit ChainFailureAlertTestBase;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  SysUtils,
  TlpTlsAlert,
  TlsLibTestCertificates,
  TlsLibTestBase;

type
  /// <summary>The chain-failure alerts every verifier must send over the fixture chains
  /// anchored at chain_root.</summary>
  TChainFailureAlertTestBase = class abstract(TTlsLibAlgorithmTestCase)
  strict protected
    // the fixture certificates named, in order
    function Chain(const ANames: array of string): TArray<TBytes>;
    // whether the verifier accepts the named server chain, with the alert when it refuses
    function Verdict(const AChain: array of string;
      out AAlert: TTlsAlertDescription): Boolean; virtual; abstract;
  published
    procedure TestValidChainIsAccepted;
    procedure TestBadSignatureUnderAPooledIntermediateIsDecryptError;
    procedure TestCriticalPrivateExtensionOnTheLeafIsCertificateUnknown;
    procedure TestCriticalPrivateExtensionOnAnIntermediateIsCertificateUnknown;
  end;

implementation

{ TChainFailureAlertTestBase }

function TChainFailureAlertTestBase.Chain(const ANames: array of string): TArray<TBytes>;
var
  LI: Int32;
begin
  Result := nil;
  SetLength(Result, System.Length(ANames));
  for LI := 0 to System.High(ANames) do
    Result[LI] := TTlsLibTestCertificates.Field('Certs/ChainFailures.txt', ANames[LI]);
end;

procedure TChainFailureAlertTestBase.TestValidChainIsAccepted;
var
  LAlert: TTlsAlertDescription;
begin
  CheckTrue(Verdict(['chain_leaf', 'chain_inter'], LAlert),
    'the fixture chain the bad-signature cases imitate is valid');
end;

procedure TChainFailureAlertTestBase.TestBadSignatureUnderAPooledIntermediateIsDecryptError;
var
  LAlert: TTlsAlertDescription;
begin
  CheckFalse(Verdict(['chain_badsig_leaf', 'chain_inter'], LAlert),
    'a leaf not signed by its named intermediate is refused');
  CheckEquals(Ord(TTlsAlertDescription.DecryptError), Ord(LAlert),
    'an invalid certificate signature is decrypt_error');
end;

procedure TChainFailureAlertTestBase.TestCriticalPrivateExtensionOnTheLeafIsCertificateUnknown;
var
  LAlert: TTlsAlertDescription;
begin
  CheckFalse(Verdict(['chain_crit_leaf'], LAlert),
    'a leaf with an unrecognized critical extension is refused');
  CheckEquals(Ord(TTlsAlertDescription.CertificateUnknown), Ord(LAlert),
    'an unhandled critical extension is certificate_unknown');
end;

procedure TChainFailureAlertTestBase.TestCriticalPrivateExtensionOnAnIntermediateIsCertificateUnknown;
var
  LAlert: TTlsAlertDescription;
begin
  CheckFalse(Verdict(['chain_crit_inter_leaf', 'chain_crit_inter'], LAlert),
    'an intermediate with an unrecognized critical extension is refused');
  CheckEquals(Ord(TTlsAlertDescription.CertificateUnknown), Ord(LAlert),
    'an unhandled critical extension is certificate_unknown');
end;

end.
