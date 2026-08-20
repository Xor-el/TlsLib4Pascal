{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

/// <summary>Proves TRootGenerator keys a certificate to its trust record by
/// (CKA_ISSUER, CKA_SERIAL_NUMBER), not by the display CKA_LABEL, over a tiny
/// synthetic certdata.txt: a label-mismatched pair still associates, a label
/// collision no longer mis-associates, and a non-delegator trust is excluded.</summary>
unit RootGenKeyingTests;

{$IFDEF FPC}
{$MODE DELPHI}
{$H+}
{$ENDIF FPC}

interface

uses
  SysUtils,
{$IFDEF FPC}
  fpcunit,
  testregistry,
{$ELSE}
  TestFramework,
{$ENDIF FPC}
  TlpRootGen,
  TlsLibTestBase;

type
  TTestRootGenKeying = class(TTlsLibAlgorithmTestCase)
  strict private
    class function SyntheticCertData: string; static;
  published
    procedure TestKeyByIssuerSerialNotLabel;
  end;

implementation

class function TTestRootGenKeying.SyntheticCertData: string;
var
  LSb: TStringBuilder;

  procedure L(const AText: string);
  begin
    LSb.Append(AText).Append(sLineBreak);
  end;

begin
  LSb := TStringBuilder.Create;
  try
    // Cert A: DER 41 42; issuer 01; serial 01; label "Alpha".
    L('CKA_CLASS CKO_CERTIFICATE');
    L('CKA_LABEL UTF8 "Alpha"');
    L('CKA_ISSUER MULTILINE_OCTAL'); L('\001'); L('END');
    L('CKA_SERIAL_NUMBER MULTILINE_OCTAL'); L('\001'); L('END');
    L('CKA_VALUE MULTILINE_OCTAL'); L('\101\102'); L('END');
    L('');
    // Trust A: matches A by (01,01) but a DIFFERENT label; trusted delegator -> A emitted.
    L('CKA_CLASS CKO_NSS_TRUST');
    L('CKA_LABEL UTF8 "Alpha Trust Object"');
    L('CKA_ISSUER MULTILINE_OCTAL'); L('\001'); L('END');
    L('CKA_SERIAL_NUMBER MULTILINE_OCTAL'); L('\001'); L('END');
    L('CKA_TRUST_SERVER_AUTH CK_TRUST CKT_NSS_TRUSTED_DELEGATOR');
    L('');
    // Cert B: DER 43 44; issuer 02; serial 02; label "Shared" (collides with C).
    L('CKA_CLASS CKO_CERTIFICATE');
    L('CKA_LABEL UTF8 "Shared"');
    L('CKA_ISSUER MULTILINE_OCTAL'); L('\002'); L('END');
    L('CKA_SERIAL_NUMBER MULTILINE_OCTAL'); L('\002'); L('END');
    L('CKA_VALUE MULTILINE_OCTAL'); L('\103\104'); L('END');
    L('');
    // Cert C: DER 45 46; issuer 03; serial 03; label "Shared" (same label as B).
    L('CKA_CLASS CKO_CERTIFICATE');
    L('CKA_LABEL UTF8 "Shared"');
    L('CKA_ISSUER MULTILINE_OCTAL'); L('\003'); L('END');
    L('CKA_SERIAL_NUMBER MULTILINE_OCTAL'); L('\003'); L('END');
    L('CKA_VALUE MULTILINE_OCTAL'); L('\105\106'); L('END');
    L('');
    // Trust C: matches C by (03,03) ONLY; trusted delegator -> C emitted, never B.
    L('CKA_CLASS CKO_NSS_TRUST');
    L('CKA_LABEL UTF8 "Shared"');
    L('CKA_ISSUER MULTILINE_OCTAL'); L('\003'); L('END');
    L('CKA_SERIAL_NUMBER MULTILINE_OCTAL'); L('\003'); L('END');
    L('CKA_TRUST_SERVER_AUTH CK_TRUST CKT_NSS_TRUSTED_DELEGATOR');
    L('');
    // Cert D: DER 47 48; issuer 04; serial 04; label "Delta".
    L('CKA_CLASS CKO_CERTIFICATE');
    L('CKA_LABEL UTF8 "Delta"');
    L('CKA_ISSUER MULTILINE_OCTAL'); L('\004'); L('END');
    L('CKA_SERIAL_NUMBER MULTILINE_OCTAL'); L('\004'); L('END');
    L('CKA_VALUE MULTILINE_OCTAL'); L('\107\110'); L('END');
    L('');
    // Trust D: matches D by (04,04) but MUST_VERIFY_TRUST -> D excluded (filter unchanged).
    L('CKA_CLASS CKO_NSS_TRUST');
    L('CKA_LABEL UTF8 "Delta"');
    L('CKA_ISSUER MULTILINE_OCTAL'); L('\004'); L('END');
    L('CKA_SERIAL_NUMBER MULTILINE_OCTAL'); L('\004'); L('END');
    L('CKA_TRUST_SERVER_AUTH CK_TRUST CKT_NSS_MUST_VERIFY_TRUST');
    Result := LSb.ToString;
  finally
    LSb.Free;
  end;
end;

procedure TTestRootGenKeying.TestKeyByIssuerSerialNotLabel;
var
  LRoots: TArray<TBytes>;
  LExpectedA, LExpectedC: TBytes;
begin
  LRoots := TRootGenerator.ExtractTrustedRoots(SyntheticCertData);

  // Only Cert A (41 42) and Cert C (45 46) carry a matching trusted-delegator record.
  // Deterministic DER sort: [41,42] < [45,46]. Cert B (43 44) shares C's label but has no
  // trust record; Cert D (47 48) is must-verify. The label-keyed code would have mis-paired
  // B with C's "Shared" trust and emitted it - byte-exact (issuer,serial) keying does not.
  SetLength(LExpectedA, 2);
  LExpectedA[0] := $41;
  LExpectedA[1] := $42;
  SetLength(LExpectedC, 2);
  LExpectedC[0] := $45;
  LExpectedC[1] := $46;

  CheckEquals(2, Length(LRoots),
    'exactly the two (issuer,serial)-matched trusted roots are emitted');
  CheckTrue(AreEqual(LRoots[0], LExpectedA),
    'first root is Cert A, matched despite a differing trust-object label');
  CheckTrue(AreEqual(LRoots[1], LExpectedC),
    'second root is Cert C; the label collision with B is resolved by issuer/serial');
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestRootGenKeying);
{$ELSE}
  RegisterTest(TTestRootGenKeying.Suite);
{$ENDIF FPC}

end.
