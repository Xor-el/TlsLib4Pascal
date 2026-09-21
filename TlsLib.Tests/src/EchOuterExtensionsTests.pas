{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit EchOuterExtensionsTests;

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
  TlpTlsAlert,
  TlpTlsLibExceptions,
  TlpCoreExtensions,
  TlpExtensionVector,
  TlpEchExtension,
  TlpEchOuterExtensions,
  TlsLibTestBase;

type
  /// <summary>
  /// The ClientHelloInner reconstruction of RFC 9849 sec. 5.1 - the attack surface a
  /// client-facing server exposes. Verifies the happy-path substitution (including
  /// non-contiguous references), and that each of the four RFC failure conditions
  /// (missing / out-of-order / duplicate reference / encrypted_client_hello referenced)
  /// aborts with illegal_parameter.
  /// </summary>
  TTestEchOuterExtensions = class(TTlsLibTestCase)
  private
    function Entry(AType: UInt16; const AData: TBytes): TExtensionEntry;
    function OuterExtEntry(const ATypes: TArray<UInt16>): TExtensionEntry;
    function Vec(const AEntries: array of TExtensionEntry): TExtensionVector;
    function ReconstructAborts(const AOuter, AInner: TExtensionVector): Boolean;
  published
    procedure TestReconstructHappyPath;
    procedure TestReconstructNonContiguous;
    procedure TestReconstructNoBlockUnchanged;
    procedure TestMissingReferenceAborts;
    procedure TestOutOfOrderReferenceAborts;
    procedure TestDuplicateReferenceAborts;
    procedure TestTwoOuterExtensionsBlocksAbort;
    procedure TestOuterExtensionsSelfReferenceAborts;
    procedure TestEchReferencedAborts;
    procedure TestIsCompressible;
  end;

implementation

{ TTestEchOuterExtensions }

function TTestEchOuterExtensions.Entry(AType: UInt16;
  const AData: TBytes): TExtensionEntry;
begin
  Result := TExtensionEntry.Create(AType, AData);
end;

function TTestEchOuterExtensions.OuterExtEntry(
  const ATypes: TArray<UInt16>): TExtensionEntry;
begin
  Result := TExtensionEntry.Create(TExtensionTypes.EchOuterExtensions,
    TEchExtension.EncodeOuterExtensions(ATypes));
end;

function TTestEchOuterExtensions.Vec(
  const AEntries: array of TExtensionEntry): TExtensionVector;
var
  LI: Int32;
begin
  Result := TExtensionVector.Empty;
  for LI := 0 to System.High(AEntries) do
    Result.Append(AEntries[LI]);
end;

function TTestEchOuterExtensions.ReconstructAborts(const AOuter,
  AInner: TExtensionVector): Boolean;
begin
  Result := False;
  try
    TEchOuterExtensions.Reconstruct(AOuter, AInner);
  except
    on E: EFatalAlertTlsLibException do
      Result := E.AlertDescription = TTlsAlertDescription.IllegalParameter;
  end;
end;

procedure TTestEchOuterExtensions.TestReconstructHappyPath;
var
  LOuter, LInner, LResult: TExtensionVector;
begin
  // outer [10,13,43,51]; inner [0, outer_ext(10,43), 28] -> [0,10,43,28]
  LOuter := Vec([Entry(10, TBytes.Create(1)),
    Entry(13, TBytes.Create(2)), Entry(43, TBytes.Create(3)),
    Entry(51, TBytes.Create(4))]);
  LInner := Vec([Entry(0, TBytes.Create(9)),
    OuterExtEntry(TArray<UInt16>.Create(UInt16(10), UInt16(43))),
    Entry(28, TBytes.Create(7))]);
  LResult := TEchOuterExtensions.Reconstruct(LOuter, LInner);
  CheckEquals(4, LResult.Count, 'expanded entry count');
  CheckEquals(0, Integer(LResult.Entries[0].ExtensionType), 'kept inner extension 0');
  CheckEquals(10, Integer(LResult.Entries[1].ExtensionType), 'pulled outer 10');
  CheckEquals(43, Integer(LResult.Entries[2].ExtensionType), 'pulled outer 43');
  CheckEquals(28, Integer(LResult.Entries[3].ExtensionType), 'kept inner extension 28');
  // the pulled bodies come from the outer, not the inner
  CheckEquals(3, LResult.Entries[2].Data[0], 'outer 43 body was copied');
end;

procedure TTestEchOuterExtensions.TestReconstructNonContiguous;
var
  LOuter, LInner, LResult: TExtensionVector;
begin
  // referenced extensions need not be adjacent in the outer, only in order
  LOuter := Vec([Entry(10, nil), Entry(13, nil), Entry(43, nil), Entry(51, nil)]);
  LInner := Vec([OuterExtEntry(TArray<UInt16>.Create(UInt16(10), UInt16(51)))]);
  LResult := TEchOuterExtensions.Reconstruct(LOuter, LInner);
  CheckEquals(2, LResult.Count, 'two pulled entries');
  CheckEquals(10, Integer(LResult.Entries[0].ExtensionType), 'first');
  CheckEquals(51, Integer(LResult.Entries[1].ExtensionType),
    'second, skipping 13 and 43');
end;

procedure TTestEchOuterExtensions.TestReconstructNoBlockUnchanged;
var
  LOuter, LInner, LResult: TExtensionVector;
begin
  LOuter := Vec([Entry(10, nil)]);
  LInner := Vec([Entry(0, TBytes.Create(1)), Entry(28, TBytes.Create(2))]);
  LResult := TEchOuterExtensions.Reconstruct(LOuter, LInner);
  CheckEquals(2, LResult.Count, 'inner returned unchanged');
  CheckEquals(0, Integer(LResult.Entries[0].ExtensionType), 'first');
  CheckEquals(28, Integer(LResult.Entries[1].ExtensionType), 'second');
end;

procedure TTestEchOuterExtensions.TestMissingReferenceAborts;
begin
  CheckTrue(ReconstructAborts(Vec([Entry(10, nil)]),
    Vec([OuterExtEntry(TArray<UInt16>.Create(UInt16(999)))])),
    'a reference missing from the outer aborts with illegal_parameter');
end;

procedure TTestEchOuterExtensions.TestOutOfOrderReferenceAborts;
begin
  // outer order is [10,13]; referencing [13,10] walks the cursor past 10
  CheckTrue(ReconstructAborts(Vec([Entry(10, nil), Entry(13, nil)]),
    Vec([OuterExtEntry(TArray<UInt16>.Create(UInt16(13), UInt16(10)))])),
    'an out-of-order reference aborts with illegal_parameter');
end;

procedure TTestEchOuterExtensions.TestDuplicateReferenceAborts;
begin
  CheckTrue(ReconstructAborts(Vec([Entry(10, nil)]),
    Vec([OuterExtEntry(TArray<UInt16>.Create(UInt16(10), UInt16(10)))])),
    'a duplicate reference aborts with illegal_parameter');
end;

procedure TTestEchOuterExtensions.TestTwoOuterExtensionsBlocksAbort;
begin
  // ech_outer_extensions is itself an extension, so two blocks repeat a type (RFC 8446 4.2)
  CheckTrue(ReconstructAborts(Vec([Entry(10, nil), Entry(13, nil)]),
    Vec([OuterExtEntry(TArray<UInt16>.Create(UInt16(10))),
    OuterExtEntry(TArray<UInt16>.Create(UInt16(13)))])),
    'a second ech_outer_extensions block aborts with illegal_parameter');
end;

procedure TTestEchOuterExtensions.TestOuterExtensionsSelfReferenceAborts;
begin
  // the reference list must not name ech_outer_extensions itself (RFC 9849 5.1)
  CheckTrue(ReconstructAborts(
    Vec([Entry(TExtensionTypes.EchOuterExtensions, nil)]),
    Vec([OuterExtEntry(TArray<UInt16>.Create(TExtensionTypes.EchOuterExtensions))])),
    'referencing ech_outer_extensions itself aborts with illegal_parameter');
end;

procedure TTestEchOuterExtensions.TestEchReferencedAborts;
begin
  CheckTrue(ReconstructAborts(
    Vec([Entry(TExtensionTypes.EncryptedClientHello, nil)]),
    Vec([OuterExtEntry(TArray<UInt16>.Create(
    TExtensionTypes.EncryptedClientHello))])),
    'referencing encrypted_client_hello aborts with illegal_parameter');
end;

procedure TTestEchOuterExtensions.TestIsCompressible;
begin
  CheckTrue(TEchOuterExtensions.IsCompressible(TExtensionTypes.SupportedGroups),
    'supported_groups is compressible');
  CheckTrue(TEchOuterExtensions.IsCompressible(TExtensionTypes.KeyShare),
    'key_share is compressible');
  CheckFalse(TEchOuterExtensions.IsCompressible(TExtensionTypes.ServerName),
    'server_name is never compressed (it differs inner vs outer)');
  CheckFalse(TEchOuterExtensions.IsCompressible(
    TExtensionTypes.EncryptedClientHello), 'ech itself is not compressible');
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestEchOuterExtensions);
{$ELSE}
  RegisterTest(TTestEchOuterExtensions.Suite);
{$ENDIF FPC}

end.
