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
    function Entry(AType: UInt16; const AData: TBytes): TEchExtEntry;
    function OuterExtEntry(const ATypes: TArray<UInt16>): TEchExtEntry;
    function ReconstructAborts(const AOuter, AInner: TArray<TEchExtEntry>): Boolean;
  published
    procedure TestReconstructHappyPath;
    procedure TestReconstructNonContiguous;
    procedure TestReconstructNoBlockUnchanged;
    procedure TestMissingReferenceAborts;
    procedure TestOutOfOrderReferenceAborts;
    procedure TestDuplicateReferenceAborts;
    procedure TestTwoOuterExtensionsBlocksAbort;
    procedure TestOuterExtensionsSelfReferenceAborts;
    procedure TestTooManyExtensionsRejected;
    procedure TestEchReferencedAborts;
    procedure TestExtensionsRoundTrip;
    procedure TestIsCompressible;
  end;

implementation

{ TTestEchOuterExtensions }

function TTestEchOuterExtensions.Entry(AType: UInt16;
  const AData: TBytes): TEchExtEntry;
begin
  Result.ExtType := AType;
  Result.Data := AData;
end;

function TTestEchOuterExtensions.OuterExtEntry(
  const ATypes: TArray<UInt16>): TEchExtEntry;
begin
  Result.ExtType := TExtensionTypes.EchOuterExtensions;
  Result.Data := TEchExtension.EncodeOuterExtensions(ATypes);
end;

function TTestEchOuterExtensions.ReconstructAborts(const AOuter,
  AInner: TArray<TEchExtEntry>): Boolean;
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
  LOuter, LInner, LResult: TArray<TEchExtEntry>;
begin
  // outer [10,13,43,51]; inner [0, outer_ext(10,43), 28] -> [0,10,43,28]
  LOuter := TArray<TEchExtEntry>.Create(Entry(10, TBytes.Create(1)),
    Entry(13, TBytes.Create(2)), Entry(43, TBytes.Create(3)),
    Entry(51, TBytes.Create(4)));
  LInner := TArray<TEchExtEntry>.Create(Entry(0, TBytes.Create(9)),
    OuterExtEntry(TArray<UInt16>.Create(UInt16(10), UInt16(43))),
    Entry(28, TBytes.Create(7)));
  LResult := TEchOuterExtensions.Reconstruct(LOuter, LInner);
  CheckEquals(4, System.Length(LResult), 'expanded entry count');
  CheckEquals(0, Integer(LResult[0].ExtType), 'kept inner extension 0');
  CheckEquals(10, Integer(LResult[1].ExtType), 'pulled outer 10');
  CheckEquals(43, Integer(LResult[2].ExtType), 'pulled outer 43');
  CheckEquals(28, Integer(LResult[3].ExtType), 'kept inner extension 28');
  // the pulled bodies come from the outer, not the inner
  CheckEquals(3, LResult[2].Data[0], 'outer 43 body was copied');
end;

procedure TTestEchOuterExtensions.TestReconstructNonContiguous;
var
  LOuter, LInner, LResult: TArray<TEchExtEntry>;
begin
  // referenced extensions need not be adjacent in the outer, only in order
  LOuter := TArray<TEchExtEntry>.Create(Entry(10, nil), Entry(13, nil),
    Entry(43, nil), Entry(51, nil));
  LInner := TArray<TEchExtEntry>.Create(
    OuterExtEntry(TArray<UInt16>.Create(UInt16(10), UInt16(51))));
  LResult := TEchOuterExtensions.Reconstruct(LOuter, LInner);
  CheckEquals(2, System.Length(LResult), 'two pulled entries');
  CheckEquals(10, Integer(LResult[0].ExtType), 'first');
  CheckEquals(51, Integer(LResult[1].ExtType), 'second, skipping 13 and 43');
end;

procedure TTestEchOuterExtensions.TestReconstructNoBlockUnchanged;
var
  LOuter, LInner, LResult: TArray<TEchExtEntry>;
begin
  LOuter := TArray<TEchExtEntry>.Create(Entry(10, nil));
  LInner := TArray<TEchExtEntry>.Create(Entry(0, TBytes.Create(1)),
    Entry(28, TBytes.Create(2)));
  LResult := TEchOuterExtensions.Reconstruct(LOuter, LInner);
  CheckEquals(2, System.Length(LResult), 'inner returned unchanged');
  CheckEquals(0, Integer(LResult[0].ExtType), 'first');
  CheckEquals(28, Integer(LResult[1].ExtType), 'second');
end;

procedure TTestEchOuterExtensions.TestMissingReferenceAborts;
var
  LOuter, LInner: TArray<TEchExtEntry>;
begin
  LOuter := TArray<TEchExtEntry>.Create(Entry(10, nil));
  LInner := TArray<TEchExtEntry>.Create(
    OuterExtEntry(TArray<UInt16>.Create(UInt16(999))));
  CheckTrue(ReconstructAborts(LOuter, LInner),
    'a reference missing from the outer aborts with illegal_parameter');
end;

procedure TTestEchOuterExtensions.TestOutOfOrderReferenceAborts;
var
  LOuter, LInner: TArray<TEchExtEntry>;
begin
  // outer order is [10,13]; referencing [13,10] walks the cursor past 10
  LOuter := TArray<TEchExtEntry>.Create(Entry(10, nil), Entry(13, nil));
  LInner := TArray<TEchExtEntry>.Create(
    OuterExtEntry(TArray<UInt16>.Create(UInt16(13), UInt16(10))));
  CheckTrue(ReconstructAborts(LOuter, LInner),
    'an out-of-order reference aborts with illegal_parameter');
end;

procedure TTestEchOuterExtensions.TestDuplicateReferenceAborts;
var
  LOuter, LInner: TArray<TEchExtEntry>;
begin
  LOuter := TArray<TEchExtEntry>.Create(Entry(10, nil));
  LInner := TArray<TEchExtEntry>.Create(
    OuterExtEntry(TArray<UInt16>.Create(UInt16(10), UInt16(10))));
  CheckTrue(ReconstructAborts(LOuter, LInner),
    'a duplicate reference aborts with illegal_parameter');
end;

procedure TTestEchOuterExtensions.TestTwoOuterExtensionsBlocksAbort;
var
  LOuter, LInner: TArray<TEchExtEntry>;
begin
  // ech_outer_extensions is itself an extension, so two blocks repeat a type (RFC 8446 4.2)
  LOuter := TArray<TEchExtEntry>.Create(Entry(10, nil), Entry(13, nil));
  LInner := TArray<TEchExtEntry>.Create(
    OuterExtEntry(TArray<UInt16>.Create(UInt16(10))),
    OuterExtEntry(TArray<UInt16>.Create(UInt16(13))));
  CheckTrue(ReconstructAborts(LOuter, LInner),
    'a second ech_outer_extensions block aborts with illegal_parameter');
end;

procedure TTestEchOuterExtensions.TestOuterExtensionsSelfReferenceAborts;
var
  LOuter, LInner: TArray<TEchExtEntry>;
begin
  // the reference list must not name ech_outer_extensions itself (RFC 9849 5.1)
  LOuter := TArray<TEchExtEntry>.Create(
    Entry(TExtensionTypes.EchOuterExtensions, nil));
  LInner := TArray<TEchExtEntry>.Create(
    OuterExtEntry(TArray<UInt16>.Create(TExtensionTypes.EchOuterExtensions)));
  CheckTrue(ReconstructAborts(LOuter, LInner),
    'referencing ech_outer_extensions itself aborts with illegal_parameter');
end;

procedure TTestEchOuterExtensions.TestTooManyExtensionsRejected;
var
  LEntries: TArray<TEchExtEntry>;
  LI: Int32;
  LRaised: Boolean;
begin
  // 65 entries exceeds the per-hello cap, so the parse rejects it in linear time (RFC 9849 5.1)
  SetLength(LEntries, 65);
  for LI := 0 to System.High(LEntries) do
    LEntries[LI].ExtType := UInt16(1000 + LI);
  LRaised := False;
  try
    TEchOuterExtensions.ParseExtensions(
      TEchOuterExtensions.EncodeExtensions(LEntries));
  except
    on E: EDecodeErrorTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'more than 64 extensions is a decode error');
end;

procedure TTestEchOuterExtensions.TestEchReferencedAborts;
var
  LOuter, LInner: TArray<TEchExtEntry>;
begin
  LOuter := TArray<TEchExtEntry>.Create(
    Entry(TExtensionTypes.EncryptedClientHello, nil));
  LInner := TArray<TEchExtEntry>.Create(OuterExtEntry(
    TArray<UInt16>.Create(TExtensionTypes.EncryptedClientHello)));
  CheckTrue(ReconstructAborts(LOuter, LInner),
    'referencing encrypted_client_hello aborts with illegal_parameter');
end;

procedure TTestEchOuterExtensions.TestExtensionsRoundTrip;
var
  LEntries, LDecoded: TArray<TEchExtEntry>;
  LI: Int32;
begin
  LEntries := TArray<TEchExtEntry>.Create(Entry(10, TBytes.Create(1, 2, 3)),
    Entry(43, nil), Entry(51, TBytes.Create(9)));
  LDecoded := TEchOuterExtensions.ParseExtensions(
    TEchOuterExtensions.EncodeExtensions(LEntries));
  CheckEquals(System.Length(LEntries), System.Length(LDecoded), 'entry count');
  for LI := 0 to System.High(LEntries) do
  begin
    CheckEquals(Integer(LEntries[LI].ExtType), Integer(LDecoded[LI].ExtType),
      'type');
    CheckEquals(System.Length(LEntries[LI].Data),
      System.Length(LDecoded[LI].Data), 'data length');
  end;
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
