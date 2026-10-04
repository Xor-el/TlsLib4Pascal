{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlsLibTestBase;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  SysUtils,
  Classes,
  Generics.Collections,
{$IFDEF FPC}
  fpcunit,
  testregistry,
{$ELSE}
  TestFramework,
{$ENDIF FPC}
  TlpArrayUtilities,
  TlpDataEncoding,
  TlpIClock,
  TlpICryptoProvider,
  TlpDefaultCryptoProvider,
  TlpIPkixProvider,
  TlpDefaultPkixProvider,
  TlpICertificateTrust,
  TlpCertificateVerifier,
  TlsLibTestResourceLoader;

type
  /// <summary>Shared base fixture. The runner reuses one fixture instance across suite runs, so a
  /// fixture must not free its own object fields (a bare free leaves a dangling field the next run
  /// can double-free). Register each with Own and the base disposes it once per run.</summary>
  TTlsLibTestCase = class abstract(TTestCase)
  strict private
    FOwned: TList<TObject>;
    procedure FreeOwnedObjects;
  strict protected
    /// <summary>Registers AInstance for disposal at TearDown and returns it, so a field reads
    /// FThing := Own&lt;TThing&gt;(TThing.Create(...)).</summary>
    function Own<T: class>(const AInstance: T): T;
  public
    destructor Destroy; override;
  protected
    procedure SetUp; override;
    procedure TearDown; override;
  end;

  /// <summary>Adds hex / comparison / resource helpers used across the suites.</summary>
  TTlsLibAlgorithmTestCase = class abstract(TTlsLibTestCase)
  strict private
    FCrypto: ICryptoProvider;
    FPkix: IPkixProvider;
    function GetCrypto: ICryptoProvider;
    function GetPkix: IPkixProvider;
  strict protected
    // Overridable so a fixture can supply a different provider (e.g. a mock).
    function CreateCrypto: ICryptoProvider; virtual;
    // Overridable so a fixture can supply a different PKIX provider (e.g. a mock).
    function CreatePkix: IPkixProvider; virtual;
  protected
    procedure TearDown; override;
    // The crypto provider, created once per test on first use.
    property Crypto: ICryptoProvider read GetCrypto;
    // The PKIX provider, created once per test on first use.
    property Pkix: IPkixProvider read GetPkix;
    function DecodeHex(const AData: String): TBytes;
    function EncodeHex(const AData: TBytes): String;
    function AreEqual(const AA, AB: TBytes): Boolean;
    // A fresh array holding AA followed by AB.
    function ConcatBytes(const AA, AB: TBytes): TBytes;
    // Fail with a hex diff unless AActual equals AExpected.
    procedure CheckEqualBytes(const AName: string; const AExpected, AActual: TBytes);
    function LoadResourceBytes(const ARelativePath: string): TBytes;
    function LoadResourceString(const ARelativePath: string): string;
    // Loads a "name=hexvalue" vector file; read fields via Result.Values['name'].
    function LoadVectorFields(const ARelativePath: string): TStringList;
    // The EcP256Chain self-signed root (Certs/EcP256Chain.txt: root_cert), for config-only tests
    // that need a real trust source present but never verify a chain.
    function EcP256RootCertificate: TBytes;
    function EcP256RootStore: ITrustAnchorStore;
  end;

  /// <summary>A clock a test advances by hand, so time-dependent behaviour (rotation, deadlines)
  /// is driven deterministically without waiting.</summary>
  TAdjustableClock = class sealed(TInterfacedObject, ITlsClock)
  strict private
    FNowMillis: UInt64;
  public
    constructor Create(AStartMillis: UInt64);
    function NowUnixMillis: UInt64;
    procedure Advance(AMillis: UInt64);
    procedure Retreat(AMillis: UInt64);
  end;

implementation

{ TAdjustableClock }

constructor TAdjustableClock.Create(AStartMillis: UInt64);
begin
  inherited Create;
  FNowMillis := AStartMillis;
end;

function TAdjustableClock.NowUnixMillis: UInt64;
begin
  Result := FNowMillis;
end;

procedure TAdjustableClock.Advance(AMillis: UInt64);
begin
  Inc(FNowMillis, AMillis);
end;

procedure TAdjustableClock.Retreat(AMillis: UInt64);
begin
  Dec(FNowMillis, AMillis);
end;

{ TTlsLibTestCase }

destructor TTlsLibTestCase.Destroy;
begin
  FreeOwnedObjects;
  FOwned.Free;
  inherited Destroy;
end;

procedure TTlsLibTestCase.SetUp;
begin
  inherited SetUp;
  // a SetUp that raised on a prior run skips its TearDown; sweep any survivors before arranging
  FreeOwnedObjects;
end;

procedure TTlsLibTestCase.TearDown;
begin
  FreeOwnedObjects;
  inherited TearDown;
end;

function TTlsLibTestCase.Own<T>(const AInstance: T): T;
begin
  if FOwned = nil then
    FOwned := TList<TObject>.Create;
  FOwned.Add(AInstance);
  Result := AInstance;
end;

procedure TTlsLibTestCase.FreeOwnedObjects;
var
  LI: Integer;
begin
  if FOwned = nil then
    Exit;
  // newest first, so a graph is disposed before the objects it references
  for LI := FOwned.Count - 1 downto 0 do
    FOwned[LI].Free;
  FOwned.Clear;
end;

{ TTlsLibAlgorithmTestCase }

procedure TTlsLibAlgorithmTestCase.TearDown;
begin
  // the fixture instance is reused across suite runs; drop the cached providers so a stateful mock
  // cannot bleed into the next run (GetCrypto/GetPkix lazily rebuild them)
  FCrypto := nil;
  FPkix := nil;
  inherited TearDown;
end;

function TTlsLibAlgorithmTestCase.CreateCrypto: ICryptoProvider;
begin
  Result := TDefaultCryptoProvider.Create;
end;

function TTlsLibAlgorithmTestCase.CreatePkix: IPkixProvider;
begin
  Result := TDefaultPkixProvider.Create;
end;

function TTlsLibAlgorithmTestCase.GetCrypto: ICryptoProvider;
begin
  if FCrypto = nil then
    FCrypto := CreateCrypto;
  Result := FCrypto;
end;

function TTlsLibAlgorithmTestCase.GetPkix: IPkixProvider;
begin
  if FPkix = nil then
    FPkix := CreatePkix;
  Result := FPkix;
end;

function TTlsLibAlgorithmTestCase.DecodeHex(const AData: String): TBytes;
begin
  // vector files may space-separate bytes; strip whitespace, then decode strictly
  Result := TDataEncoding.HexDecode(StringReplace(AData, ' ', '', [rfReplaceAll]));
end;

function TTlsLibAlgorithmTestCase.EncodeHex(const AData: TBytes): String;
begin
  Result := TDataEncoding.HexEncode(AData, THexCase.Upper);
end;

function TTlsLibAlgorithmTestCase.AreEqual(const AA, AB: TBytes): Boolean;
var
  LI: Int32;
begin
  Result := System.Length(AA) = System.Length(AB);
  if not Result then
    Exit;
  for LI := 0 to System.Length(AA) - 1 do
    if AA[LI] <> AB[LI] then
      Exit(False);
end;

function TTlsLibAlgorithmTestCase.ConcatBytes(const AA, AB: TBytes): TBytes;
begin
  Result := TArrayUtilities.Concat(AA, AB);
end;

procedure TTlsLibAlgorithmTestCase.CheckEqualBytes(const AName: string;
  const AExpected, AActual: TBytes);
begin
  if not AreEqual(AExpected, AActual) then
    Fail(Format('%s failed - expected %s got %s',
      [AName, EncodeHex(AExpected), EncodeHex(AActual)]));
end;

function TTlsLibAlgorithmTestCase.LoadResourceBytes(const ARelativePath: string): TBytes;
begin
  Result := TTlsLibTestResourceLoader.LoadBytes(ARelativePath);
end;

function TTlsLibAlgorithmTestCase.LoadResourceString(const ARelativePath: string): string;
begin
  Result := TTlsLibTestResourceLoader.LoadString(ARelativePath);
end;

function TTlsLibAlgorithmTestCase.LoadVectorFields(const ARelativePath: string): TStringList;
begin
  Result := TStringList.Create;
  try
    Result.LoadFromFile(TTlsLibTestResourceLoader.ResourcePath(ARelativePath));
  except
    Result.Free;
    raise;
  end;
end;

function TTlsLibAlgorithmTestCase.EcP256RootCertificate: TBytes;
var
  LFields: TStringList;
begin
  LFields := LoadVectorFields('Certs/EcP256Chain.txt');
  try
    Result := DecodeHex(LFields.Values['root_cert']);
  finally
    LFields.Free;
  end;
end;

function TTlsLibAlgorithmTestCase.EcP256RootStore: ITrustAnchorStore;
begin
  Result := TTrustAnchorStore.Create(
    TArray<TBytes>.Create(EcP256RootCertificate)) as ITrustAnchorStore;
end;

end.
