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
  TlpDateTimeUtilities,
  TlpSystemTimeUtilities,
  TlpICryptoProvider,
  TlpIPkixProvider,
  TlpISession,
  TlpICertificateTrust,
  TlpITrustAnchorStore,
  TlpTrustAnchorStore,
  TlpCertificateVerifier,
  TlpICertificateVerifierSource,
  TlpCertificateVerifierSource,
  TlsLibTestResourceLoader,
  TlsLibTestProviders;

type
  /// <summary>A server-side session store that issues tickets of a fixed length, as a foreign
  /// server with an unbounded ticket would; it holds nothing and resumes nothing.</summary>
  TFixedLengthTicketStore = class sealed(TInterfacedObject, ISessionStore)
  strict private
  var
    FTicketLength: Int32;
  public
    constructor Create(ATicketLength: Int32);
    function Put(const ASession: IResumableSession): TBytes;
    procedure PutWithId(const AId: TBytes; const ASession: IResumableSession);
    function Peek(const AId: TBytes; out ASession: IResumableSession): Boolean;
    function Take(const AId: TBytes; out ASession: IResumableSession): Boolean;
    procedure Remove(const AId: TBytes);
    procedure Clear;
    function Count: Int32;
  end;

  /// <summary>Shared base fixture. The runner reuses one fixture instance across suite runs, so a
  /// fixture must not free its own object fields (a bare free leaves a dangling field the next run
  /// can double-free). Register each with Own and the base disposes it once per run.</summary>
  TTlsLibTestCase = class abstract(TTestCase)
  strict private
    FOwned: TList<TObject>;
    FTempDir: string;
    procedure FreeOwnedObjects;
    procedure RemoveTree(const APath: string);
    procedure RemoveTempDir;
  strict protected
    /// <summary>A path for a scratch file in a directory unique to this test run; the directory
    /// and its files are removed at TearDown.</summary>
    function TempPath(const AName: string): string;
    /// <summary>Registers AInstance for disposal at TearDown and returns it, so a field reads
    /// FThing := Own&lt;TThing&gt;(TThing.Create(...)).</summary>
    function Own<T: class>(const AInstance: T): T;
    /// <summary>The current UTC time as a TDateTime.</summary>
    function NowUtc: TDateTime;
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
    // The selected provider; override to pin one (e.g. a mock or a named choice).
    function CreateCrypto: ICryptoProvider; virtual;
    // The selected PKIX provider; override to pin one.
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
    // Whether ANeedle occurs in AHaystack (an empty needle always does).
    function ContainsBytes(const AHaystack, ANeedle: TBytes): Boolean;
    // Whether AText occurs in ABytes as ASCII.
    function ContainsAscii(const ABytes: TBytes; const AText: string): Boolean;
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
    // A named certificate of Certs/CriticalExtensionsChain.txt.
    function CriticalExtensionsCertificate(const AName: string): TBytes;
    // The built-in PKIX pipeline over AStore / over PEM or DER roots, with its default settings.
    function WebPkiServer(const AStore: ITrustAnchorStore): IServerVerification; overload;
    function WebPkiServer(const AAnchorData: TBytes): IServerVerification; overload;
    function WebPkiClient(const AStore: ITrustAnchorStore): IClientVerification; overload;
    function WebPkiClient(const AAnchorData: TBytes): IClientVerification; overload;
  end;

implementation

{ TFixedLengthTicketStore }

constructor TFixedLengthTicketStore.Create(ATicketLength: Int32);
begin
  inherited Create;
  FTicketLength := ATicketLength;
end;

function TFixedLengthTicketStore.Put(const ASession: IResumableSession): TBytes;
begin
  Result := nil;
  System.SetLength(Result, FTicketLength);
end;

procedure TFixedLengthTicketStore.PutWithId(const AId: TBytes; const ASession: IResumableSession);
begin
end;

function TFixedLengthTicketStore.Peek(const AId: TBytes; out ASession: IResumableSession): Boolean;
begin
  ASession := nil;
  Result := False;
end;

function TFixedLengthTicketStore.Take(const AId: TBytes; out ASession: IResumableSession): Boolean;
begin
  ASession := nil;
  Result := False;
end;

procedure TFixedLengthTicketStore.Remove(const AId: TBytes);
begin
end;

procedure TFixedLengthTicketStore.Clear;
begin
end;

function TFixedLengthTicketStore.Count: Int32;
begin
  Result := 0;
end;

{ TTlsLibTestCase }

destructor TTlsLibTestCase.Destroy;
begin
  FreeOwnedObjects;
  RemoveTempDir;
  FOwned.Free;
  inherited Destroy;
end;

function TTlsLibTestCase.TempPath(const AName: string): string;
var
  LBase: string;
  LId: TGUID;
begin
  if FTempDir = '' then
  begin
    LBase := GetEnvironmentVariable('TEMP');
    if LBase = '' then
      LBase := GetEnvironmentVariable('TMPDIR');
    if LBase = '' then
      LBase := GetCurrentDir;
    CreateGUID(LId);
    FTempDir := IncludeTrailingPathDelimiter(LBase) + 'tlslib-tests-' +
      Copy(GUIDToString(LId), 2, 36);
    ForceDirectories(FTempDir);
  end;
  Result := IncludeTrailingPathDelimiter(FTempDir) + AName;
end;

procedure TTlsLibTestCase.RemoveTree(const APath: string);
var
  LFind: TSearchRec;
begin
  if FindFirst(IncludeTrailingPathDelimiter(APath) + '*', faAnyFile, LFind) = 0 then
  begin
    repeat
      if (LFind.Name = '.') or (LFind.Name = '..') then
        Continue;
      if (LFind.Attr and faDirectory) <> 0 then
        RemoveTree(IncludeTrailingPathDelimiter(APath) + LFind.Name)
      else
        DeleteFile(IncludeTrailingPathDelimiter(APath) + LFind.Name);
    until FindNext(LFind) <> 0;
    FindClose(LFind);
  end;
  RemoveDir(APath);
end;

procedure TTlsLibTestCase.RemoveTempDir;
begin
  if FTempDir = '' then
    Exit;
  RemoveTree(FTempDir);
  FTempDir := '';
end;

procedure TTlsLibTestCase.SetUp;
begin
  inherited SetUp;
  // fpcunit skips TearDown when SetUp raises, and DUnit runs it regardless; sweep any survivors
  // before arranging so neither leaves a stale object or scratch directory behind
  FreeOwnedObjects;
  RemoveTempDir;
end;

procedure TTlsLibTestCase.TearDown;
begin
  FreeOwnedObjects;
  RemoveTempDir;
  inherited TearDown;
end;

function TTlsLibTestCase.NowUtc: TDateTime;
begin
  Result := TDateTimeUtilities.UnixMsToDateTime(TSystemTimeUtilities.UtcUnixMs);
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
  LItem: TObject;
begin
  if FOwned = nil then
    Exit;
  // newest first, so a graph is disposed before the objects it references; an entry leaves the
  // list before it is freed, so a destructor that raises cannot make the next sweep free it twice
  for LI := FOwned.Count - 1 downto 0 do
  begin
    LItem := FOwned[LI];
    FOwned.Delete(LI);
    LItem.Free;
  end;
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
  Result := TTlsLibTestProviders.Crypto;
end;

function TTlsLibAlgorithmTestCase.CreatePkix: IPkixProvider;
begin
  Result := TTlsLibTestProviders.Pkix;
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

function TTlsLibAlgorithmTestCase.ContainsBytes(const AHaystack, ANeedle: TBytes): Boolean;
var
  LOffset, LIdx: Int32;
begin
  for LOffset := 0 to System.Length(AHaystack) - System.Length(ANeedle) do
  begin
    LIdx := 0;
    while (LIdx < System.Length(ANeedle)) and
      (AHaystack[LOffset + LIdx] = ANeedle[LIdx]) do
      Inc(LIdx);
    if LIdx = System.Length(ANeedle) then
      Exit(True);
  end;
  Result := False;
end;

function TTlsLibAlgorithmTestCase.ContainsAscii(const ABytes: TBytes;
  const AText: string): Boolean;
var
  LNeedle: TBytes;
  LI: Int32;
begin
  LNeedle := nil;
  SetLength(LNeedle, System.Length(AText));
  for LI := 1 to System.Length(AText) do
    LNeedle[LI - 1] := Byte(Ord(AText[LI]));
  Result := ContainsBytes(ABytes, LNeedle);
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

function TTlsLibAlgorithmTestCase.CriticalExtensionsCertificate(const AName: string): TBytes;
var
  LFields: TStringList;
begin
  LFields := LoadVectorFields('Certs/CriticalExtensionsChain.txt');
  try
    Result := DecodeHex(LFields.Values[AName]);
  finally
    LFields.Free;
  end;
end;

function TTlsLibAlgorithmTestCase.WebPkiServer(const AStore: ITrustAnchorStore)
  : IServerVerification;
begin
  Result := TServerVerification.WebPki(AStore).Build;
end;

function TTlsLibAlgorithmTestCase.WebPkiServer(const AAnchorData: TBytes): IServerVerification;
begin
  Result := TServerVerification.WebPki(AAnchorData).Build;
end;

function TTlsLibAlgorithmTestCase.WebPkiClient(const AStore: ITrustAnchorStore)
  : IClientVerification;
begin
  Result := TClientVerification.WebPki(AStore).Build;
end;

function TTlsLibAlgorithmTestCase.WebPkiClient(const AAnchorData: TBytes): IClientVerification;
begin
  Result := TClientVerification.WebPki(AAnchorData).Build;
end;

end.
