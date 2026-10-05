{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlsTrustAnchorBenchmark;

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

interface

uses
  SysUtils,
  TlpICryptoProvider,
  TlpIPkixProvider,
  TlpICertificateTrust,
  TlpITrustAnchorStore,
  TlpTrustAnchorStore,
  TlpTrustTypes,
  TlpCertificateVerifier,
  BenchmarkCommon,
  TlsBenchmarkData;

type
  /// <summary>
  /// Times the trust-anchor share of a server-certificate verification: a warm verify against a
  /// store of one root, a large root bundle, and the union of the two (the shape the builder
  /// composes), the first verify against a store object the provider has not seen, and store
  /// construction. The gap between the bundle rows and the single-root row is the per-handshake
  /// anchor cost.
  /// </summary>
  TTlsTrustAnchorBenchmark = class sealed(TObject)
  strict private
  const
    BundleRoots = Int32(150);
    // one op = this many verifies, so the millisecond timer resolves a microsecond-scale verify
    VerifiesPerOp = Int32(100);
  var
    FPkix: IPkixProvider;
    FCredential: TTlsBenchmarkCredential;
    FChain: TArray<TBytes>;
    FBundle: TArray<TBytes>;
    FBundleStore: ITrustAnchorStore;
    FContentCounter: Int32;
    FCrypto: ICryptoProvider;
    FVerifier: IServerCertificateVerifier;
    procedure Verify;
    procedure VerifyBatch;
    procedure NewStoreVerify;
    procedure NewContentVerify;
    procedure ConstructBundle;
    procedure ConstructUnion;
    procedure CopyRoots;
    procedure HashRoots;
    procedure Arm(const AStore: ITrustAnchorStore);
    function MeasureWarm(const AStore: ITrustAnchorStore): Double;
    function UnionStore: ITrustAnchorStore;
    procedure BuildBundle;
  public
    constructor Create(const APkix: IPkixProvider);
    /// <summary>Runs the scenarios and returns the rendered table width.</summary>
    class function Run(ALogProc: TBenchmarkLogProc): Int32; static;
  end;

implementation

uses
  Classes,
  TlpIClock,
  TlpClock,
  TlpServerName,
  TlpTlsAlert,
  TlpCryptoDomainTypes,
  TlpDefaultCryptoProvider,
  TlpDefaultPkixProvider;

resourcestring
  SVerifyFailed = 'benchmark: the chain did not verify against the trust store';

{ TTlsTrustAnchorBenchmark }

constructor TTlsTrustAnchorBenchmark.Create(const APkix: IPkixProvider);
begin
  inherited Create;
  FPkix := APkix;
  FCrypto := TDefaultCryptoProvider.Create as ICryptoProvider;
  FCredential := TTlsBenchmarkData.LoadEcP256;
  FChain := TArray<TBytes>.Create(FCredential.LeafCertDer);
  BuildBundle;
  FBundleStore := TTrustAnchorStore.Create(FBundle) as ITrustAnchorStore;
end;

procedure TTlsTrustAnchorBenchmark.CopyRoots;
var
  LI: Int32;
  LRoots: TArray<TBytes>;
begin
  for LI := 1 to VerifiesPerOp do
    LRoots := FBundleStore.RootCertificates;
end;

procedure TTlsTrustAnchorBenchmark.HashRoots;
var
  LI, LJ: Int32;
  LHash: IHash;
  LDigest: TBytes;
begin
  for LI := 1 to VerifiesPerOp do
  begin
    LHash := FCrypto.Primitives.CreateHash(THashAlgorithm.SHA_256);
    for LJ := 0 to High(FBundle) do
      LHash.Update(FBundle[LJ], 0, Length(FBundle[LJ]));
    LDigest := LHash.DoFinal;
  end;
end;

procedure TTlsTrustAnchorBenchmark.BuildBundle;
var
  LRsa: TTlsBenchmarkCredential;
  LI: Int32;
begin
  // distinct roots that parse like real ones: the RSA root with its trailing signature byte varied
  LRsa := TTlsBenchmarkData.LoadRsa2048;
  SetLength(FBundle, BundleRoots);
  FBundle[0] := FCredential.RootCertDer;
  for LI := 1 to BundleRoots - 1 do
  begin
    FBundle[LI] := Copy(LRsa.RootCertDer);
    FBundle[LI][High(FBundle[LI])] := Byte(LI);
  end;
end;

procedure TTlsTrustAnchorBenchmark.Arm(const AStore: ITrustAnchorStore);
begin
  FVerifier := TCertificateVerifier.Create(FPkix, TSystemClock.Create as ITlsClock, AStore,
    False) as IServerCertificateVerifier;
end;

procedure TTlsTrustAnchorBenchmark.Verify;
var
  LVerified: TVerifiedChain;
  LAlert: TTlsAlertDescription;
begin
  if not FVerifier.VerifyServerCertificate(FChain, TServerName.DnsName(''), nil, LVerified,
    LAlert) then
    raise Exception.Create(SVerifyFailed);
end;

procedure TTlsTrustAnchorBenchmark.VerifyBatch;
var
  LI: Int32;
begin
  for LI := 1 to VerifiesPerOp do
    Verify;
end;

procedure TTlsTrustAnchorBenchmark.NewStoreVerify;
begin
  // a distinct store object over the same content, as a per-connection config build produces
  Arm(TTrustAnchorStore.Create(FBundle) as ITrustAnchorStore);
  Verify;
end;

procedure TTlsTrustAnchorBenchmark.NewContentVerify;
var
  LRoots: TArray<TBytes>;
begin
  // content the provider has never parsed: one filler root differs on every call
  LRoots := Copy(FBundle);
  LRoots[BundleRoots - 1] := Copy(LRoots[BundleRoots - 1]);
  Inc(FContentCounter);
  LRoots[BundleRoots - 1][High(LRoots[BundleRoots - 1])] := Byte(FContentCounter);
  LRoots[BundleRoots - 1][High(LRoots[BundleRoots - 1]) - 1] := Byte(FContentCounter shr 8);
  Arm(TTrustAnchorStore.Create(LRoots) as ITrustAnchorStore);
  Verify;
end;

procedure TTlsTrustAnchorBenchmark.ConstructBundle;
var
  LStore: ITrustAnchorStore;
begin
  LStore := TTrustAnchorStore.Create(FBundle) as ITrustAnchorStore;
end;

procedure TTlsTrustAnchorBenchmark.ConstructUnion;
var
  LStore: ITrustAnchorStore;
begin
  LStore := UnionStore;
end;

function TTlsTrustAnchorBenchmark.UnionStore: ITrustAnchorStore;
begin
  Result := TTrustAnchorStore.Union(TArray<ITrustAnchorStore>.Create(
    TTrustAnchorStore.Create(FBundle) as ITrustAnchorStore,
    TTrustAnchorStore.Create(TArray<TBytes>.Create(FCredential.RootCertDer))
    as ITrustAnchorStore));
end;

function TTlsTrustAnchorBenchmark.MeasureWarm(const AStore: ITrustAnchorStore): Double;
begin
  Arm(AStore);
  VerifyBatch; // parse and cache the anchors before timing
  Result := TBenchmarkTiming.MeasureMeanMillisecondsPerOp(VerifyBatch) / VerifiesPerOp;
end;

class function TTlsTrustAnchorBenchmark.Run(ALogProc: TBenchmarkLogProc): Int32;
var
  LBench: TTlsTrustAnchorBenchmark;
  LOne, LBundle, LUnion, LNew, LFresh, LCtorBundle, LCtorUnion, LCopy, LHash: Double;

  function Micros(AMs: Double): String;
  begin
    Result := Format('%12.1f us', [AMs * 1000.0]);
  end;

begin
  LBench := TTlsTrustAnchorBenchmark.Create(TDefaultPkixProvider.Create as IPkixProvider);
  try
    LOne := LBench.MeasureWarm(TTrustAnchorStore.Create(
      TArray<TBytes>.Create(LBench.FCredential.RootCertDer)) as ITrustAnchorStore);
    LBundle := LBench.MeasureWarm(TTrustAnchorStore.Create(LBench.FBundle) as ITrustAnchorStore);
    LUnion := LBench.MeasureWarm(LBench.UnionStore);
    LNew := TBenchmarkTiming.MeasureMeanMillisecondsPerOp(LBench.NewStoreVerify);
    LFresh := TBenchmarkTiming.MeasureMeanMillisecondsPerOp(LBench.NewContentVerify);
    LCtorBundle := TBenchmarkTiming.MeasureMeanMillisecondsPerOp(LBench.ConstructBundle);
    LCtorUnion := TBenchmarkTiming.MeasureMeanMillisecondsPerOp(LBench.ConstructUnion);
    LCopy := TBenchmarkTiming.MeasureMeanMillisecondsPerOp(LBench.CopyRoots) / VerifiesPerOp;
    LHash := TBenchmarkTiming.MeasureMeanMillisecondsPerOp(LBench.HashRoots) / VerifiesPerOp;
  finally
    LBench.Free;
  end;
  ALogProc('Trust-anchor cost (server certificate verification, EC P-256 leaf)');
  ALogProc('  warm verify, 1 root              ' + Micros(LOne));
  ALogProc(Format('  warm verify, %d-root bundle      ', [BundleRoots]) + Micros(LBundle));
  ALogProc(Format('  warm verify, union (%d + 1)     ', [BundleRoots]) + Micros(LUnion));
  ALogProc('  anchor cost, bundle              ' + Micros(LBundle - LOne));
  ALogProc('  anchor cost, union               ' + Micros(LUnion - LOne));
  ALogProc('  first verify, new store object   ' + Micros(LNew));
  ALogProc('  first verify, unseen content     ' + Micros(LFresh));
  ALogProc('  construct bundle store           ' + Micros(LCtorBundle));
  ALogProc('  construct union store            ' + Micros(LCtorUnion));
  ALogProc('  isolated: copy the roots         ' + Micros(LCopy));
  ALogProc('  isolated: hash the roots         ' + Micros(LHash));
  Result := 60;
end;

end.
