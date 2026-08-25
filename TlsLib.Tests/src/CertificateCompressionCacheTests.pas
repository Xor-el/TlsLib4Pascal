{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit CertificateCompressionCacheTests;

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
  TlpIClock,
  TlpClock,
  TlpICryptoProvider,
  TlpNamedGroups,
  TlpNegotiationTypes,
  TlpNegotiationPolicy,
  TlpCipherSuiteRegistry,
  TlpCoreExtensions,
  TlpIHandshakeMachine,
  TlpHandshakeEffect,
  TlpHandshakeMessage,
  TlpHandshakeMessages,
  TlpICertificateTrust,
  TlpCertificateVerifier,
  TlpTlsCredential,
  TlpCredentialResolvers,
  TlpCertificateCompression,
  TlpICertificateCompression,
  TlpICertificateCompressionCache,
  TlpZlibCertificateCompression,
  TlpInMemoryCertificateCompressionCache,
  TlpTls13ClientStateMachine,
  TlpTls13ServerStateMachine,
  TlsLibTestBase;

type
  TTestCertificateCompressionCache = class(TTlsLibAlgorithmTestCase)
  private
    function ByteBlob(AValue: Byte; ALength: Int32): TBytes;
    function ZlibCompressor: ICertificateCompressor;
    function DirectCompress(const ABody: TBytes): TBytes;
    // low-level machine scaffold for the end-to-end loopback proof
    function TestRootCertificate: TBytes;
    function ServerCredential: TTlsCredential;
    function CredentialWithChain(const AChain: TArray<TBytes>): TTlsCredential;
    function CompressibleChain(AValue: Byte): TArray<TBytes>;
    function NewClientMachine: IHandshakeMachine;
    function NewServerMachine(const AChain: TArray<TBytes>;
      const ACompressors: TArray<ICertificateCompressor>;
      const ACache: ICertificateCompressionCache): IHandshakeMachine;
    function ServerCertMessage(const AChain: TArray<TBytes>;
      const ACompressors: TArray<ICertificateCompressor>;
      const ACache: ICertificateCompressionCache): TTlsHandshakeMessage;
    function PlaintextCertBody(const AChain: TArray<TBytes>): TBytes;
    function MsgFrom(const AFramed: TBytes): TTlsHandshakeMessage;
    function FirstSendHandshake(const AEffects: TArray<THandshakeEffect>): TBytes;
    function AllSendHandshake(const AEffects: TArray<THandshakeEffect>): TArray<TBytes>;
  published
    // cache unit
    procedure TestMissThenPutThenHit;
    procedure TestBoundedEvictionDropsOldest;
    procedure TestCompactionPreservesLiveEntriesUnderChurn;
    procedure TestConcurrentPutAndGetSmoke;
    // policy (CompressWithCache)
    procedure TestCacheHitAndMissEqualDirectCompress;
    procedure TestComputesOncePerBody;
    procedure TestRecomputesWhenBodyChanges;
    procedure TestNilCacheEqualsDirect;
    // end-to-end loopback
    procedure TestLoopbackWireIdenticalAndSingleCompress;
    procedure TestLoopbackBodyChangeRecomputesBothWireCorrect;
  end;

implementation

type
  /// <summary>A zlib compressor that tallies its Compress calls, so a test can prove the
  /// cache computes a given body exactly once.</summary>
  TSpyCompressor = class sealed(TInterfacedObject, ICertificateCompressor)
  strict private
  var
    FInner: ICertificateCompressor;
    FCount: Int32;
  public
    constructor Create;
    function Algorithm: UInt16;
    function Compress(const AData: TBytes): TBytes;
    property Count: Int32 read FCount;
  end;

  /// <summary>Hammers one shared cache from a background thread to smoke-test the lock.</summary>
  TCacheStressThread = class sealed(TThread)
  strict private
  var
    FCache: ICertificateCompressionCache;
    FBase: Byte;
    FOps: Int32;
  public
    Failure: string;
    constructor Create(const ACache: ICertificateCompressionCache; ABase: Byte; AOps: Int32);
    procedure Execute; override;
  end;

{ TSpyCompressor }

constructor TSpyCompressor.Create;
begin
  inherited Create;
  FInner := TZlibCertificateCompression.DefaultCompressors[0];
  FCount := 0;
end;

function TSpyCompressor.Algorithm: UInt16;
begin
  Result := FInner.Algorithm;
end;

function TSpyCompressor.Compress(const AData: TBytes): TBytes;
begin
  Inc(FCount);
  Result := FInner.Compress(AData);
end;

{ TCacheStressThread }

constructor TCacheStressThread.Create(const ACache: ICertificateCompressionCache;
  ABase: Byte; AOps: Int32);
begin
  inherited Create(True);
  FreeOnTerminate := False;
  FCache := ACache;
  FBase := ABase;
  FOps := AOps;
end;

procedure TCacheStressThread.Execute;
var
  LI: Int32;
  LKey, LValue, LGot: TBytes;
begin
  Failure := '';
  try
    for LI := 0 to FOps - 1 do
    begin
      LKey := TBytes.Create(FBase, Byte(LI), Byte(LI shr 8), Byte(LI shr 16));
      LValue := TBytes.Create(FBase, Byte(LI));
      FCache.Put(LKey, LValue);
      FCache.TryGet(LKey, LGot);
    end;
  except
    on E: Exception do
      Failure := E.ClassName + ': ' + E.Message;
  end;
end;

{ TTestCertificateCompressionCache }

function TTestCertificateCompressionCache.ByteBlob(AValue: Byte; ALength: Int32): TBytes;
begin
  Result := nil;
  SetLength(Result, ALength);
  if ALength > 0 then
    FillChar(Result[0], ALength, AValue);
end;

function TTestCertificateCompressionCache.ZlibCompressor: ICertificateCompressor;
begin
  Result := TZlibCertificateCompression.DefaultCompressors[0];
end;

function TTestCertificateCompressionCache.DirectCompress(const ABody: TBytes): TBytes;
begin
  Result := ZlibCompressor.Compress(ABody);
end;

procedure TTestCertificateCompressionCache.TestMissThenPutThenHit;
var
  LCache: ICertificateCompressionCache;
  LKey, LValue, LGot: TBytes;
begin
  LCache := TInMemoryCertificateCompressionCache.Create;
  LKey := ByteBlob($11, 32);
  LValue := ByteBlob($AB, 100);
  CheckFalse(LCache.TryGet(LKey, LGot), 'an unknown key misses');
  LCache.Put(LKey, LValue);
  CheckTrue(LCache.TryGet(LKey, LGot), 'a stored key hits');
  CheckEqualBytes('the stored bytes come back unchanged', LValue, LGot);
  CheckEquals(1, LCache.Count, 'one entry is held');
end;

procedure TTestCertificateCompressionCache.TestBoundedEvictionDropsOldest;
var
  LCache: ICertificateCompressionCache;
  LK1, LK2, LK3, LGot: TBytes;
begin
  LCache := TInMemoryCertificateCompressionCache.Create(2);
  LK1 := ByteBlob($01, 32);
  LK2 := ByteBlob($02, 32);
  LK3 := ByteBlob($03, 32);
  LCache.Put(LK1, ByteBlob($A1, 8));
  LCache.Put(LK2, ByteBlob($A2, 8));
  LCache.Put(LK3, ByteBlob($A3, 8)); // pushes the cap; oldest (LK1) is evicted
  CheckEquals(2, LCache.Count, 'the cache never grows past its cap');
  CheckFalse(LCache.TryGet(LK1, LGot), 'the oldest entry was evicted');
  CheckTrue(LCache.TryGet(LK2, LGot), 'a newer entry survives');
  CheckTrue(LCache.TryGet(LK3, LGot), 'the newest entry survives');
end;

procedure TTestCertificateCompressionCache.TestCompactionPreservesLiveEntriesUnderChurn;
var
  LCache: ICertificateCompressionCache;
  LLive: array [0 .. 4] of TBytes;
  LChurn, LGot: TBytes;
  LI: Int32;
begin
  // overwrite one throwaway key far more often than the cap: FByKey stays small so eviction
  // rarely fires and the order structure must be compacted instead of growing without bound.
  // Compaction must leave the long-lived entries intact.
  LCache := TInMemoryCertificateCompressionCache.Create(8);
  for LI := 0 to 4 do
  begin
    LLive[LI] := ByteBlob(Byte($A0 + LI), 32);
    LCache.Put(LLive[LI], ByteBlob(Byte($A0 + LI), 16));
  end;
  LChurn := ByteBlob($55, 32);
  for LI := 0 to 999 do
    LCache.Put(LChurn, ByteBlob(Byte(LI), 4));
  for LI := 0 to 4 do
  begin
    CheckTrue(LCache.TryGet(LLive[LI], LGot), 'a live entry survives repeated compaction');
    CheckEqualBytes('with its bytes intact', ByteBlob(Byte($A0 + LI), 16), LGot);
  end;
  CheckTrue(LCache.TryGet(LChurn, LGot), 'the churned key holds its latest value');
  CheckEqualBytes('the last write wins', ByteBlob(999 and $FF, 4), LGot);
  CheckEquals(6, LCache.Count, 'only the live and churn entries remain');
end;

procedure TTestCertificateCompressionCache.TestConcurrentPutAndGetSmoke;
var
  LCache: ICertificateCompressionCache;
  LThreads: array [0 .. 3] of TCacheStressThread;
  LI: Int32;
begin
  LCache := TInMemoryCertificateCompressionCache.Create(64);
  for LI := 0 to High(LThreads) do
    LThreads[LI] := TCacheStressThread.Create(LCache, Byte($10 + LI), 3000);
  try
    for LI := 0 to High(LThreads) do
      LThreads[LI].Start;
    for LI := 0 to High(LThreads) do
      LThreads[LI].WaitFor;
    for LI := 0 to High(LThreads) do
      CheckEquals('', LThreads[LI].Failure, 'no thread saw corruption');
    CheckTrue(LCache.Count <= 64, 'the cache stays bounded under concurrency');
  finally
    for LI := 0 to High(LThreads) do
      LThreads[LI].Free;
  end;
end;

procedure TTestCertificateCompressionCache.TestCacheHitAndMissEqualDirectCompress;
var
  LCache: ICertificateCompressionCache;
  LBody, LDirect, LMiss, LHit: TBytes;
begin
  LCache := TInMemoryCertificateCompressionCache.Create;
  LBody := ByteBlob($3C, 2048);
  LDirect := DirectCompress(LBody);
  // first call is a miss (computes + stores); second is a hit (returns the stored bytes)
  LMiss := TCertificateCompression.CompressWithCache(LCache, Provider, ZlibCompressor, LBody);
  LHit := TCertificateCompression.CompressWithCache(LCache, Provider, ZlibCompressor, LBody);
  CheckEqualBytes('a miss equals a direct Compress', LDirect, LMiss);
  CheckEqualBytes('a hit equals a direct Compress', LDirect, LHit);
end;

procedure TTestCertificateCompressionCache.TestComputesOncePerBody;
var
  LCache: ICertificateCompressionCache;
  LSpy: TSpyCompressor;
  LSpyRef: ICertificateCompressor;
  LBody, LFirst, LSecond: TBytes;
begin
  LCache := TInMemoryCertificateCompressionCache.Create;
  LSpy := TSpyCompressor.Create;
  LSpyRef := LSpy; // the interface reference governs lifetime; read Count off the object
  LBody := ByteBlob($77, 4096);
  LFirst := TCertificateCompression.CompressWithCache(LCache, Provider, LSpyRef, LBody);
  LSecond := TCertificateCompression.CompressWithCache(LCache, Provider, LSpyRef, LBody);
  CheckEquals(1, LSpy.Count, 'the same body is compressed exactly once');
  CheckEqualBytes('both calls return the same bytes', LFirst, LSecond);
end;

procedure TTestCertificateCompressionCache.TestRecomputesWhenBodyChanges;
var
  LCache: ICertificateCompressionCache;
  LSpy: TSpyCompressor;
  LSpyRef: ICertificateCompressor;
  LBodyA, LBodyB, LOutA, LOutB: TBytes;
begin
  LCache := TInMemoryCertificateCompressionCache.Create;
  LSpy := TSpyCompressor.Create;
  LSpyRef := LSpy;
  LBodyA := ByteBlob($10, 2048);
  // a changed leaf staple changes the exact bytes handed to Compress, so the key differs
  LBodyB := ByteBlob($10, 2049);
  LOutA := TCertificateCompression.CompressWithCache(LCache, Provider, LSpyRef, LBodyA);
  TCertificateCompression.CompressWithCache(LCache, Provider, LSpyRef, LBodyA); // hit
  LOutB := TCertificateCompression.CompressWithCache(LCache, Provider, LSpyRef, LBodyB);
  CheckEquals(2, LSpy.Count, 'a distinct body forces a recompute; a repeat does not');
  CheckEqualBytes('body A stays byte-correct', DirectCompress(LBodyA), LOutA);
  CheckEqualBytes('body B stays byte-correct', DirectCompress(LBodyB), LOutB);
end;

procedure TTestCertificateCompressionCache.TestNilCacheEqualsDirect;
var
  LBody, LOut: TBytes;
begin
  LBody := ByteBlob($5A, 1024);
  LOut := TCertificateCompression.CompressWithCache(nil, Provider, ZlibCompressor, LBody);
  CheckEqualBytes('a nil cache compresses directly', DirectCompress(LBody), LOut);
end;

function TTestCertificateCompressionCache.TestRootCertificate: TBytes;
var
  LCerts: TStringList;
begin
  LCerts := LoadVectorFields('Certs/EcP256Chain.txt');
  try
    Result := DecodeHex(LCerts.Values['root_cert']);
  finally
    LCerts.Free;
  end;
end;

function TTestCertificateCompressionCache.ServerCredential: TTlsCredential;
var
  LCerts: TStringList;
begin
  LCerts := LoadVectorFields('Certs/EcP256Chain.txt');
  try
    Result.CertificateChain := TArray<TBytes>.Create(
      DecodeHex(LCerts.Values['leaf_cert']));
    Result.PrivateKey := Provider.Signing.ImportSigningKey(DecodeHex(LCerts.Values['leaf_key']));
  finally
    LCerts.Free;
  end;
end;

function TTestCertificateCompressionCache.CredentialWithChain(
  const AChain: TArray<TBytes>): TTlsCredential;
begin
  // keep the real signing key, swap the certificate chain the Certificate carries
  Result := ServerCredential;
  Result.CertificateChain := AChain;
end;

function TTestCertificateCompressionCache.CompressibleChain(AValue: Byte): TArray<TBytes>;
var
  LData: TBytes;
  LI: Int32;
begin
  // a full-byte permutation repeated many times: it deflates well yet stays well under the
  // decompression-bomb ratio; AValue seeds a distinct-but-still-compressible body
  LData := nil;
  SetLength(LData, 4096);
  for LI := 0 to System.Length(LData) - 1 do
    LData[LI] := Byte((LI * 31 + 7 + AValue) and $FF);
  Result := TArray<TBytes>.Create(LData);
end;

function TTestCertificateCompressionCache.NewClientMachine: IHandshakeMachine;
var
  LParams: TClientHandshakeParams;
begin
  LParams := Default(TClientHandshakeParams);
  LParams.Clock := TSystemClock.Create;
  LParams.Provider := Provider;
  LParams.Group := TNamedGroups.CreateX25519(Provider);
  LParams.GroupCode := TNamedGroupCatalog.X25519;
  LParams.CipherSuites := TCipherSuiteRegistry.CreateDefault(Provider);
  LParams.ExtensionRegistry := TCoreExtensions.CreateDefaultRegistry;
  LParams.OfferedSuites := TArray<UInt16>.Create(TCipherSuites13.Aes128GcmSha256);
  LParams.OfferedSchemes := TArray<UInt16>.Create(TSignatureSchemes.EcdsaSecp256r1Sha256);
  LParams.ClientRandom := DecodeHex(StringOfChar('1', 64));
  LParams.LegacySessionId := DecodeHex(StringOfChar('3', 64));
  LParams.CertificateVerifier := TCertificateVerifier.Create(Provider,
    TSystemClock.Create as ITlsClock,
    TTrustAnchorStore.Create(TArray<TBytes>.Create(TestRootCertificate)) as ITrustAnchorStore,
    True) as ICertificateVerifier;
  // the client advertises the built-in zlib decompressor, so the server may compress
  LParams.CertificateDecompressors := TZlibCertificateCompression.DefaultDecompressors;
  LParams.ExpectedHostName := 'localhost';
  Result := TTls13ClientStateMachine.Create(LParams) as IHandshakeMachine;
end;

function TTestCertificateCompressionCache.NewServerMachine(
  const AChain: TArray<TBytes>;
  const ACompressors: TArray<ICertificateCompressor>;
  const ACache: ICertificateCompressionCache): IHandshakeMachine;
var
  LParams: TServerHandshakeParams;
begin
  LParams := Default(TServerHandshakeParams);
  LParams.Clock := TSystemClock.Create;
  LParams.Provider := Provider;
  LParams.Policy := TNegotiationPolicy.CreateDefault(Provider);
  LParams.CipherSuites := TCipherSuiteRegistry.CreateDefault(Provider);
  LParams.ExtensionRegistry := TCoreExtensions.CreateDefaultRegistry;
  LParams.Group := TNamedGroups.CreateX25519(Provider);
  LParams.ServerRandom := DecodeHex(StringOfChar('2', 64));
  LParams.CertificateCompressors := ACompressors;
  LParams.CertificateCompressionCache := ACache;
  LParams.CredentialResolver := TSniCredentialResolver.ForCredential(CredentialWithChain(AChain));
  Result := TTls13ServerStateMachine.Create(LParams) as IHandshakeMachine;
end;

function TTestCertificateCompressionCache.ServerCertMessage(
  const AChain: TArray<TBytes>;
  const ACompressors: TArray<ICertificateCompressor>;
  const ACache: ICertificateCompressionCache): TTlsHandshakeMessage;
var
  LClient, LServer: IHandshakeMachine;
  LFlight: TArray<TBytes>;
begin
  LClient := NewClientMachine;
  LServer := NewServerMachine(AChain, ACompressors, ACache);
  // the encrypted flight is [ServerHello, EncryptedExtensions, Certificate, ...]
  LFlight := AllSendHandshake(LServer.ProcessMessage(MsgFrom(
    FirstSendHandshake(LClient.Start))));
  Result := MsgFrom(LFlight[2]);
end;

function TTestCertificateCompressionCache.PlaintextCertBody(
  const AChain: TArray<TBytes>): TBytes;
begin
  // a server with no compressors always sends the uncompressed Certificate body
  Result := ServerCertMessage(AChain, nil, nil).Body;
end;

function TTestCertificateCompressionCache.MsgFrom(
  const AFramed: TBytes): TTlsHandshakeMessage;
var
  LReader: THandshakeMessageReader;
begin
  LReader := THandshakeMessageReader.Create;
  try
    LReader.Append(AFramed, 0, System.Length(AFramed));
    LReader.NextMessage(Result);
  finally
    LReader.Free;
  end;
end;

function TTestCertificateCompressionCache.FirstSendHandshake(
  const AEffects: TArray<THandshakeEffect>): TBytes;
var
  LEffect: THandshakeEffect;
begin
  Result := nil;
  for LEffect in AEffects do
    if LEffect.Kind = THandshakeEffectKind.SendHandshake then
      Exit(LEffect.Bytes);
end;

function TTestCertificateCompressionCache.AllSendHandshake(
  const AEffects: TArray<THandshakeEffect>): TArray<TBytes>;
var
  LEffect: THandshakeEffect;
  LCount: Int32;
begin
  Result := nil;
  LCount := 0;
  for LEffect in AEffects do
    if LEffect.Kind = THandshakeEffectKind.SendHandshake then
    begin
      SetLength(Result, LCount + 1);
      Result[LCount] := LEffect.Bytes;
      Inc(LCount);
    end;
end;

procedure TTestCertificateCompressionCache.TestLoopbackWireIdenticalAndSingleCompress;
var
  LCache: ICertificateCompressionCache;
  LSpy: TSpyCompressor;
  LCompressors: TArray<ICertificateCompressor>;
  LChain: TArray<TBytes>;
  LMsg1, LMsg2: TTlsHandshakeMessage;
  LDecoded: TTlsCompressedCertificate;
  LRecovered: TBytes;
begin
  // one shared cache and one spy compressor across two independent server handshakes
  LCache := TInMemoryCertificateCompressionCache.Create;
  LSpy := TSpyCompressor.Create;
  LCompressors := TArray<ICertificateCompressor>.Create(LSpy as ICertificateCompressor);
  LChain := CompressibleChain(0);

  LMsg1 := ServerCertMessage(LChain, LCompressors, LCache);
  LMsg2 := ServerCertMessage(LChain, LCompressors, LCache);

  CheckTrue(LMsg1.TypeByte = Byte(Ord(TTlsHandshakeType.CompressedCertificate)),
    'the first handshake emits a CompressedCertificate');
  CheckTrue(LMsg2.TypeByte = Byte(Ord(TTlsHandshakeType.CompressedCertificate)),
    'the second handshake emits a CompressedCertificate');
  CheckEqualBytes('the cached handshake reproduces the exact wire bytes',
    LMsg1.Body, LMsg2.Body);
  CheckEquals(1, LSpy.Count, 'a stable certificate is deflated once across two handshakes');

  // the receiver decompresses the emitted body back to the plaintext Certificate
  LDecoded := THandshakeMessages.DecodeCompressedCertificate(LMsg2.Body);
  LRecovered := TCertificateCompression.Decompress(
    TZlibCertificateCompression.DefaultDecompressors, LDecoded.Algorithm,
    LDecoded.Compressed, LDecoded.UncompressedLength);
  CheckEqualBytes('the cached body decompresses to the plaintext Certificate',
    PlaintextCertBody(LChain), LRecovered);
end;

procedure TTestCertificateCompressionCache.TestLoopbackBodyChangeRecomputesBothWireCorrect;
var
  LCache: ICertificateCompressionCache;
  LSpy: TSpyCompressor;
  LCompressors: TArray<ICertificateCompressor>;
  LChainA, LChainB: TArray<TBytes>;
  LMsgA, LMsgB: TTlsHandshakeMessage;
  LDecodedA, LDecodedB: TTlsCompressedCertificate;
begin
  LCache := TInMemoryCertificateCompressionCache.Create;
  LSpy := TSpyCompressor.Create;
  LCompressors := TArray<ICertificateCompressor>.Create(LSpy as ICertificateCompressor);
  LChainA := CompressibleChain(0);
  LChainB := CompressibleChain(1); // a different Certificate body (staple/chain change)

  LMsgA := ServerCertMessage(LChainA, LCompressors, LCache);
  ServerCertMessage(LChainA, LCompressors, LCache); // repeat A -> cache hit, no recompute
  LMsgB := ServerCertMessage(LChainB, LCompressors, LCache);

  CheckEquals(2, LSpy.Count, 'a changed body recomputes; a repeat of A does not');

  LDecodedA := THandshakeMessages.DecodeCompressedCertificate(LMsgA.Body);
  CheckEqualBytes('body A decompresses to its plaintext Certificate',
    PlaintextCertBody(LChainA), TCertificateCompression.Decompress(
    TZlibCertificateCompression.DefaultDecompressors, LDecodedA.Algorithm,
    LDecodedA.Compressed, LDecodedA.UncompressedLength));
  LDecodedB := THandshakeMessages.DecodeCompressedCertificate(LMsgB.Body);
  CheckEqualBytes('body B decompresses to its plaintext Certificate',
    PlaintextCertBody(LChainB), TCertificateCompression.Decompress(
    TZlibCertificateCompression.DefaultDecompressors, LDecodedB.Algorithm,
    LDecodedB.Compressed, LDecodedB.UncompressedLength));
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestCertificateCompressionCache);
{$ELSE}
  RegisterTest(TTestCertificateCompressionCache.Suite);
{$ENDIF FPC}

end.
