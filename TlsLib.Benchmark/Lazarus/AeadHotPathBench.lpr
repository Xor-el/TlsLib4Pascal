program AeadHotPathBench;

{$MODE DELPHI}
{$APPTYPE CONSOLE}

// Throughput harness for the AEAD record hot-path: seals many TLS-sized (~1.4 KB)
// records through ONE reused adapter ("after") versus a fresh create-per-record
// adapter ("before"), for each AEAD suite, and reports MB/s + speedup.

uses
  SysUtils,
  Classes,
  TlpICryptoProvider,
  TlpCryptoDomainTypes,
  TlpISecretBuffer,
  TlpSecretBuffer,
  TlpDefaultCryptoProvider;

const
  CRecordSize = 1400;  // a typical TLS 1.3 application record payload
  CRecords    = 100000;
  CAadSize    = 5;     // TLS 1.3 record header additional-data length

function MakeBytes(ALen, ASeed: Int32): TBytes;
var
  LI: Int32;
begin
  Result := nil;
  SetLength(Result, ALen);
  for LI := 0 to ALen - 1 do
    Result[LI] := Byte((LI * 31 + ASeed * 17 + 7) and $FF);
end;

procedure SetNonce(var ANonce: TBytes; AIndex: Int32);
begin
  // monotonic, distinct nonce per record (the record layer's sequence guarantee)
  ANonce[System.Length(ANonce) - 1] := Byte(AIndex and $FF);
  ANonce[System.Length(ANonce) - 2] := Byte((AIndex shr 8) and $FF);
  ANonce[System.Length(ANonce) - 3] := Byte((AIndex shr 16) and $FF);
  ANonce[System.Length(ANonce) - 4] := Byte((AIndex shr 24) and $FF);
end;

procedure Report(const ALabel: string; AElapsedMs: UInt32);
var
  LSeconds, LMBps, LRecsPerSec: Double;
begin
  if AElapsedMs = 0 then
    AElapsedMs := 1;
  LSeconds := AElapsedMs / 1000.0;
  LMBps := (Int64(CRecords) * CRecordSize) / (1024.0 * 1024.0) / LSeconds;
  LRecsPerSec := CRecords / LSeconds;
  WriteLn(Format('  %-26s %7d ms   %9.1f MB/s   %12.0f rec/s',
    [ALabel, AElapsedMs, LMBps, LRecsPerSec]));
end;

procedure BenchAlgorithm(const AProvider: ICryptoProvider;
  AAlgorithm: TAeadAlgorithm; AKeySize: Int32; const AName: string);
var
  LReused, LFresh: IAead;
  LKey: ISecretBuffer;
  LNonce, LAad, LPlain, LSealed: TBytes;
  LI: Int32;
  LStart, LReuseMs, LPerRecMs: UInt32;
begin
  LKey := TSecretBuffer.From(MakeBytes(AKeySize, 1));
  LPlain := MakeBytes(CRecordSize, 2);
  LAad := MakeBytes(CAadSize, 3);
  LReused := AProvider.Primitives.CreateAead(AAlgorithm);
  LReused.Init(LKey);
  LNonce := nil;
  SetLength(LNonce, LReused.NonceSize);
  LSealed := nil;
  SetLength(LSealed, CRecordSize + LReused.TagSize);
  FillChar(LNonce[0], System.Length(LNonce), 0);

  // after: one keyed adapter reused for every record; both loops reuse the same key and nonces,
  // which a real sender must never do
  LStart := TThread.GetTickCount;
  for LI := 0 to CRecords - 1 do
  begin
    SetNonce(LNonce, LI);
    LReused.Seal(LNonce, LAad, LPlain, 0, CRecordSize, LSealed, 0);
  end;
  LReuseMs := TThread.GetTickCount - LStart;

  // before: a brand-new adapter created and keyed for every record
  LStart := TThread.GetTickCount;
  for LI := 0 to CRecords - 1 do
  begin
    SetNonce(LNonce, LI);
    LFresh := AProvider.Primitives.CreateAead(AAlgorithm);
    LFresh.Init(LKey);
    LFresh.Seal(LNonce, LAad, LPlain, 0, CRecordSize, LSealed, 0);
  end;
  LPerRecMs := TThread.GetTickCount - LStart;

  WriteLn(AName, ':');
  Report('after  (reuse cipher)', LReuseMs);
  Report('before (per-record)', LPerRecMs);
  if LReuseMs > 0 then
    WriteLn(Format('  speedup: %.2fx', [LPerRecMs / LReuseMs]));
  WriteLn;
  if System.Length(LSealed) = 0 then  // keep LSealed live
    WriteLn('(unreachable)');
end;

function PlatformInfo: string;
var
  LOS, LCPU: string;
begin
{$IF DEFINED(MSWINDOWS)}
  LOS := 'Windows';
{$ELSEIF DEFINED(LINUX)}
  LOS := 'Linux';
{$ELSEIF DEFINED(DARWIN)}
  LOS := 'macOS';
{$ELSE}
  LOS := 'Unknown OS';
{$ENDIF}
{$IF DEFINED(CPUX86_64)}
  LCPU := 'x86_64';
{$ELSEIF DEFINED(CPUI386)}
  LCPU := 'i386';
{$ELSEIF DEFINED(CPUAARCH64)}
  LCPU := 'AArch64';
{$ELSE}
  LCPU := 'Unknown CPU';
{$ENDIF}
  Result := Format('%s %s, FPC %s', [LOS, LCPU, {$I %FPCVERSION%}]);
end;

var
  LProvider: ICryptoProvider;
begin
  LProvider := TDefaultCryptoProvider.Create;
  WriteLn('AEAD hot-path benchmark');
  WriteLn('Platform: ', PlatformInfo);
  WriteLn(Format('records=%d  record-size=%d bytes  HasHardwareAes=%s',
    [CRecords, CRecordSize, BoolToStr(LProvider.Primitives.HasHardwareAes, True)]));
  WriteLn;
  BenchAlgorithm(LProvider, TAeadAlgorithm.AES_128_GCM, 16, 'AES-128-GCM');
  BenchAlgorithm(LProvider, TAeadAlgorithm.AES_256_GCM, 32, 'AES-256-GCM');
  BenchAlgorithm(LProvider, TAeadAlgorithm.CHACHA20_POLY1305, 32, 'ChaCha20-Poly1305');
end.
