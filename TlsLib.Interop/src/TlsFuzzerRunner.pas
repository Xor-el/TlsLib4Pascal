{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlsFuzzerRunner;

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}
{$SCOPEDENUMS ON}

interface

uses
  SysUtils,
  Classes,
  SyncObjs,
  Math,
  TlpTlsLibExceptions,
  TlpICryptoProvider,
  TlpITlsEngine,
  TlpHandshakeMessage,
  TlpHandshakeMessages,
  TlpRecordLayer,
  TlpCertificateCompression,
  TlpZlibCertificateCompression,
  TlpICertificateCompression,
  TlpEchConfig,
  TlpEchExtension,
  TlpEchOuterExtensions,
  InteropEngine,
  InteropCredentials,
  InteropUtils;

type
  /// <summary>Invoked when a fuzz iteration outlives the watchdog timeout (a suspected
  /// parser hang). The default handler emits the reproducer and halts; a self-test can
  /// substitute one that only records that it fired.</summary>
  IFuzzHangHandler = interface
    ['{7B1C2D3E-4F50-4A61-8B72-9C0D1E2F3A4B}']
    procedure HandleHang(const AInput: TBytes; AIteration: Int32);
  end;

  /// <summary>One background thread that fires the handler if an armed interval outlives
  /// the timeout. The loop calls Arm before the guarded work and Disarm after, so a
  /// normal iteration never triggers it.</summary>
  TFuzzWatchdog = class sealed(TThread)
  strict private
    FLock: TCriticalSection;
    FWake: TEvent;
    FArmed: Boolean;
    FDeadline: UInt64;
    FInput: TBytes;
    FIteration: Int32;
    FTimeoutMs: UInt64;
    FHandler: IFuzzHangHandler;
  protected
    procedure Execute; override;
  public
    constructor Create(ATimeoutMs: UInt64; const AHandler: IFuzzHangHandler);
    destructor Destroy; override;
    /// <summary>Starts the timeout window for AInput; the handler fires if Disarm does
    /// not arrive within the timeout.</summary>
    procedure Arm(const AInput: TBytes; AIteration: Int32);
    procedure Disarm;
  end;

  /// <summary>One target per parser surface: record + handshake framing, every
  /// handshake-message decoder, the cert-compression bomb defense, and two engine feeds
  /// that reach the extension parser + key_share / pre_shared_key + PSK-binder.</summary>
  TFuzzTarget = (
    RecordLayer,
    HandshakeReader,
    ClientHello,
    ServerHello,
    EncryptedExtensions,
    Certificate13,
    CertificateVerify,
    CompressedCertParse,
    CompressedCertBomb,
    Finished,
    NewSessionTicket13,
    NewSessionTicket12,
    CertRequest13,
    CertRequest12,
    Certificate12,
    ServerKeyExchange,
    ClientKeyExchange,
    CertificateStatus,
    LeafStaple,
    EchConfigListParse,
    EchExtensionDecode,
    EchOuterExtensionsParse,
    EngineServer,
    EngineClient);

  /// <summary>Structure-aware mutation fuzzer: each target seeds from a canonical valid
  /// message (+ corpora), mutates it, and feeds that parser. Oracle: a clean outcome or a
  /// typed EBaseTlsLibException, never a crash/hang. Per-push = regression replay +
  /// fixed-seed smoke; discovery persists new crashers.</summary>
  TTlsFuzzerRunner = class sealed(TObject)
  strict private
  class var
    FProvider: ICryptoProvider;
    FCredentialFile: string;
    FRootFile: string;
    FCorpusDir: string;
    FRegressDir: string;
    FFailuresDir: string;
    FTargetSeeds: array[TFuzzTarget] of TArray<TBytes>;
    class function Rnd(ABound: Int32): Int32; static;
    class function Filler(ALength: Int32; AByte: Byte): TBytes; static;
    class function PlaintextRecord(AContentType: Byte;
      const APayload: TBytes): TBytes; static;
    class function CaptureClientHelloFlight: TBytes; static;
    class function StripToHandshakeBody(const AFlight: TBytes): TBytes; static;
    class function CanonicalSeed(ATarget: TFuzzTarget): TBytes; static;
    class procedure LoadSeeds; static;
    class procedure AppendSeed(var ADest: TArray<TBytes>; const ASeed: TBytes); static;
    class procedure AppendSeeds(var ADest: TArray<TBytes>;
      const ASource: TArray<TBytes>); static;
    class function LoadDirBlobs(const ADir: string): TArray<TBytes>; static;
    class function Mutate(const ASeed: TBytes): TBytes; static;
    class procedure BuildServerEngine(out AEngine: ITlsEngine); static;
    class procedure BuildClientEngine(out AEngine: ITlsEngine); static;
    class procedure DrainEngine(const AEngine: ITlsEngine); static;
    class function Exercise(ATarget: TFuzzTarget; const AInput: TBytes;
      out ADetail: string): Boolean; static;
    class function TargetName(ATarget: TFuzzTarget): string; static;
    class procedure EmitFinding(ATarget: TFuzzTarget; const AInput: TBytes;
      const ATag, ADetail, ADir: string); static;
    class function RunReplay(const AWatchdog: TFuzzWatchdog): Int32; static;
    class function RunSmoke(const AWatchdog: TFuzzWatchdog;
      APerTarget: Int32): Int32; static;
    class function RunDiscovery(const AWatchdog: TFuzzWatchdog;
      APerTarget: Int32; AMaxSeconds: Int64): Int32; static;
  public
    /// <summary>Emits the reproducer for a watchdog-detected hang and halts non-zero (a
    /// hang is a finding, so terminating the run is correct).</summary>
    class procedure EmitHangFinding(const AInput: TBytes; AIteration: Int32); static;
    /// <summary>The default hang handler: emit the reproducer and halt.</summary>
    class function HangHandler: IFuzzHangHandler; static;
    /// <summary>Runs the fuzz budget; returns 0 clean, 1 on any finding.</summary>
    class function Run: Int32; static;
  end;

implementation

const
  RecordHeaderLen = 5;
  ContentTypeHandshake = Byte(22);

type
  // the default hang action: delegate to the reproducer emitter, which halts
  TReproducerHangHandler = class sealed(TInterfacedObject, IFuzzHangHandler)
  public
    procedure HandleHang(const AInput: TBytes; AIteration: Int32);
  end;

procedure TReproducerHangHandler.HandleHang(const AInput: TBytes; AIteration: Int32);
begin
  TTlsFuzzerRunner.EmitHangFinding(AInput, AIteration);
end;

{ TFuzzWatchdog }

constructor TFuzzWatchdog.Create(ATimeoutMs: UInt64; const AHandler: IFuzzHangHandler);
begin
  FLock := TCriticalSection.Create;
  FWake := TEvent.Create(nil, False, False, '');
  FTimeoutMs := ATimeoutMs;
  FHandler := AHandler;
  FArmed := False;
  FreeOnTerminate := False;
  inherited Create(False);
end;

destructor TFuzzWatchdog.Destroy;
begin
  Terminate;
  FWake.SetEvent; // wake the poll so the thread notices Terminated promptly
  inherited Destroy; // joins the thread
  FWake.Free;
  FLock.Free;
end;

procedure TFuzzWatchdog.Arm(const AInput: TBytes; AIteration: Int32);
begin
  FLock.Enter;
  try
    FInput := AInput;
    FIteration := AIteration;
    FDeadline := GetTickCount64 + FTimeoutMs;
    FArmed := True;
  finally
    FLock.Leave;
  end;
end;

procedure TFuzzWatchdog.Disarm;
begin
  FLock.Enter;
  try
    FArmed := False;
  finally
    FLock.Leave;
  end;
end;

procedure TFuzzWatchdog.Execute;
const
  PollMs = 25;
var
  LFire: Boolean;
  LInput: TBytes;
  LIteration: Int32;
begin
  while not Terminated do
  begin
    FWake.WaitFor(PollMs);
    if Terminated then
      Break;
    LFire := False;
    LInput := nil;
    LIteration := 0;
    FLock.Enter;
    try
      if FArmed and (GetTickCount64 >= FDeadline) then
      begin
        LFire := True;
        LInput := FInput;
        LIteration := FIteration;
        FArmed := False; // fire once per armed interval
      end;
    finally
      FLock.Leave;
    end;
    if LFire then
      FHandler.HandleHang(LInput, LIteration);
  end;
end;

{ TTlsFuzzerRunner }

class function TTlsFuzzerRunner.Rnd(ABound: Int32): Int32;
begin
  if ABound <= 0 then
    Result := 0
  else
    Result := Random(ABound);
end;

class function TTlsFuzzerRunner.Filler(ALength: Int32; AByte: Byte): TBytes;
begin
  Result := nil;
  if ALength <= 0 then
    Exit;
  SetLength(Result, ALength);
  FillChar(Result[0], ALength, AByte);
end;

class function TTlsFuzzerRunner.PlaintextRecord(AContentType: Byte;
  const APayload: TBytes): TBytes;
var
  LLen: Int32;
begin
  // a single plaintext record: type || 0x0303 || uint16 length || payload
  LLen := System.Length(APayload);
  Result := nil;
  SetLength(Result, RecordHeaderLen + LLen);
  Result[0] := AContentType;
  Result[1] := $03;
  Result[2] := $03;
  Result[3] := Byte((LLen shr 8) and $FF);
  Result[4] := Byte(LLen and $FF);
  if LLen > 0 then
    Move(APayload[0], Result[RecordHeaderLen], LLen);
end;

class procedure TTlsFuzzerRunner.BuildServerEngine(out AEngine: ITlsEngine);
var
  LOptions: TInteropEngineOptions;
begin
  LOptions := Default(TInteropEngineOptions);
  LOptions.Role := TInteropRole.Server;
  LOptions.HasCredential := True;
  LOptions.Credential :=
    TInteropCredentials.ServerCredentialFromFieldFile(FProvider, FCredentialFile);
  AEngine := TInteropEngine.Build(FProvider, LOptions);
end;

class procedure TTlsFuzzerRunner.BuildClientEngine(out AEngine: ITlsEngine);
var
  LOptions: TInteropEngineOptions;
begin
  LOptions := Default(TInteropEngineOptions);
  LOptions.Role := TInteropRole.Client;
  LOptions.ServerName := 'localhost';
  LOptions.CheckServerName := True;
  LOptions.Trust := TInteropCredentials.TrustFromFieldFile(FProvider, FRootFile);
  AEngine := TInteropEngine.Build(FProvider, LOptions);
end;

class function TTlsFuzzerRunner.CaptureClientHelloFlight: TBytes;
var
  LEngine: ITlsEngine;
  LBuf: TBytes;
  LGot: Int32;
begin
  // a live, valid ClientHello flight is the richest record-framed seed
  Result := nil;
  BuildClientEngine(LEngine);
  LEngine.StartHandshake;
  LBuf := nil;
  SetLength(LBuf, 65536);
  repeat
    LGot := LEngine.TakeOutgoing(LBuf, 0);
    if LGot > 0 then
      Result := TInteropUtils.Concat(Result, System.Copy(LBuf, 0, LGot));
  until LGot = 0;
end;

class function TTlsFuzzerRunner.StripToHandshakeBody(const AFlight: TBytes): TBytes;
var
  LBodyLen: Int32;
begin
  // peel a single plaintext handshake record (5-byte record header + 4-byte handshake
  // header) down to the message body; nil when the flight is not that exact shape
  Result := nil;
  if (System.Length(AFlight) < RecordHeaderLen + 4) or
    (AFlight[0] <> ContentTypeHandshake) then
    Exit;
  LBodyLen := (Int32(AFlight[RecordHeaderLen + 1]) shl 16) or
    (Int32(AFlight[RecordHeaderLen + 2]) shl 8) or Int32(AFlight[RecordHeaderLen + 3]);
  if RecordHeaderLen + 4 + LBodyLen > System.Length(AFlight) then
    Exit;
  Result := System.Copy(AFlight, RecordHeaderLen + 4, LBodyLen);
end;

class function TTlsFuzzerRunner.CanonicalSeed(ATarget: TFuzzTarget): TBytes;
var
  LClientHello: TTlsClientHello;
  LServerHello: TTlsServerHello;
  LCertificate: TTlsCertificate;
  LCertVerify: TTlsCertificateVerify;
  LCompressed: TTlsCompressedCertificate;
  LTicket13: TTlsNewSessionTicket;
  LTicket12: TTls12NewSessionTicket;
  LReq13: TTlsCertificateRequest13;
  LReq12: TTlsCertificateRequest12;
  LSke: TTlsServerKeyExchangeEcdhe;
  LCke: TTlsClientKeyExchangeEcdhe;
  LEmptyExt, LBody, LPlain, LDeflated: TBytes;
  LCompressors: TArray<ICertificateCompressor>;
  LEchConfig: TEchConfig;
  LEchSuite: TEchCipherSuite;
begin
  // the empty extensions vector (0x0000) is a valid extension block for the messages
  // that carry one raw
  LEmptyExt := TBytes.Create($00, $00);
  case ATarget of
    TFuzzTarget.ClientHello, TFuzzTarget.EngineServer:
      begin
        LClientHello.Random := Filler(32, $2A);
        LClientHello.LegacySessionId := nil;
        LClientHello.CipherSuites := TArray<UInt16>.Create($1301, $1302, $1303);
        LClientHello.Extensions := LEmptyExt;
        LBody := THandshakeMessages.EncodeClientHello(LClientHello);
        if ATarget = TFuzzTarget.ClientHello then
          Result := LBody
        else
          Result := PlaintextRecord(ContentTypeHandshake,
            THandshakeFraming.Frame(TTlsHandshakeType.ClientHello, LBody));
      end;
    TFuzzTarget.ServerHello, TFuzzTarget.EngineClient:
      begin
        LServerHello.Random := Filler(32, $53);
        LServerHello.LegacySessionIdEcho := nil;
        LServerHello.CipherSuite := $1301;
        LServerHello.Extensions := LEmptyExt;
        LBody := THandshakeMessages.EncodeServerHello(LServerHello);
        if ATarget = TFuzzTarget.ServerHello then
          Result := LBody
        else
          Result := PlaintextRecord(ContentTypeHandshake,
            THandshakeFraming.Frame(TTlsHandshakeType.ServerHello, LBody));
      end;
    TFuzzTarget.EncryptedExtensions:
      Result := LEmptyExt;
    TFuzzTarget.Certificate13:
      begin
        LCertificate.RequestContext := nil;
        SetLength(LCertificate.Entries, 1);
        LCertificate.Entries[0].CertData := Filler(48, $C7);
        LCertificate.Entries[0].Extensions := LEmptyExt;
        Result := THandshakeMessages.EncodeCertificate(LCertificate);
      end;
    TFuzzTarget.CertificateVerify:
      begin
        LCertVerify.Algorithm := $0804;
        LCertVerify.Signature := Filler(64, $5B);
        Result := THandshakeMessages.EncodeCertificateVerify(LCertVerify);
      end;
    TFuzzTarget.CompressedCertParse, TFuzzTarget.CompressedCertBomb:
      begin
        LPlain := Filler(96, $41);
        LCompressors := TZlibCertificateCompression.DefaultCompressors;
        LDeflated := LCompressors[0].Compress(LPlain);
        LCompressed.Algorithm := TCertificateCompressionAlgorithms.Zlib;
        LCompressed.UncompressedLength := System.Length(LPlain);
        LCompressed.Compressed := LDeflated;
        Result := THandshakeMessages.EncodeCompressedCertificate(LCompressed);
      end;
    TFuzzTarget.Finished:
      Result := Filler(48, $F1);
    TFuzzTarget.NewSessionTicket13:
      begin
        LTicket13.TicketLifetime := 7200;
        LTicket13.TicketAgeAdd := $01020304;
        LTicket13.TicketNonce := Filler(8, $9);
        LTicket13.Ticket := Filler(32, $71);
        LTicket13.Extensions := LEmptyExt;
        Result := THandshakeMessages.EncodeNewSessionTicket(LTicket13);
      end;
    TFuzzTarget.NewSessionTicket12:
      begin
        LTicket12.TicketLifetimeHint := 7200;
        LTicket12.Ticket := Filler(48, $72);
        Result := THandshakeMessages.EncodeTls12NewSessionTicket(LTicket12);
      end;
    TFuzzTarget.CertRequest13:
      begin
        LReq13.RequestContext := nil;
        LReq13.Extensions := LEmptyExt;
        Result := THandshakeMessages.EncodeCertificateRequest13(LReq13);
      end;
    TFuzzTarget.CertRequest12:
      begin
        LReq12.CertificateTypes := TBytes.Create($40, $01, $02);
        LReq12.SupportedSignatureAlgorithms :=
          TArray<UInt16>.Create($0403, $0804, $0401);
        Result := THandshakeMessages.EncodeCertificateRequest12(LReq12);
      end;
    TFuzzTarget.Certificate12:
      Result := THandshakeMessages.EncodeCertificate12(
        TArray<TBytes>.Create(Filler(48, $C1), Filler(40, $C2)));
    TFuzzTarget.ServerKeyExchange:
      begin
        LSke.NamedCurve := $0017;
        LSke.PublicKey := Filler(65, $04);
        LSke.SignatureScheme := $0403;
        LSke.Signature := Filler(72, $53);
        Result := THandshakeMessages.EncodeServerKeyExchangeEcdhe(LSke);
      end;
    TFuzzTarget.ClientKeyExchange:
      begin
        LCke.PublicKey := Filler(65, $04);
        Result := THandshakeMessages.EncodeClientKeyExchangeEcdhe(LCke);
      end;
    TFuzzTarget.CertificateStatus:
      Result := THandshakeMessages.EncodeCertificateStatus(Filler(120, $A5));
    TFuzzTarget.LeafStaple:
      Result := THandshakeMessages.EncodeLeafStapleExtensions(Filler(120, $A5));
    TFuzzTarget.RecordLayer:
      Result := CaptureClientHelloFlight;
    TFuzzTarget.HandshakeReader:
      begin
        LClientHello.Random := Filler(32, $2A);
        LClientHello.LegacySessionId := nil;
        LClientHello.CipherSuites := TArray<UInt16>.Create($1301);
        LClientHello.Extensions := LEmptyExt;
        Result := THandshakeFraming.Frame(TTlsHandshakeType.ClientHello,
          THandshakeMessages.EncodeClientHello(LClientHello));
      end;
    TFuzzTarget.EchConfigListParse:
      begin
        LEchSuite.KdfId := 1; // HKDF-SHA256
        LEchSuite.AeadId := 1; // AES-128-GCM
        LEchConfig := TEchConfig.Build($FE0D, 7, 32 { X25519 }, Filler(32, $11),
          TArray<TEchCipherSuite>.Create(LEchSuite), 64,
          TBytes.Create($65, $78, $61, $6D, $70, $6C, $65) { "example" }, nil);
        Result := TEchConfigList.Encode(TArray<TEchConfig>.Create(LEchConfig));
      end;
    TFuzzTarget.EchExtensionDecode:
      Result := TEchExtension.EncodeInner; // the inner marker; mutation explores the outer form
    TFuzzTarget.EchOuterExtensionsParse:
      Result := TEchExtension.EncodeOuterExtensions(
        TArray<UInt16>.Create($000D, $0033, $002B));
  else
    Result := nil;
  end;
end;

class procedure TTlsFuzzerRunner.AppendSeed(var ADest: TArray<TBytes>;
  const ASeed: TBytes);
var
  LN: Int32;
begin
  LN := System.Length(ADest);
  SetLength(ADest, LN + 1);
  ADest[LN] := ASeed;
end;

class procedure TTlsFuzzerRunner.AppendSeeds(var ADest: TArray<TBytes>;
  const ASource: TArray<TBytes>);
var
  LI: Int32;
begin
  for LI := 0 to System.High(ASource) do
    AppendSeed(ADest, ASource[LI]);
end;

class function TTlsFuzzerRunner.LoadDirBlobs(const ADir: string): TArray<TBytes>;
var
  LSearch: TSearchRec;
  LFound, LMaskIdx: Int32;
  LStream: TFileStream;
  LBytes: TBytes;
  LPath, LMask: string;
  LMasks: TArray<string>;
  LN: Int32;
begin
  Result := nil;
  if not DirectoryExists(ADir) then
    Exit;
  // *.hex are hex-text seeds, *.bin are raw byte seeds
  LMasks := TArray<string>.Create('*.hex', '*.bin');
  for LMaskIdx := 0 to System.High(LMasks) do
  begin
    LMask := LMasks[LMaskIdx];
    LFound := FindFirst(ADir + PathDelim + LMask, faAnyFile, LSearch);
    try
      while LFound = 0 do
      begin
        if (LSearch.Attr and faDirectory) = 0 then
        begin
          LPath := ADir + PathDelim + LSearch.Name;
          if LMask = '*.hex' then
            LBytes := TInteropUtils.DecodeHex(TInteropUtils.ReadAllText(LPath))
          else
          begin
            LBytes := nil;
            LStream := TFileStream.Create(LPath, fmOpenRead or fmShareDenyNone);
            try
              SetLength(LBytes, LStream.Size);
              if LStream.Size > 0 then
                LStream.ReadBuffer(LBytes[0], LStream.Size);
            finally
              LStream.Free;
            end;
          end;
          LN := System.Length(Result);
          SetLength(Result, LN + 1);
          Result[LN] := LBytes;
        end;
        LFound := FindNext(LSearch);
      end;
    finally
      FindClose(LSearch);
    end;
  end;
end;

class procedure TTlsFuzzerRunner.LoadSeeds;
var
  LTarget: TFuzzTarget;
  LCanonical, LChFlight, LChBody: TBytes;
  LCorpus, LRegress: TArray<TBytes>;
begin
  // the on-disk corpus and the always-replayed regression corpus are generic byte blobs;
  // they seed the framing/engine targets where any record-shaped input is meaningful
  LCorpus := LoadDirBlobs(FCorpusDir);
  LRegress := LoadDirBlobs(FRegressDir);
  LChFlight := CaptureClientHelloFlight;
  LChBody := StripToHandshakeBody(LChFlight);
  for LTarget := Low(TFuzzTarget) to High(TFuzzTarget) do
  begin
    FTargetSeeds[LTarget] := nil;
    LCanonical := CanonicalSeed(LTarget);
    if System.Length(LCanonical) > 0 then
      AppendSeed(FTargetSeeds[LTarget], LCanonical);
    // a live-captured ClientHello body is a second, real seed for the ClientHello decoder
    if (LTarget = TFuzzTarget.ClientHello) and (System.Length(LChBody) > 0) then
      AppendSeed(FTargetSeeds[LTarget], LChBody);
    // the framing + engine targets accept any record-shaped bytes, so fold in the corpus
    if LTarget in [TFuzzTarget.RecordLayer, TFuzzTarget.HandshakeReader, TFuzzTarget.EngineServer, TFuzzTarget.EngineClient] then
    begin
      AppendSeeds(FTargetSeeds[LTarget], LCorpus);
      AppendSeeds(FTargetSeeds[LTarget], LRegress);
    end;
    if System.Length(FTargetSeeds[LTarget]) = 0 then
      FTargetSeeds[LTarget] := TArray<TBytes>.Create(TBytes.Create($00));
  end;
end;

class function TTlsFuzzerRunner.Mutate(const ASeed: TBytes): TBytes;
var
  LStrategy, LPos, LLen, LI: Int32;
begin
  Result := System.Copy(ASeed, 0, System.Length(ASeed));
  LLen := System.Length(Result);
  if LLen = 0 then
    Exit;
  LStrategy := Rnd(7);
  case LStrategy of
    0:
      // flip a single bit
      Result[Rnd(LLen)] := Result[Rnd(LLen)] xor (1 shl Rnd(8));
    1:
      // replace a byte with a random value
      Result[Rnd(LLen)] := Byte(Rnd(256));
    2:
      // truncate (exercises the "spans several feeds" reassembly path)
      SetLength(Result, Rnd(LLen));
    3:
      // tweak the leading length-shaped bytes to over/under-state the body
      if LLen >= RecordHeaderLen then
      begin
        Result[3] := Byte(Rnd(256));
        Result[4] := Byte(Rnd(256));
      end;
    4:
      // tweak an interior length field (3 bytes past the record header)
      if LLen >= RecordHeaderLen + 4 then
        for LI := RecordHeaderLen + 1 to RecordHeaderLen + 3 do
          Result[LI] := Byte(Rnd(256));
    5:
      // zero a run of bytes
      begin
        LPos := Rnd(LLen);
        for LI := LPos to Min(LLen - 1, LPos + Rnd(16)) do
          Result[LI] := 0;
      end;
    6:
      // duplicate the buffer (a coalesced double flight)
      Result := TInteropUtils.Concat(Result, Result);
  end;
end;

class procedure TTlsFuzzerRunner.DrainEngine(const AEngine: ITlsEngine);
var
  LBuf: TBytes;
  LEvent: ITlsEvent;
begin
  // exercise the drain paths too, not just ProcessInput
  LBuf := nil;
  SetLength(LBuf, 4096);
  while AEngine.TakeOutgoing(LBuf, 0) > 0 do ;
  while AEngine.ReadAppData(LBuf, 0, System.Length(LBuf)) > 0 do ;
  while AEngine.NextEvent(LEvent) do ;
end;

class function TTlsFuzzerRunner.Exercise(ATarget: TFuzzTarget; const AInput: TBytes;
  out ADetail: string): Boolean;
var
  LEngine: ITlsEngine;
  LRecordLayer: TRecordLayer;
  LFragment: TTlsRecordFragment;
  LReader: THandshakeMessageReader;
  LMessage: TTlsHandshakeMessage;
  LCompressed: TTlsCompressedCertificate;
  LStaple: TBytes;
  LEchType: TEchClientHelloType;
  LEchOuter: TEchOuterClientHello;
begin
  ADetail := '';
  try
    case ATarget of
      TFuzzTarget.ClientHello:
        THandshakeMessages.DecodeClientHello(AInput);
      TFuzzTarget.ServerHello:
        THandshakeMessages.DecodeServerHello(AInput);
      TFuzzTarget.EncryptedExtensions:
        THandshakeMessages.DecodeEncryptedExtensions(AInput);
      TFuzzTarget.Certificate13:
        THandshakeMessages.DecodeCertificate(AInput);
      TFuzzTarget.CertificateVerify:
        THandshakeMessages.DecodeCertificateVerify(AInput);
      TFuzzTarget.CompressedCertParse:
        THandshakeMessages.DecodeCompressedCertificate(AInput);
      TFuzzTarget.CompressedCertBomb:
        begin
          // parse, then run the bomb defense (declared-length ceiling, ratio guard,
          // exact-length match) through the real zlib decompressor
          LCompressed := THandshakeMessages.DecodeCompressedCertificate(AInput);
          TCertificateCompression.Decompress(
            TZlibCertificateCompression.DefaultDecompressors,
            LCompressed.Algorithm, LCompressed.Compressed,
            LCompressed.UncompressedLength);
        end;
      TFuzzTarget.Finished:
        THandshakeMessages.DecodeFinished(AInput);
      TFuzzTarget.NewSessionTicket13:
        THandshakeMessages.DecodeNewSessionTicket(AInput);
      TFuzzTarget.NewSessionTicket12:
        THandshakeMessages.DecodeTls12NewSessionTicket(AInput);
      TFuzzTarget.CertRequest13:
        THandshakeMessages.DecodeCertificateRequest13(AInput);
      TFuzzTarget.CertRequest12:
        THandshakeMessages.DecodeCertificateRequest12(AInput);
      TFuzzTarget.Certificate12:
        THandshakeMessages.DecodeCertificate12(AInput);
      TFuzzTarget.ServerKeyExchange:
        THandshakeMessages.DecodeServerKeyExchangeEcdhe(AInput);
      TFuzzTarget.ClientKeyExchange:
        THandshakeMessages.DecodeClientKeyExchangeEcdhe(AInput);
      TFuzzTarget.CertificateStatus:
        THandshakeMessages.DecodeCertificateStatus(AInput);
      TFuzzTarget.LeafStaple:
        THandshakeMessages.TryExtractLeafStaple(AInput, LStaple);
      TFuzzTarget.EchConfigListParse:
        // the ECHConfigList a peer publishes / a reject's retry_configs (RFC 9849 sec. 4)
        TEchConfigList.Parse(AInput);
      TFuzzTarget.EchExtensionDecode:
        // the encrypted_client_hello extension body (outer or inner, RFC 9849 sec. 5)
        TEchExtension.Decode(AInput, LEchType, LEchOuter);
      TFuzzTarget.EchOuterExtensionsParse:
        // the ech_outer_extensions list a server walks to reconstruct the inner (sec. 5.1)
        TEchExtension.DecodeOuterExtensions(AInput);
      TFuzzTarget.HandshakeReader:
        begin
          LReader := THandshakeMessageReader.Create;
          try
            LReader.Append(AInput, 0, System.Length(AInput));
            while LReader.NextMessage(LMessage) do ;
          finally
            LReader.Free;
          end;
        end;
      TFuzzTarget.RecordLayer:
        begin
          LRecordLayer := TRecordLayer.Create;
          try
            LRecordLayer.ProcessInput(AInput, 0, System.Length(AInput));
            while LRecordLayer.NextIncoming(LFragment) do ;
          finally
            LRecordLayer.Free;
          end;
        end;
      TFuzzTarget.EngineServer:
        begin
          BuildServerEngine(LEngine);
          LEngine.ProcessInput(AInput, 0, System.Length(AInput));
          DrainEngine(LEngine);
        end;
      TFuzzTarget.EngineClient:
        begin
          BuildClientEngine(LEngine);
          LEngine.StartHandshake;
          DrainEngine(LEngine);
          LEngine.ProcessInput(AInput, 0, System.Length(AInput));
          DrainEngine(LEngine);
        end;
    end;
    Result := True;
  except
    on E: EBaseTlsLibException do
      // a typed library rejection is the intended, clean failure mode
      Result := True;
    on E: Exception do
    begin
      ADetail := E.ClassName + ': ' + E.Message;
      Result := False;
    end;
  end;
end;

class function TTlsFuzzerRunner.TargetName(ATarget: TFuzzTarget): string;
begin
  case ATarget of
    TFuzzTarget.RecordLayer: Result := 'record-layer+framing';
    TFuzzTarget.HandshakeReader: Result := 'handshake-reassembly';
    TFuzzTarget.ClientHello: Result := 'ClientHello';
    TFuzzTarget.ServerHello: Result := 'ServerHello/HelloRetryRequest';
    TFuzzTarget.EncryptedExtensions: Result := 'EncryptedExtensions';
    TFuzzTarget.Certificate13: Result := 'Certificate(1.3)+cert-list';
    TFuzzTarget.CertificateVerify: Result := 'CertificateVerify';
    TFuzzTarget.CompressedCertParse: Result := 'CompressedCertificate(parse)';
    TFuzzTarget.CompressedCertBomb: Result := 'CompressedCertificate(bomb-defense)';
    TFuzzTarget.Finished: Result := 'Finished';
    TFuzzTarget.NewSessionTicket13: Result := 'NewSessionTicket(1.3)';
    TFuzzTarget.NewSessionTicket12: Result := 'NewSessionTicket(1.2)';
    TFuzzTarget.CertRequest13: Result := 'CertificateRequest(1.3)';
    TFuzzTarget.CertRequest12: Result := 'CertificateRequest(1.2)';
    TFuzzTarget.Certificate12: Result := 'Certificate(1.2)';
    TFuzzTarget.ServerKeyExchange: Result := 'ServerKeyExchange(ECDHE)';
    TFuzzTarget.ClientKeyExchange: Result := 'ClientKeyExchange(ECDHE)';
    TFuzzTarget.CertificateStatus: Result := 'CertificateStatus(OCSP)';
    TFuzzTarget.LeafStaple: Result := 'leaf status_request staple';
    TFuzzTarget.EchConfigListParse: Result := 'ECHConfigList (retry_configs/policy)';
    TFuzzTarget.EchExtensionDecode: Result := 'encrypted_client_hello extension';
    TFuzzTarget.EchOuterExtensionsParse: Result := 'ech_outer_extensions list';
    TFuzzTarget.EngineServer: Result := 'engine: ClientHello->server (ext/key_share/PSK-binder)';
    TFuzzTarget.EngineClient: Result := 'engine: ServerHello->client (ext/key_share)';
  else
    Result := 'unknown';
  end;
end;

class procedure TTlsFuzzerRunner.EmitFinding(ATarget: TFuzzTarget;
  const AInput: TBytes; const ATag, ADetail, ADir: string);
var
  LPath, LHex, LBase: string;
  LI: Int32;
  LStream: TFileStream;
begin
  if not DirectoryExists(ADir) then
    ForceDirectories(ADir);
  LBase := 'finding-' + ATag + '-' + IntToStr(Ord(ATarget));
  LPath := ADir + PathDelim + LBase + '.bin';
  if System.Length(AInput) > 0 then
  begin
    LStream := TFileStream.Create(LPath, fmCreate);
    try
      LStream.WriteBuffer(AInput[0], System.Length(AInput));
    finally
      LStream.Free;
    end;
  end;
  LHex := '';
  for LI := 0 to System.High(AInput) do
    LHex := LHex + IntToHex(AInput[LI], 2);
  Writeln(ErrOutput, 'FUZZ FINDING [', TargetName(ATarget), ']: ', ADetail);
  Writeln(ErrOutput, '  reproducer: ', LPath);
  Writeln(ErrOutput, '  input hex: ', LHex);
end;

class procedure TTlsFuzzerRunner.EmitHangFinding(const AInput: TBytes;
  AIteration: Int32);
var
  LPath, LHex: string;
  LI: Int32;
  LStream: TFileStream;
begin
  // a hang persists straight to the regression corpus so it re-runs deterministically
  if not DirectoryExists(FRegressDir) then
    ForceDirectories(FRegressDir);
  LPath := FRegressDir + PathDelim + 'hang-' + IntToStr(AIteration) + '.bin';
  if System.Length(AInput) > 0 then
  begin
    LStream := TFileStream.Create(LPath, fmCreate);
    try
      LStream.WriteBuffer(AInput[0], System.Length(AInput));
    finally
      LStream.Free;
    end;
  end;
  LHex := '';
  for LI := 0 to System.High(AInput) do
    LHex := LHex + IntToHex(AInput[LI], 2);
  Writeln(ErrOutput, 'FUZZ FINDING at iteration ', AIteration, ': hang (watchdog timeout)');
  Writeln(ErrOutput, '  reproducer: ', LPath);
  Writeln(ErrOutput, '  input hex: ', LHex);
  Halt(1);
end;

class function TTlsFuzzerRunner.HangHandler: IFuzzHangHandler;
begin
  Result := TReproducerHangHandler.Create as IFuzzHangHandler;
end;

class function TTlsFuzzerRunner.RunReplay(const AWatchdog: TFuzzWatchdog): Int32;
var
  LRegress: TArray<TBytes>;
  LTarget: TFuzzTarget;
  LI, LFindings: Int32;
  LDetail: string;
begin
  // the load-bearing deterministic gate: every checked-in regression input must parse
  // cleanly through every target (a fixed parser bug can never silently return)
  LFindings := 0;
  LRegress := LoadDirBlobs(FRegressDir);
  Writeln('replay: ', System.Length(LRegress), ' regression corpus input(s) x ',
    Ord(High(TFuzzTarget)) + 1, ' target(s)');
  for LI := 0 to System.High(LRegress) do
    for LTarget := Low(TFuzzTarget) to High(TFuzzTarget) do
    begin
      AWatchdog.Arm(LRegress[LI], LI);
      if not Exercise(LTarget, LRegress[LI], LDetail) then
      begin
        EmitFinding(LTarget, LRegress[LI], 'replay', LDetail, FFailuresDir);
        Inc(LFindings);
      end;
      AWatchdog.Disarm;
    end;
  Result := LFindings;
end;

class function TTlsFuzzerRunner.RunSmoke(const AWatchdog: TFuzzWatchdog;
  APerTarget: Int32): Int32;
var
  LTarget: TFuzzTarget;
  LSeeds: TArray<TBytes>;
  LInput: TBytes;
  LI, LFindings: Int32;
  LDetail: string;
begin
  // a fixed-seed, fixed-budget mutation smoke per target: reproducible, seconds-scale,
  // enough to catch gross new breakage a change introduces
  LFindings := 0;
  Writeln('smoke: ', APerTarget, ' mutation(s) per target, ',
    Ord(High(TFuzzTarget)) + 1, ' target(s)');
  for LTarget := Low(TFuzzTarget) to High(TFuzzTarget) do
  begin
    LSeeds := FTargetSeeds[LTarget];
    for LI := 0 to APerTarget - 1 do
    begin
      LInput := Mutate(LSeeds[Rnd(System.Length(LSeeds))]);
      AWatchdog.Arm(LInput, LI);
      if not Exercise(LTarget, LInput, LDetail) then
      begin
        EmitFinding(LTarget, LInput, 'smoke', LDetail, FFailuresDir);
        Inc(LFindings);
      end;
      AWatchdog.Disarm;
      if LFindings >= 10 then
        Break;
    end;
    if LFindings >= 10 then
      Break;
  end;
  Result := LFindings;
end;

class function TTlsFuzzerRunner.RunDiscovery(const AWatchdog: TFuzzWatchdog;
  APerTarget: Int32; AMaxSeconds: Int64): Int32;
var
  LTarget: TFuzzTarget;
  LSeeds: TArray<TBytes>;
  LInput: TBytes;
  LI, LFindings: Int32;
  LDetail: string;
  LDeadline: UInt64;
begin
  // the scheduled soak: a far larger budget doing real coverage-growing mutation. A new
  // crasher is persisted to the regression corpus so it becomes a per-push replay input.
  // Never on the per-push path (a genuine new find would make an unrelated PR flaky).
  LFindings := 0;
  if AMaxSeconds > 0 then
    LDeadline := GetTickCount64 + UInt64(AMaxSeconds) * 1000
  else
    LDeadline := High(UInt64);
  Writeln('discovery: up to ', APerTarget, ' mutation(s) per target, wall-clock cap ',
    AMaxSeconds, 's');
  for LTarget := Low(TFuzzTarget) to High(TFuzzTarget) do
  begin
    LSeeds := FTargetSeeds[LTarget];
    for LI := 0 to APerTarget - 1 do
    begin
      if GetTickCount64 >= LDeadline then
        Break;
      LInput := Mutate(LSeeds[Rnd(System.Length(LSeeds))]);
      AWatchdog.Arm(LInput, LI);
      if not Exercise(LTarget, LInput, LDetail) then
      begin
        // persist to the regression corpus, not just report, so the fix is gated forever
        EmitFinding(LTarget, LInput, 'discovery-' + IntToStr(LI), LDetail, FRegressDir);
        Inc(LFindings);
      end;
      AWatchdog.Disarm;
    end;
    if GetTickCount64 >= LDeadline then
      Break;
  end;
  Result := LFindings;
end;

class function TTlsFuzzerRunner.Run: Int32;
var
  LSeed, LPerTarget, LI, LFindings: Int32;
  LMaxSeconds, LTimeoutMs: Int64;
  LDataDir, LArg: string;
  LDiscovery: Boolean;
  LWatchdog: TFuzzWatchdog;
  LTarget: TFuzzTarget;
begin
  LSeed := 20260804;
  LTimeoutMs := 2000; // generous per-iteration bound: only a genuine hang exceeds it
  LDiscovery := False;
  LPerTarget := -1;   // resolved below from the mode
  LMaxSeconds := 0;   // 0 = no wall-clock cap
  for LI := 1 to ParamCount do
  begin
    LArg := ParamStr(LI);
    if LArg = '--discovery' then
      LDiscovery := True
    else if (LArg = '--iterations') or (LArg = '--iterations-per-target') then
      LPerTarget := StrToIntDef(ParamStr(LI + 1), LPerTarget)
    else if LArg = '--seed' then
      LSeed := StrToIntDef(ParamStr(LI + 1), LSeed)
    else if LArg = '--max-seconds' then
      LMaxSeconds := StrToInt64Def(ParamStr(LI + 1), LMaxSeconds)
    else if LArg = '--timeout-ms' then
      LTimeoutMs := StrToInt64Def(ParamStr(LI + 1), LTimeoutMs);
  end;
  if LPerTarget < 0 then
    if LDiscovery then
      LPerTarget := 200000  // scheduled soak default (bounded by --max-seconds if set)
    else
      LPerTarget := 400;    // per-push smoke default, sits inside the BoGo wall-clock
  RandSeed := LSeed;

  LDataDir := TInteropUtils.LocateDataDir;
  FCredentialFile := LDataDir + PathDelim + 'Certs' + PathDelim + 'EcP256Chain.txt';
  FRootFile := FCredentialFile;
  FCorpusDir := LDataDir + PathDelim + 'Corpus';
  FRegressDir := FCorpusDir + PathDelim + 'regress';
  FFailuresDir := FCorpusDir + PathDelim + 'failures';
  FProvider := TInteropEngine.DefaultProvider;
  LoadSeeds;

  // no silent caps: log every parser fuzzed and each tier's budget
  Writeln('structure-aware parser fuzz (seed=', LSeed, ', ', Ord(High(TFuzzTarget)) + 1,
    ' targets):');
  for LTarget := Low(TFuzzTarget) to High(TFuzzTarget) do
    Writeln('  - ', TargetName(LTarget), ' (', System.Length(FTargetSeeds[LTarget]),
      ' seed(s))');

  LFindings := 0;
  // a parser infinite loop inside Exercise would otherwise hang to the CI timeout; the
  // watchdog turns it into a reported finding for the current input
  LWatchdog := TFuzzWatchdog.Create(UInt64(LTimeoutMs), HangHandler);
  try
    LFindings := LFindings + RunReplay(LWatchdog);
    if LDiscovery then
      LFindings := LFindings + RunDiscovery(LWatchdog, LPerTarget, LMaxSeconds)
    else
      LFindings := LFindings + RunSmoke(LWatchdog, LPerTarget);
  finally
    LWatchdog.Free;
  end;

  if LFindings = 0 then
  begin
    Writeln('PASS: no crash/hang/over-read; every rejection was a clean outcome or a ',
      'typed exception');
    Result := 0;
  end
  else
  begin
    Writeln(ErrOutput, 'FAIL: ', LFindings, ' fuzz finding(s)');
    Result := 1;
  end;
end;

end.
