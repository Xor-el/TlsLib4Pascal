{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlsRecordThroughputBenchmark;

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

interface

uses
  SysUtils,
  BenchmarkCommon;

type
  /// <summary>
  /// Times application-data throughput (MB/s) through an established hardened TLS
  /// connection for TlsLib against OpenSSL, per protocol version (TLS 1.3 / 1.2), AEAD
  /// suite (AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305), TLS record size (256 B / 1400 B /
  /// 16 KB) and delivery pattern (each sealed chunk fed whole, or in 1400-byte slices as a
  /// small-read socket would). X25519 ECDHE and the same EC P-256 certificate are used on
  /// both sides; the connection is handshaked once, then a fixed payload is chunked into
  /// records of each size, sealed on the client and opened on the server - the record
  /// layer's steady-state cost, and how a smaller record spreads the per-record header +
  /// AEAD tag over less data.
  ///
  /// Caveat by design: throughput is dominated by the AEAD, which TlsLib delegates to
  /// CryptoLib, so this is an end-to-end figure (the framing overhead TlsLib adds is a
  /// thin slice on top of the cipher).
  /// </summary>
  TTlsRecordThroughputBenchmark = class sealed(TObject)
  public
    /// <summary>Runs every version / suite / size / feed cell and returns the rendered table width.</summary>
    class function Run(ALogProc: TBenchmarkLogProc): Int32; static;
  end;

implementation

uses
  StrUtils,
  TlpNegotiationTypes,
  TlpTlsVersion,
  TlpICryptoProvider,
  TlpIPkixProvider,
  TlpDefaultCryptoProvider,
  TlpDefaultPkixProvider,
  TlsBenchmarkData,
  TlsLibThroughputPeer,
  OpenSslThroughputPeer;

const
  BENCH_TP_VALUE_COL_WIDTH = 18;
  // one connection's application-data payload sealed+opened per pass; a multiple of the
  // 16 KiB record ceiling so the per-pass overhead is amortised into steady-state throughput
  BENCH_TP_PAYLOAD = 256 * 1024;
  // X25519 for the key exchange, P-256 for the certificate's own curve (RFC 8422 5.4)
  BENCH_TP_OSSL_GROUPS = 'X25519:P-256';
  // the application-write (TLS record) sizes measured: a tiny record, an MTU-sized record
  // and the 16 KiB record ceiling - the payload is chunked into records of each size, so a
  // smaller record spreads the per-record header + AEAD tag over less data
  BENCH_TP_RECORD_SIZES: array [0 .. 2] of Int32 = (256, 1400, 16384);
  // the sliced feed hands the server each sealed chunk in reads of this size, so a 16 KB
  // record arrives as a dozen partial reads the record layer has to accumulate
  BENCH_TP_FEED_SLICE = 1400;

type
  TThroughputSuite = record
    Wire: UInt16;       // protocol version wire value the suite belongs to
    TlsCode: UInt16;    // TlsLib cipher-suite codepoint
    OsslCipher: string; // OpenSSL cipher-list token (1.2) or ciphersuite name (1.3)
    Name: string;       // display label
  end;

  TThroughputVersion = record
    Wire: UInt16;
    Name: string;
  end;

  TThroughputFeed = record
    Slice: Int32;       // 0 = each sealed chunk delivered whole
    Name: string;
  end;

class function TTlsRecordThroughputBenchmark.Run(ALogProc: TBenchmarkLogProc): Int32;
var
  LCrypto: ICryptoProvider;
  LPkix: IPkixProvider;
  LCredential: TTlsBenchmarkCredential;
  LOpenSslAvailable: Boolean;
  LDeferred: TArray<string>;
  LSuites: array [0 .. 5] of TThroughputSuite;
  LVersions: array [0 .. 1] of TThroughputVersion;
  LFeeds: array [0 .. 1] of TThroughputFeed;
  LIdx, LVi, LFi, LSi, LShown: Int32;
  LRowName: string;
  LTlsMbps, LOslMbps: Double;

  procedure Note(const AMessage: string);
  begin
    SetLength(LDeferred, System.Length(LDeferred) + 1);
    LDeferred[System.High(LDeferred)] := AMessage;
  end;

  function Mbps(AValue: Double): String;
  begin
    if AValue > 0.0 then
      Result := TBenchmarkFormat.FormatThroughputMbPerSec(AValue)
    else
      Result := 'ERROR';
  end;

  // exact record-size label (unlike FormatBufferSize, an MTU-sized 1400 stays "1400 B")
  function RecordSizeLabel(ASize: Int32): String;
  begin
    if (ASize >= 1024) and (ASize mod 1024 = 0) then
      Result := IntToStr(ASize div 1024) + ' KB'
    else
      Result := IntToStr(ASize) + ' B';
  end;

  function MeasureTls(const ASuite: TThroughputSuite; ARecordSize, AFeedSlice: Int32;
    const AName: string): Double;
  var
    LPeer: TTlsLibThroughputPeer;
  begin
    Result := -1.0;
    try
      LPeer := TTlsLibThroughputPeer.Create(LCrypto, LPkix, LCredential, ASuite.Wire,
        ASuite.TlsCode, ARecordSize, BENCH_TP_PAYLOAD, AFeedSlice);
      try
        // one warm pass before the timed one
        LPeer.SendOnce;
        Result := TBenchmarkTiming.MeasureThroughputMbPerSec(LPeer.SendOnce, LPeer.PayloadBytes);
      finally
        LPeer.Free;
      end;
    except
      on E: Exception do
        Note(AName + ' - TlsLib: ' + E.Message);
    end;
  end;

  function MeasureOssl(const ASuite: TThroughputSuite; ARecordSize, AFeedSlice: Int32;
    const AName: string): Double;
  var
    LPeer: TOpenSslThroughputPeer;
  begin
    Result := -1.0;
    if not LOpenSslAvailable then
      Exit;
    try
      LPeer := TOpenSslThroughputPeer.Create(LCredential, ASuite.Wire, ASuite.OsslCipher,
        BENCH_TP_OSSL_GROUPS, ARecordSize, BENCH_TP_PAYLOAD, AFeedSlice);
      try
        Result := TBenchmarkTiming.MeasureThroughputMbPerSec(LPeer.SendOnce, BENCH_TP_PAYLOAD);
      finally
        LPeer.Free;
      end;
    except
      on E: Exception do
        Note(AName + ' - OpenSSL: ' + E.Message);
    end;
  end;

  procedure Suite(AIndex: Int32; AWire, ACode: UInt16; const AOssl, AName: string);
  begin
    LSuites[AIndex].Wire := AWire;
    LSuites[AIndex].TlsCode := ACode;
    LSuites[AIndex].OsslCipher := AOssl;
    LSuites[AIndex].Name := AName;
  end;

begin
  Result := BENCH_LABEL_COL_WIDTH + 5 * BENCH_TP_VALUE_COL_WIDTH;
  LCrypto := TDefaultCryptoProvider.Create as ICryptoProvider;
  LPkix := TDefaultPkixProvider.Create as IPkixProvider;
  LCredential := TTlsBenchmarkData.LoadEcP256;
  LOpenSslAvailable := TOpenSslThroughputPeer.IsAvailable;
  LDeferred := nil;

  Suite(0, TlsWireVersionTls13, TCipherSuites13.Aes128GcmSha256,
    'TLS_AES_128_GCM_SHA256', 'AES-128-GCM');
  Suite(1, TlsWireVersionTls13, TCipherSuites13.Aes256GcmSha384,
    'TLS_AES_256_GCM_SHA384', 'AES-256-GCM');
  Suite(2, TlsWireVersionTls13, TCipherSuites13.ChaCha20Poly1305Sha256,
    'TLS_CHACHA20_POLY1305_SHA256', 'ChaCha20-Poly1305');
  Suite(3, TlsWireVersionTls12, TCipherSuites12.EcdheEcdsaAes128GcmSha256,
    'ECDHE-ECDSA-AES128-GCM-SHA256', 'AES-128-GCM');
  Suite(4, TlsWireVersionTls12, TCipherSuites12.EcdheEcdsaAes256GcmSha384,
    'ECDHE-ECDSA-AES256-GCM-SHA384', 'AES-256-GCM');
  Suite(5, TlsWireVersionTls12, TCipherSuites12.EcdheEcdsaChaCha20Poly1305Sha256,
    'ECDHE-ECDSA-CHACHA20-POLY1305', 'ChaCha20-Poly1305');
  LVersions[0].Wire := TlsWireVersionTls13; LVersions[0].Name := 'TLS 1.3';
  LVersions[1].Wire := TlsWireVersionTls12; LVersions[1].Name := 'TLS 1.2';
  LFeeds[0].Slice := 0;
  LFeeds[0].Name := 'whole-record feed';
  LFeeds[1].Slice := BENCH_TP_FEED_SLICE;
  LFeeds[1].Name := 'sliced feed (' + IntToStr(BENCH_TP_FEED_SLICE) + ' B reads)';

  ALogProc('TLS record throughput - ECDHE-ECDSA over X25519, EC P-256 certificate, ' +
    TBenchmarkFormat.FormatBufferSize(BENCH_TP_PAYLOAD) + ' payloads, peer verification off');
  ALogProc('one connection handshaked once, then application data is sealed + opened each pass');
  ALogProc('TlsLib hardware AES: ' + IfThen(LCrypto.Primitives.HasHardwareAes, 'yes', 'no'));
  if not LOpenSslAvailable then
    ALogProc('OpenSSL not loaded - reporting TlsLib only');

  for LVi := System.Low(LVersions) to System.High(LVersions) do
    for LFi := System.Low(LFeeds) to System.High(LFeeds) do
    begin
      ALogProc('');
      ALogProc(LVersions[LVi].Name + ' - ' + LFeeds[LFi].Name);
      ALogProc(TBenchmarkReport.BuildSeparator(Result));
      ALogProc(TBenchmarkReport.BuildHeaderRow('AEAD suite',
        ['TlsLib', 'OpenSSL', 'TlsLib/OpenSSL'],
        BENCH_TP_VALUE_COL_WIDTH));
      ALogProc(TBenchmarkReport.BuildSeparator(Result));

      LShown := 0;
      for LIdx := System.Low(LSuites) to System.High(LSuites) do
      begin
        if LSuites[LIdx].Wire <> LVersions[LVi].Wire then
          Continue;
        if LShown > 0 then
          ALogProc('');
        Inc(LShown);
        for LSi := System.Low(BENCH_TP_RECORD_SIZES) to System.High(BENCH_TP_RECORD_SIZES) do
        begin
          LRowName := LSuites[LIdx].Name + ' @ ' + RecordSizeLabel(BENCH_TP_RECORD_SIZES[LSi]);
          LTlsMbps := MeasureTls(LSuites[LIdx], BENCH_TP_RECORD_SIZES[LSi], LFeeds[LFi].Slice,
            LVersions[LVi].Name + ' ' + LRowName);
          LOslMbps := MeasureOssl(LSuites[LIdx], BENCH_TP_RECORD_SIZES[LSi], LFeeds[LFi].Slice,
            LVersions[LVi].Name + ' ' + LRowName);

          ALogProc(TBenchmarkReport.BuildDataRow(LRowName,
            [Mbps(LTlsMbps),
             IfThen(LOpenSslAvailable, Mbps(LOslMbps), 'N/A'),
             IfThen((LTlsMbps > 0.0) and (LOslMbps > 0.0),
               FormatFloat('0.00', LTlsMbps / LOslMbps, TBenchmarkReport.FloatFormat) + 'x', 'N/A')],
            BENCH_TP_VALUE_COL_WIDTH));
        end;
      end;
      ALogProc(TBenchmarkReport.BuildSeparator(Result));
    end;

  for LIdx := System.Low(LDeferred) to System.High(LDeferred) do
    ALogProc('  ! ' + LDeferred[LIdx]);
end;

end.
