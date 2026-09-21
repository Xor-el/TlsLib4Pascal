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
  /// Times application-data throughput (MB/s) through an established hardened TLS 1.2
  /// connection for TlsLib against OpenSSL, per AEAD suite (AES-128-GCM, AES-256-GCM,
  /// ChaCha20-Poly1305) and TLS record size (256 B / 1400 B / 16 KB). X25519 ECDHE and the
  /// same EC P-256 certificate are used on both sides; the connection is handshaked once,
  /// then a fixed payload is chunked into records of each size, sealed on the client and
  /// opened on the server - the record layer's steady-state cost, and how a smaller record
  /// spreads the per-record header + AEAD tag over less data.
  ///
  /// Caveat by design: throughput is dominated by the AEAD, which TlsLib delegates to
  /// CryptoLib, so this is an end-to-end figure (the framing overhead TlsLib adds is a
  /// thin slice on top of the cipher).
  /// </summary>
  TTlsRecordThroughputBenchmark = class sealed(TObject)
  public
    /// <summary>Runs every AEAD suite and returns the rendered table width.</summary>
    class function Run(ALogProc: TBenchmarkLogProc): Int32; static;
  end;

implementation

uses
  StrUtils,
  TlpNegotiationTypes,
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

type
  TThroughputSuite = record
    TlsCode: UInt16;    // TlsLib TLS 1.2 cipher-suite codepoint
    OsslCipher: string; // OpenSSL cipher-list token for the same suite
    Name: string;       // display label
  end;

class function TTlsRecordThroughputBenchmark.Run(ALogProc: TBenchmarkLogProc): Int32;
var
  LProvider: ICryptoProvider;
  LPkix: IPkixProvider;
  LCredential: TTlsBenchmarkCredential;
  LOpenSslAvailable: Boolean;
  LDeferred: TArray<string>;
  LSuites: array [0 .. 2] of TThroughputSuite;
  LIdx, LSi: Int32;
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

  function MeasureTls(ASuiteCode: UInt16; ARecordSize: Int32;
    const AName: string): Double;
  var
    LPeer: TTlsLibThroughputPeer;
  begin
    Result := -1.0;
    try
      LPeer := TTlsLibThroughputPeer.Create(LProvider, LPkix, LCredential, ASuiteCode,
        ARecordSize, BENCH_TP_PAYLOAD);
      try
        Result := TBenchmarkTiming.MeasureThroughputMbPerSec(LPeer.SendOnce, LPeer.PayloadBytes);
      finally
        LPeer.Free;
      end;
    except
      on E: Exception do
        Note(AName + ' - TlsLib: ' + E.Message);
    end;
  end;

  function MeasureOssl(const ACipher: string; ARecordSize: Int32;
    const AName: string): Double;
  var
    LPeer: TOpenSslThroughputPeer;
  begin
    Result := -1.0;
    if not LOpenSslAvailable then
      Exit;
    try
      LPeer := TOpenSslThroughputPeer.Create(LCredential, ACipher, BENCH_TP_OSSL_GROUPS,
        ARecordSize, BENCH_TP_PAYLOAD);
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

begin
  Result := BENCH_LABEL_COL_WIDTH + 3 * BENCH_TP_VALUE_COL_WIDTH;
  LProvider := TDefaultCryptoProvider.Create as ICryptoProvider;
  LPkix := TDefaultPkixProvider.Create as IPkixProvider;
  LCredential := TTlsBenchmarkData.LoadEcP256;
  LOpenSslAvailable := TOpenSslThroughputPeer.IsAvailable;
  LDeferred := nil;

  LSuites[0].TlsCode := TCipherSuites12.EcdheEcdsaAes128GcmSha256;
  LSuites[0].OsslCipher := 'ECDHE-ECDSA-AES128-GCM-SHA256';
  LSuites[0].Name := 'AES-128-GCM';
  LSuites[1].TlsCode := TCipherSuites12.EcdheEcdsaAes256GcmSha384;
  LSuites[1].OsslCipher := 'ECDHE-ECDSA-AES256-GCM-SHA384';
  LSuites[1].Name := 'AES-256-GCM';
  LSuites[2].TlsCode := TCipherSuites12.EcdheEcdsaChaCha20Poly1305Sha256;
  LSuites[2].OsslCipher := 'ECDHE-ECDSA-CHACHA20-POLY1305';
  LSuites[2].Name := 'ChaCha20-Poly1305';

  ALogProc('TLS record throughput - TLS 1.2 ECDHE-ECDSA over X25519, ' +
    TBenchmarkFormat.FormatBufferSize(BENCH_TP_PAYLOAD) + ' payloads, peer verification off');
  ALogProc('one connection handshaked once, then application data is sealed + opened each pass');
  if not LOpenSslAvailable then
    ALogProc('OpenSSL not loaded - reporting TlsLib only');
  ALogProc(TBenchmarkReport.BuildSeparator(Result));
  ALogProc(TBenchmarkReport.BuildHeaderRow('AEAD suite',
    ['TlsLib', 'OpenSSL', 'TlsLib/OpenSSL'], BENCH_TP_VALUE_COL_WIDTH));
  ALogProc(TBenchmarkReport.BuildSeparator(Result));

  for LIdx := System.Low(LSuites) to System.High(LSuites) do
  begin
    if LIdx > System.Low(LSuites) then
      ALogProc('');
    for LSi := System.Low(BENCH_TP_RECORD_SIZES) to System.High(BENCH_TP_RECORD_SIZES) do
    begin
      LRowName := LSuites[LIdx].Name + ' @ ' +
        RecordSizeLabel(BENCH_TP_RECORD_SIZES[LSi]);
      LTlsMbps := MeasureTls(LSuites[LIdx].TlsCode, BENCH_TP_RECORD_SIZES[LSi], LRowName);
      LOslMbps := MeasureOssl(LSuites[LIdx].OsslCipher, BENCH_TP_RECORD_SIZES[LSi], LRowName);

      ALogProc(TBenchmarkReport.BuildDataRow(LRowName,
        [Mbps(LTlsMbps),
         IfThen(LOpenSslAvailable, Mbps(LOslMbps), 'N/A'),
         IfThen((LTlsMbps > 0.0) and (LOslMbps > 0.0),
           FormatFloat('0.00', LTlsMbps / LOslMbps, TBenchmarkReport.FloatFormat) + 'x', 'N/A')],
        BENCH_TP_VALUE_COL_WIDTH));
    end;
  end;

  for LIdx := System.Low(LDeferred) to System.High(LDeferred) do
    ALogProc('  ! ' + LDeferred[LIdx]);

  ALogProc(TBenchmarkReport.BuildSeparator(Result));
end;

end.
