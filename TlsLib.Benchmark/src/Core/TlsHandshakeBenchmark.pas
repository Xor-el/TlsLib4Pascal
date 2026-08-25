{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlsHandshakeBenchmark;

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

interface

uses
  SysUtils,
  BenchmarkCommon;

type
  /// <summary>
  /// Times full 1-RTT TLS handshakes for TlsLib against OpenSSL, in memory, across the
  /// supported ECDHE groups (X25519 and the NIST P-256/384/521 curves) for both TLS 1.3
  /// and hardened TLS 1.2 - X25519 and the classical curves are all version-agnostic
  /// ECDHE groups per RFC 8422, usable in 1.2 and 1.3 alike. The whole matrix runs once
  /// per leaf certificate - an EC P-256 leaf (ECDSA CertificateVerify) and an RSA-2048 leaf
  /// (RSA-PSS CertificateVerify in 1.3, ECDHE-RSA in 1.2), the Let's-Encrypt-style case that
  /// the EC-only rows never exercised. An ECDSA leaf also offers its own curve in
  /// supported_groups (RFC 8422 5.4). Peer verification is disabled, so the figure reflects
  /// the handshake proper (ECDHE key exchange + the certificate signature) rather than PKIX.
  ///
  /// Caveat by design: the handshake cost is dominated by the asymmetric crypto, which
  /// TlsLib delegates to CryptoLib. This is therefore an end-to-end, user-facing figure
  /// (how fast a connection is), not a measure of TlsLib's own orchestration - that
  /// overhead is a thin slice on top of the EC operations.
  /// </summary>
  TTlsHandshakeBenchmark = class sealed(TObject)
  public
    /// <summary>Runs every scenario and returns the rendered table width.</summary>
    class function Run(ALogProc: TBenchmarkLogProc): Int32; static;
  end;

implementation

uses
  StrUtils,
  TlpTlsVersion,
  TlpNegotiationTypes,
  TlpCryptoAlgorithms,
  TlpICryptoProvider,
  TlpDefaultCryptoProvider,
  TlsBenchmarkData,
  TlsLibHandshakePeer,
  OpenSslHandshakePeer;

const
  BENCH_HS_VALUE_COL_WIDTH = 16;
  // fixed-cost handshakes ahead of measurement so the per-curve EC precomputation, the
  // allocator and the code paths are warm - the measured window is then steady-state
  BENCH_HS_WARMUP = 25;

type
  TBenchCurve = record
    Code: UInt16;      // TlsLib named-group codepoint (the ECDHE group)
    OsslName: string;  // the same curve as an OpenSSL groups-list token
    Name: string;      // display label
  end;

  TBenchVersion = record
    Wire: UInt16;
    Name: string;
  end;

  TBenchCert = record
    Cred: TTlsBenchmarkCredential;
    CertLabel: string;  // section label, e.g. 'EC P-256 certificate'
    AuthLabel: string;  // per-row auth tag, e.g. 'ECDSA-P256' / 'RSA-2048'
  end;

class function TTlsHandshakeBenchmark.Run(ALogProc: TBenchmarkLogProc): Int32;
var
  LProvider: ICryptoProvider;
  LCredential: TTlsBenchmarkCredential;
  LOpenSslAvailable: Boolean;
  LDeferred: TArray<string>;
  LCurves: array [0 .. 3] of TBenchCurve;
  LVersions: array [0 .. 1] of TBenchVersion;
  LCerts: array [0 .. 1] of TBenchCert;
  LCertCode: UInt16;
  LCertOssl, LRowName, LOsslGroups: string;
  LKi, LVi, LCi: Int32;
  LTlsMs, LOslMs: Double;

  function HsPerSec(AMs: Double): String;
  begin
    if AMs > 0.0 then
      Result := FormatFloat('#,##0.00', 1000.0 / AMs, TBenchmarkReport.FloatFormat)
    else
      Result := 'ERROR';
  end;

  procedure Note(const AMessage: string);
  begin
    SetLength(LDeferred, System.Length(LDeferred) + 1);
    LDeferred[System.High(LDeferred)] := AMessage;
  end;

  function OsslNameOf(ACode: UInt16): string;
  var
    LI: Int32;
  begin
    Result := '';
    for LI := System.Low(LCurves) to System.High(LCurves) do
      if LCurves[LI].Code = ACode then
        Exit(LCurves[LI].OsslName);
  end;

  // the leaf's own curve, read from the certificate, so the OpenSSL groups list can include
  // it (RFC 8422 5.4) exactly as the TlsLib peer does; 0 for a non-ECDSA leaf
  function CertGroupCode: UInt16;
  var
    LKind: TCertKeyKind;
    LCurve: UInt16;
  begin
    Result := 0;
    if LProvider.Certificates.KeyKind(LCredential.LeafCertDer, LKind, LCurve)
      and (LKind = TCertKeyKind.Ecdsa) then
      Result := LCurve;
  end;

  function MeasureTls(AWire, ACurve: UInt16; const AName: string): Double;
  var
    LPeer: TTlsLibHandshakePeer;
    LWarm: Int32;
  begin
    Result := -1.0;
    try
      LPeer := TTlsLibHandshakePeer.Create(LProvider, LCredential, AWire, ACurve);
      try
        for LWarm := 1 to BENCH_HS_WARMUP do
          LPeer.RunOneHandshake;
        Result := TBenchmarkTiming.MeasureMeanMillisecondsPerOp(LPeer.RunOneHandshake);
      finally
        LPeer.Free;
      end;
    except
      on E: Exception do
        Note(AName + ' - TlsLib: ' + E.Message);
    end;
  end;

  function MeasureOssl(AWire: UInt16; const AGroups, AName: string): Double;
  var
    LPeer: TOpenSslHandshakePeer;
    LWarm: Int32;
  begin
    Result := -1.0;
    if not LOpenSslAvailable then
      Exit;
    try
      LPeer := TOpenSslHandshakePeer.Create(LCredential, AWire, AGroups);
      try
        for LWarm := 1 to BENCH_HS_WARMUP do
          LPeer.RunOneHandshake;
        Result := TBenchmarkTiming.MeasureMeanMillisecondsPerOp(LPeer.RunOneHandshake);
      finally
        LPeer.Free;
      end;
    except
      on E: Exception do
        Note(AName + ' - OpenSSL: ' + E.Message);
    end;
  end;

begin
  Result := BENCH_LABEL_COL_WIDTH + 5 * BENCH_HS_VALUE_COL_WIDTH;
  LProvider := TDefaultCryptoProvider.Create as ICryptoProvider;
  LOpenSslAvailable := TOpenSslHandshakePeer.IsAvailable;
  LDeferred := nil;

  LCurves[0].Code := TNamedGroupCatalog.X25519;    LCurves[0].OsslName := 'X25519'; LCurves[0].Name := 'X25519';
  LCurves[1].Code := TNamedGroupCatalog.Secp256r1; LCurves[1].OsslName := 'P-256';  LCurves[1].Name := 'secp256r1';
  LCurves[2].Code := TNamedGroupCatalog.Secp384r1; LCurves[2].OsslName := 'P-384';  LCurves[2].Name := 'secp384r1';
  LCurves[3].Code := TNamedGroupCatalog.Secp521r1; LCurves[3].OsslName := 'P-521';  LCurves[3].Name := 'secp521r1';
  LVersions[0].Wire := TlsWireVersionTls13; LVersions[0].Name := 'TLS 1.3';
  LVersions[1].Wire := TlsWireVersionTls12; LVersions[1].Name := 'TLS 1.2';
  LCerts[0].Cred := TTlsBenchmarkData.LoadEcP256;
  LCerts[0].CertLabel := 'EC P-256 certificate';  LCerts[0].AuthLabel := 'ECDSA-P256';
  LCerts[1].Cred := TTlsBenchmarkData.LoadRsa2048;
  LCerts[1].CertLabel := 'RSA-2048 certificate';  LCerts[1].AuthLabel := 'RSA-2048';

  if not LOpenSslAvailable then
    ALogProc('OpenSSL not loaded - reporting TlsLib only (put libssl / libcrypto next to the executable)');

  for LKi := System.Low(LCerts) to System.High(LCerts) do
  begin
    // the nested measure helpers read LCredential, so pin the current certificate first
    LCredential := LCerts[LKi].Cred;
    LCertCode := CertGroupCode;
    LCertOssl := OsslNameOf(LCertCode);

    if LKi > System.Low(LCerts) then
      ALogProc('');
    ALogProc('TLS handshake throughput - ECDHE per row, ' + LCerts[LKi].CertLabel
      + ', peer verification off');
    ALogProc('reusable config / SSL_CTX built once; a fresh engine/SSL + full 1-RTT handshake is timed');
    ALogProc(TBenchmarkReport.BuildSeparator(Result));
    ALogProc(TBenchmarkReport.BuildHeaderRow('Scenario',
      ['TlsLib hs/s', 'OpenSSL hs/s', 'TlsLib ms', 'OpenSSL ms', 'TlsLib/OpenSSL'],
      BENCH_HS_VALUE_COL_WIDTH));
    ALogProc(TBenchmarkReport.BuildSeparator(Result));

    for LVi := System.Low(LVersions) to System.High(LVersions) do
    begin
      if LVi > System.Low(LVersions) then
        ALogProc('');
      for LCi := System.Low(LCurves) to System.High(LCurves) do
      begin
        LRowName := LVersions[LVi].Name + ' ' + LCerts[LKi].AuthLabel
          + ' (' + LCurves[LCi].Name + ')';

        // the OpenSSL groups list: the ECDHE curve, plus the certificate's curve when it
        // differs (TlsLib derives the same fallback from the certificate itself)
        LOsslGroups := LCurves[LCi].OsslName;
        if (LCertOssl <> '') and (LCertCode <> LCurves[LCi].Code) then
          LOsslGroups := LOsslGroups + ':' + LCertOssl;

        LTlsMs := MeasureTls(LVersions[LVi].Wire, LCurves[LCi].Code, LRowName);
        LOslMs := MeasureOssl(LVersions[LVi].Wire, LOsslGroups, LRowName);

        ALogProc(TBenchmarkReport.BuildDataRow(LRowName,
          [HsPerSec(LTlsMs),
           IfThen(LOpenSslAvailable, HsPerSec(LOslMs), 'N/A'),
           TBenchmarkFormat.FormatMeanMilliseconds(LTlsMs),
           IfThen(LOpenSslAvailable, TBenchmarkFormat.FormatMeanMilliseconds(LOslMs), 'N/A'),
           IfThen((LTlsMs > 0.0) and (LOslMs > 0.0),
             FormatFloat('0.00', LOslMs / LTlsMs, TBenchmarkReport.FloatFormat) + 'x', 'N/A')],
          BENCH_HS_VALUE_COL_WIDTH));
      end;
    end;

    ALogProc(TBenchmarkReport.BuildSeparator(Result));
  end;

  for LVi := System.Low(LDeferred) to System.High(LDeferred) do
    ALogProc('  ! ' + LDeferred[LVi]);
end;

end.
