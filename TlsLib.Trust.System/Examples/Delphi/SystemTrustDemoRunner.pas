{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

/// <summary>
/// Everything the system-trust demo does, so the form only delegates to it: a live HTTPS GET
/// verified by the host OS trust store (an unmodified Indy TIdHTTP with UseSystemTrust), then
/// on-device checks of the OS trust delegate against whatever platform engine the build targets
/// (the Android X509TrustManager on a device). Each check is self-contained and needs no network:
/// a three-tier chain is supplied as bytes, the intermediate reaches the OS engine only through
/// the context, and the verdicts are read straight from the delegate verifiers.
/// </summary>
unit SystemTrustDemoRunner;

interface

uses
  System.SysUtils,
  TlpTlsAlert,
  TlpTrustPolicy;

type
  TSystemTrustDemoRunner = class sealed(TObject)
  strict private
    /// <summary>One live GET over the OS system trust store. Returns a human line; the network
    /// must not run on the UI thread (mobile platforms forbid it).</summary>
    class function RunSystemTrustGet(const AUrl: string): string; static;
    class function ClientContext(const AIntermediates: TArray<TBytes>): TClientTrustContext; static;
    class function ServerContext(const AIntermediates: TArray<TBytes>): TServerTrustContext; static;
    class function VerifyClient(const AIntermediates, AChain: TArray<TBytes>;
      out AAlert: TTlsAlertDescription): Boolean; static;
    /// <summary>The leaf names an issuer that is not an anchor: it verifies only if the
    /// intermediate carried in the context reaches the OS engine, and not at all without it.</summary>
    class function CheckIntermediates: string; static;
    /// <summary>An empty presented chain is refused even when intermediates are configured, so the
    /// OS engine is never handed only the configured intermediates.</summary>
    class function CheckEmptyChain: string; static;
    /// <summary>Reports whether the engine accepts a live-revocation source. One without a network
    /// revocation knob must refuse it up front, so a live deadline is never silently dropped.</summary>
    class function CheckLiveFetch: string; static;
    /// <summary>Every OS-delegate check, one result line each.</summary>
    class function RunChecks: TArray<string>; static;
  public
    /// <summary>The live GET of AUrl, then every OS-delegate check, as the lines to show: the GET
    /// result, a heading, then one "PASS: ...", "FAIL: ..." or "INFO: ..." line per check. Blocks
    /// on the network, so call it off the UI thread.</summary>
    class function Run(const AUrl: string): TArray<string>; static;
  end;

implementation

uses
  IdHTTP,
  IdStack,
  TlpTlsLibExceptions,
  TlsLibIndyTls,
  TlpDataEncoding,
  TlpIPkixProvider,
  TlpDefaultPkixProvider,
  TlpTrustAnchorStore,
  TlpICertificateTrust,
  TlpICertificateVerifierSource,
  TlpTrustTypes,
  TlpCertificateLimits,
  TlpCertificateStrengthPolicy,
  TlpNegotiationTypes,
  TlpServerName,
  TlpIClock,
  TlpClock,
  TlpSystemTrustBase,
  TlpSystemTrustExceptions,
  TlpOSSystemTrust;

const
  TimeoutMs = 15000;
  // a three-tier EC P-256 chain (root -> issuer -> leaf, valid to 2099), generated once for the
  // test suite; the leaf is presented alone and its issuer travels only as a context intermediate
  RootHex =
    '3082018330820129a003020102020101300a06082a8648ce3d040302302831263024' +
    '06035504030c1d546c734c696220496e7465726d656469617465205465737420526f' +
    '6f743020170d3230303130313030303030305a180f32303939313233313030303030' +
    '305a30283126302406035504030c1d546c734c696220496e7465726d656469617465' +
    '205465737420526f6f743059301306072a8648ce3d020106082a8648ce3d03010703' +
    '420004f9db87b097ea6fa97afc1c42a5cc9aeb873c347f95bc4c66a8aa52a805a632' +
    'efba1056a5f1a27a3d0c4aa0b0c5150aa4a8d697d8e95b500bd92499c9ff5e34eba3' +
    '423040300f0603551d130101ff040530030101ff300e0603551d0f0101ff04040302' +
    '0106301d0603551d0e0416041403543ef858d32b61523ab957e15f646d4599a8f630' +
    '0a06082a8648ce3d040302034800304502203c1c665eced0d2b6b95bb15eb7fae0e6' +
    'd437e485d67cd265b72a310cfa7b1cb9022100ffbe294b1c28859abf8323eed2cf18' +
    'f8adcf03f993385c90bafe02282cb87352';
  IssuerHex =
    '308201a53082014ca003020102020102300a06082a8648ce3d040302302831263024' +
    '06035504030c1d546c734c696220496e7465726d656469617465205465737420526f' +
    '6f743020170d3230303130313030303030305a180f32303939313233313030303030' +
    '305a302a3128302606035504030c1f546c734c696220496e7465726d656469617465' +
    '2054657374204973737565723059301306072a8648ce3d020106082a8648ce3d0301' +
    '0703420004500990e304283c6c33ffba30ebf39aca9e2c8718562e72be0006cb6d3b' +
    '1135cbdcd8c372f2186ca80b3197298183a6f181f5617ea741da91166019c215749e' +
    '8fa3633061300f0603551d130101ff040530030101ff300e0603551d0f0101ff0404' +
    '03020106301d0603551d0e04160414e1f85fe9774c4a3f8719a76d5e3733c9996075' +
    '10301f0603551d2304183016801403543ef858d32b61523ab957e15f646d4599a8f6' +
    '300a06082a8648ce3d040302034700304402206b97303c3f1bfba955f78180e23ffe' +
    'bacc0951b6b15b17af5f8ac5aa79df79cf022047c5fee42a8a2a2dd08908f18c4ff5' +
    '77893e2eeb81fa316f2ce4eb565cf54269';
  LeafHex =
    '308201c430820169a003020102020103300a06082a8648ce3d040302302a31283026' +
    '06035504030c1f546c734c696220496e7465726d6564696174652054657374204973' +
    '737565723020170d3230303130313030303030305a180f3230393931323331303030' +
    '3030305a30143112301006035504030c096c6f63616c686f73743059301306072a86' +
    '48ce3d020106082a8648ce3d0301070342000453d8abdee6dc9517f341845506a233' +
    '0ba0f1107c4cc08d3615490d9f2b3e64ee0f598762ef41f985f70e6a136863f2887d' +
    '635aae5d2233618d742c5d8ca920dfa3819330819030090603551d1304023000300e' +
    '0603551d0f0101ff040403020780301d0603551d250416301406082b060105050703' +
    '0106082b0601050507030230140603551d11040d300b82096c6f63616c686f737430' +
    '1d0603551d0e04160414a8da8fd6bdbf7daa83446dea3fe1d10f185f5400301f0603' +
    '551d23041830168014e1f85fe9774c4a3f8719a76d5e3733c999607510300a06082a' +
    '8648ce3d0403020349003046022100b99e56131479b565f9b1809270038bbd880a77' +
    '791faab7835eb2ec306b551f21022100f5b368512d9e9fdaad508351ec1edbd5e1da' +
    '02fc37ca9ae7374b3b896cdcb197';

{ TSystemTrustDemoRunner }

class function TSystemTrustDemoRunner.RunSystemTrustGet(const AUrl: string): string;
var
  LHttp: TIdHTTP;
  LIO: TTlsLibIOHandlerSocket;
  LBody: string;
begin
  LHttp := TIdHTTP.Create(nil);
  try
    LIO := TTlsLibIOHandlerSocket.Create(LHttp);
    // Trust the OS store only - no RootCertFile, no CustomTrustStore. The platform
    // X509TrustManager renders the verdict over JNI.
    LIO.SSLOptions.UseSystemTrust := True;
    LHttp.IOHandler := LIO;
    LHttp.HandleRedirects := True;
    LHttp.ConnectTimeout := TimeoutMs;
    LHttp.ReadTimeout := TimeoutMs;
    LHttp.Request.UserAgent := 'TlsLib4Pascal-SystemTrust';
    try
      LBody := LHttp.Get(AUrl);
      Result := Format('PASS: %d bytes over OS-verified TLS (status %d)',
        [Length(LBody), LHttp.ResponseCode]);
    except
      on E: EIdSocketError do
        Result := 'SKIP: network unreachable (' + E.Message + ')';
      on E: ETlsStreamError do
        if E.HasAlert then
          Result := Format('FAIL: TLS alert %d - %s', [Ord(E.Alert), E.Message])
        else
          Result := 'FAIL: ' + E.Message;
      on E: Exception do
        Result := Format('FAIL: %s: %s', [E.ClassName, E.Message]);
    end;
  finally
    LHttp.Free;
  end;
end;

class function TSystemTrustDemoRunner.ClientContext(
  const AIntermediates: TArray<TBytes>): TClientTrustContext;
begin
  Result := Default(TClientTrustContext);
  Result.Pkix := TDefaultPkixProvider.Create as IPkixProvider;
  Result.Clock := TSystemClock.Create as ITlsClock;
  Result.TrustStore := TTrustAnchorStore.Create(
    TArray<TBytes>.Create(TDataEncoding.HexDecode(RootHex)));
  Result.ChainLimits := TCertificateChainLimits.Defaults;
  Result.RevocationPosture := TRevocationPosture.Soft;
  Result.Deferral := TVerdictDeferral.None;
  Result.StrengthPolicy := TCertificateStrengthPolicy.Defaults;
  Result.AdvertisedSignatureSchemes := TArray<UInt16>.Create(
    TSignatureSchemes.EcdsaSecp256r1Sha256);
  Result.Intermediates := AIntermediates;
end;

class function TSystemTrustDemoRunner.ServerContext(
  const AIntermediates: TArray<TBytes>): TServerTrustContext;
begin
  Result := Default(TServerTrustContext);
  Result.Pkix := TDefaultPkixProvider.Create as IPkixProvider;
  Result.Clock := TSystemClock.Create as ITlsClock;
  Result.CheckHostName := True;
  Result.ChainLimits := TCertificateChainLimits.Defaults;
  Result.RevocationPosture := TRevocationPosture.Soft;
  Result.Deferral := TVerdictDeferral.None;
  Result.StrengthPolicy := TCertificateStrengthPolicy.Defaults;
  Result.AdvertisedSignatureSchemes := TArray<UInt16>.Create(
    TSignatureSchemes.EcdsaSecp256r1Sha256);
  Result.Intermediates := AIntermediates;
end;

class function TSystemTrustDemoRunner.VerifyClient(const AIntermediates,
  AChain: TArray<TBytes>; out AAlert: TTlsAlertDescription): Boolean;
var
  LSource: IClientCertificateVerifierSource;
  LVerifier: IClientCertificateVerifier;
  LVerified: TVerifiedChain;
begin
  LSource := TOSSystemTrust.ClientVerifierSource(TSystemTrustFetch.CacheOnly);
  LVerifier := LSource.CreateClientVerifier(ClientContext(AIntermediates));
  Result := LVerifier.VerifyClientCertificate(AChain, LVerified, AAlert);
end;

class function TSystemTrustDemoRunner.CheckIntermediates: string;
var
  LLeaf, LIssuer: TBytes;
  LAlert: TTlsAlertDescription;
begin
  LLeaf := TDataEncoding.HexDecode(LeafHex);
  LIssuer := TDataEncoding.HexDecode(IssuerHex);
  if not VerifyClient(TArray<TBytes>.Create(LIssuer), TArray<TBytes>.Create(LLeaf), LAlert) then
    Exit(Format('FAIL: intermediates: a leaf-only chain was refused though its issuer was ' +
      'supplied (alert %d)', [Ord(LAlert)]));
  if VerifyClient(nil, TArray<TBytes>.Create(LLeaf), LAlert) then
    Exit('FAIL: intermediates: the same leaf verified with no intermediate supplied');
  Result := 'PASS: intermediates: leaf-only chain verified through a supplied intermediate and ' +
    'was refused without it';
end;

class function TSystemTrustDemoRunner.CheckEmptyChain: string;
var
  LInter: TArray<TBytes>;
  LAlert: TTlsAlertDescription;
  LServer: IServerCertificateVerifierSource;
  LVerifier: IServerCertificateVerifier;
  LVerified: TVerifiedChain;
begin
  LInter := TArray<TBytes>.Create(TDataEncoding.HexDecode(IssuerHex));
  if VerifyClient(LInter, nil, LAlert) then
    Exit('FAIL: empty chain: a client verification of an empty chain succeeded');
  if LAlert <> TTlsAlertDescription.BadCertificate then
    Exit(Format('FAIL: empty chain: client alert %d, expected bad_certificate', [Ord(LAlert)]));
  LServer := TOSSystemTrust.ServerVerifierSource(TSystemTrustFetch.CacheOnly);
  LVerifier := LServer.CreateServerVerifier(ServerContext(LInter));
  if LVerifier.VerifyServerCertificate(nil, TServerName.DnsName('localhost'), nil, LVerified,
    LAlert) then
    Exit('FAIL: empty chain: a server verification of an empty chain succeeded');
  if LAlert <> TTlsAlertDescription.BadCertificate then
    Exit(Format('FAIL: empty chain: server alert %d, expected bad_certificate', [Ord(LAlert)]));
  Result := 'PASS: empty chain: refused with bad_certificate on both roles';
end;

class function TSystemTrustDemoRunner.CheckLiveFetch: string;
begin
  try
    TOSSystemTrust.ClientVerifierSource(TSystemTrustFetch.Live);
  except
    on E: ESystemTrustUnsupportedTlsLibException do
      Exit('PASS: live fetch: refused up front, so no live deadline is silently dropped');
  end;
  Result := 'INFO: live fetch: accepted, so this engine fetches live revocation (expected on ' +
    'Windows and Apple, not on Android)';
end;

class function TSystemTrustDemoRunner.Run(const AUrl: string): TArray<string>;
var
  LChecks: TArray<string>;
  LI: Integer;
begin
  LChecks := RunChecks;
  SetLength(Result, System.Length(LChecks) + 2);
  Result[0] := RunSystemTrustGet(AUrl);
  Result[1] := 'OS-delegate checks:';
  for LI := 0 to System.High(LChecks) do
    Result[LI + 2] := '  ' + LChecks[LI];
end;

class function TSystemTrustDemoRunner.RunChecks: TArray<string>;
begin
  SetLength(Result, 3);
  try
    Result[0] := CheckIntermediates;
  except
    on E: Exception do
      Result[0] := Format('FAIL: intermediates: %s: %s', [E.ClassName, E.Message]);
  end;
  try
    Result[1] := CheckEmptyChain;
  except
    on E: Exception do
      Result[1] := Format('FAIL: empty chain: %s: %s', [E.ClassName, E.Message]);
  end;
  try
    Result[2] := CheckLiveFetch;
  except
    on E: Exception do
      Result[2] := Format('FAIL: live fetch: %s: %s', [E.ClassName, E.Message]);
  end;
end;

end.
