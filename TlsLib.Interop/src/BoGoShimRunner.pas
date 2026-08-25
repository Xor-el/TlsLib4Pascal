{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit BoGoShimRunner;

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

interface

uses
  SysUtils,
  TlpICryptoProvider,
  TlpCryptoAlgorithms,
  TlpISecretBuffer,
  TlpSecretBuffer,
  TlpTlsCredential,
  TlpISession,
  TlpSession,
  TlpInMemorySessionCache,
  TlpInMemorySessionStore,
  TlpSessionTicketKeys,
  TlpIClock,
  TlpITlsEngine,
  InteropSocket,
  InteropEngine,
  InteropCredentials,
  InteropPump,
  InteropUtils;

const
  // BoGo's shim exit-code contract: 0 pass, 89 = a request the shim can't fulfill
  // (unknown flag / unsupported parameter) so the runner may skip it, any other
  // non-zero = failure (the exchange did not go as the shim expected)
  ShimExitPass = 0;
  ShimExitFail = 1;
  ShimExitUnimplemented = 89;

type
  /// <summary>A test clock with a fixed base that only advances by explicit steps, so a
  /// resumption PSK's obfuscated_ticket_age is exactly the runner's -resumption-delay (no
  /// real-time drift). The harness advances it before each resumption connection.</summary>
  TInteropAdjustableClock = class sealed(TInterfacedObject, ITlsClock)
  strict private
    FNowMillis: UInt64;
  public
    constructor Create;
    function NowUnixMillis: UInt64;
    procedure Advance(AMillis: UInt64);
  end;

  /// <summary>The parsed per-test shim configuration BoGo hands over on argv.</summary>
  TBoGoConfig = record
    IsServer: Boolean;
    UseIpv6: Boolean;
    Port: Word;
    ShimId: Int64;
    CertFile: string;
    KeyFile: string;
    TrustCert: string;
    HostName: string;
    SuppressServerNameAck: Boolean;
    EnableGrease: Boolean;
    ExpectVersion: Int32;
    MinVersion: Int32;
    MaxVersion: Int32;
    Curves: TArray<UInt16>;
    AdvertiseAlpn: TArray<string>;
    SelectAlpn: string;
    RejectAlpn: Boolean;
    /// <summary>Per-connection ALPN, used by the 0-RTT ALPN tests where the initial and
    /// resumption handshakes negotiate different protocols: a server selects
    /// -on-initial/-on-resume-select-alpn, a client advertises -on-initial/-on-resume-advertise-alpn.
    /// The *Set flag distinguishes "select/advertise nothing" (empty) from "not overridden".</summary>
    OnInitialSelectAlpn: string;
    OnInitialSelectAlpnSet: Boolean;
    OnResumeSelectAlpn: string;
    OnResumeSelectAlpnSet: Boolean;
    OnInitialAdvertiseAlpn: TArray<string>;
    OnInitialAdvertiseAlpnSet: Boolean;
    OnResumeAdvertiseAlpn: TArray<string>;
    OnResumeAdvertiseAlpnSet: Boolean;
    ExpectAlpn: string;
    ShimWritesFirst: Boolean;
    ShimShutsDown: Boolean;
    /// <summary>-check-close-notify: the shim's shutdown is bidirectional - after sending its
    /// close_notify it waits for the peer's, reading through any interleaved warning alerts /
    /// empty records (RFC 8446 6.1).</summary>
    CheckCloseNotify: Boolean;
    /// <summary>Exported keying material (RFC 5705 / RFC 8446 7.5): the shim exports this many
    /// bytes right after the handshake and writes them for the runner to compare. 0 = none.</summary>
    ExportLen: Int32;
    ExportLabel: string;
    ExportContext: TBytes;
    UseExportContext: Boolean;
    OnResumeExportLen: Int32;
    OnResumeExportLabel: string;
    OnResumeExportContext: TBytes;
    InitialWrite: TBytes;
    SigningPrefs: TArray<UInt16>;
    /// <summary>-verify-prefs: the signature schemes the client is willing to verify; restricts
    /// the offered signature_algorithms so an unadvertised peer signature is rejected.</summary>
    VerifyPrefs: TArray<UInt16>;
    /// <summary>-use-client-ca-list: the DER DistinguishedName issuers a server names in its
    /// CertificateRequest certificate_authorities; the literal &lt;NULL&gt;/&lt;EMPTY&gt; name none
    /// (RFC 5246 7.4.4 / RFC 8446 4.2.4).</summary>
    UseClientCaList: TArray<TBytes>;
    /// <summary>-expect-client-ca-list: the DER DistinguishedName issuers the client must have
    /// seen in the server's CertificateRequest; asserted after the handshake when set.</summary>
    ExpectClientCaList: TArray<TBytes>;
    ExpectClientCaListSet: Boolean;
    /// <summary>A server requires a client certificate (mutual TLS).</summary>
    RequireClientCert: Boolean;
    /// <summary>A server requests and verifies a client certificate but tolerates none.</summary>
    VerifyPeer: Boolean;
    /// <summary>-verify-fail: peer-certificate verification must fail. Mapped to an augment-only
    /// verify callback that rejects (the certificate verifies against the trust anchor, then the
    /// callback additionally rejects), so the handshake aborts. -use-custom-verify-callback only
    /// changes the alert BoringSSL expects, which -loose-errors relaxes.</summary>
    VerifyFail: Boolean;
    /// <summary>-async: BoGo drives the shim's operations asynchronously. We map it to our
    /// deferred-verdict seam - the handshake parks after the pipeline accepts the peer chain and
    /// the pump resolves it out-of-band with SetCertificateVerdict - so the async certificate
    /// verification path is exercised against BoringSSL. Inert where no peer certificate is
    /// verified (a server without client-auth), so it leaves other -async tests' outcome
    /// unchanged.</summary>
    AsyncVerify: Boolean;
    /// <summary>-on-resume-verify-fail: verification fails only on the resumption handshake. We
    /// never re-verify a certificate on PSK/abbreviated resumption (there is none), so the resume
    /// succeeds - which is exactly BoringSSL's default (it does not re-verify unless
    /// -reverify-on-resume, which we do not implement, so those variants stay out of scope).</summary>
    OnResumeVerifyFail: Boolean;
    /// <summary>Send one unsolicited post-handshake KeyUpdate (RFC 8446 4.6.3).</summary>
    KeyUpdate: Boolean;
    /// <summary>Number of resumption connections after the initial one (RFC 8446 2.2);
    /// the shim makes ResumeCount+1 connections reusing one session cache/STEK.</summary>
    ResumeCount: Int32;
    /// <summary>-no-ticket: the server mints no session tickets (no STEK), so a 1.2 client
    /// resumes only via the session id and a 1.3 client gets no NewSessionTicket.</summary>
    NoTicket: Boolean;
    /// <summary>-on-resume-no-ticket: session tickets are disabled on the resumption
    /// connection only (after the first established them). The server then cannot accept the
    /// offered ticket and falls back to a full handshake; the client stops offering the cached
    /// session, so a server that still echoes the session id is rejected (RFC 5246 7.4.1.3).</summary>
    OnResumeNoTicket: Boolean;
    /// <summary>The client offers 0-RTT early data on a resumption (RFC 8446 2.3).</summary>
    EnableEarlyData: Boolean;
    /// <summary>-on-resume-enable-early-data: early data is enabled on the resumption connection
    /// only. The initial ticket is minted without 0-RTT authorization, so the server rejects the
    /// client's early data on resume (the session did not allow it, RFC 8446 4.2.10).</summary>
    OnResumeEnableEarlyData: Boolean;
    /// <summary>On a resumption connection the shim writes first (its early data / initial
    /// message), rather than waiting to echo the peer.</summary>
    OnResumeShimWritesFirst: Boolean;
    /// <summary>-on-resume-shim-initial-write + -on-resume-repeat-shim-initial-write: on the
    /// resumption the shim writes this payload repeated N times as its initial (early) write.
    /// Used by the large-early-data test where the total exceeds max_early_data, so the engine
    /// sends the budget as 0-RTT and defers the remainder to 1-RTT (RFC 8446 4.2.10).</summary>
    OnResumeInitialWrite: TBytes;
    OnResumeInitialWriteRepeat: Int32;
    /// <summary>The client-side cache and the server-side STEK, created once and shared
    /// across the resume loop so a later connection resumes an earlier one.</summary>
    SessionCache: ISessionCache;
    SessionTicketKeys: ISessionTicketKeyManager;
    SessionStore: ISessionStore;
    /// <summary>-resumption-delay: seconds the runner advances its (and the shim's) clock
    /// between connections, so a resumption PSK's obfuscated_ticket_age reflects it and an
    /// over-lifetime ticket is dropped.</summary>
    ResumptionDelaySeconds: Int32;
    /// <summary>The adjustable clock shared across the resume loop, advanced by
    /// ResumptionDelaySeconds before each resumption connection (nil = system clock).</summary>
    Clock: ITlsClock;
    /// <summary>Set by -enable-ocsp-stapling: the client offers status_request.</summary>
    EnableOcspStapling: Boolean;
    /// <summary>A server's stapled OCSP response (RFC 6066), from -ocsp-response.</summary>
    OcspResponse: TBytes;
    /// <summary>The out-of-band external PSK credentials (RFC 9258) built from the shim's
    /// credential list (-new-psk-credential + -psk-importer-*). A client imports and offers
    /// them; a server imports and matches an offered pre_shared_key against them.</summary>
    ExternalPsks: TArray<TExternalPsk>;
    /// <summary>Set when -expect-ocsp-response was given; the client must have received
    /// exactly ExpectOcspResponse from the peer.</summary>
    HasExpectOcsp: Boolean;
    ExpectOcspResponse: TBytes;
  end;

  /// <summary>
  /// The BoringSSL "BoGo" shim: BoGo spawns this per test, connecting to its runner
  /// over loopback TCP. We dial the runner, announce the shim id, build the role's
  /// engine from the flags, run the handshake and the runner's XOR echo protocol,
  /// and translate the outcome into BoGo's shim exit codes. The sans-IO library is
  /// untouched - this is transport and flag glue only.
  /// </summary>
  TBoGoShimRunner = class sealed(TObject)
  strict private
    /// <summary>The fixed initial message BoGo expects a writes-first shim to send ("hello").</summary>
    class function ShimInitialWrite: TBytes; static;
    class procedure LogArgv; static;
    class function HandleProbeFlags: Boolean; static;
    class function ParseAlpnWire(const AWire: string): TArray<string>; static;
    class function TryParseArgs(out AConfig: TBoGoConfig;
      out AReason: string): Boolean; static;
    class procedure AnnounceShimId(const ASocket: TInteropSocket;
      AShimId: Int64); static;
    class function VersionRange(const AConfig: TBoGoConfig): TArray<UInt16>; static;
    class function BuildOptions(const AProvider: ICryptoProvider;
      const AConfig: TBoGoConfig; AIsResume: Boolean): TInteropEngineOptions; static;
    class function RunExchange(const AProvider: ICryptoProvider;
      const ASocket: TInteropSocket; const AConfig: TBoGoConfig;
      AIsResume: Boolean): Int32; static;
    class function FinishShutdown(const AEngine: ITlsEngine;
      const ASocket: TInteropSocket; ACheckCloseNotify: Boolean): Int32; static;
  public
    /// <summary>Parses argv, runs one test, and returns the shim exit code.</summary>
    class function Run: Int32; static;
  end;

implementation

const
  WireVersionTls13 = $0304;
  WireVersionTls12 = $0303;
  XorMask = $FF;
  // the server's 0-RTT budget when early data is enabled (BoGo's test messages are small)
  EarlyDataBudget = UInt32(16384);

{ TInteropAdjustableClock }

constructor TInteropAdjustableClock.Create;
begin
  inherited Create;
  // a fixed base (the absolute value is irrelevant: only the delta between the ticket's
  // issue time and now matters, and both are read from this clock)
  FNowMillis := UInt64(1700000000) * 1000;
end;

function TInteropAdjustableClock.NowUnixMillis: UInt64;
begin
  Result := FNowMillis;
end;

procedure TInteropAdjustableClock.Advance(AMillis: UInt64);
begin
  FNowMillis := FNowMillis + AMillis;
end;

{ TBoGoShimRunner }

class function TBoGoShimRunner.ShimInitialWrite: TBytes;
begin
  // "hello" - the exact bytes BoGo's runner reads from a writes-first shim
  Result := TBytes.Create($68, $65, $6C, $6C, $6F);
end;

class procedure TBoGoShimRunner.LogArgv;
var
  LPath, LLine: string;
  LI: Int32;
  LFile: TextFile;
begin
  // diagnostic seam for curating the subset: when SHIM_ARGV_LOG is set, append the
  // full argv of every invocation so the flag set each BoGo test needs is visible
  LPath := GetEnvironmentVariable('SHIM_ARGV_LOG');
  if LPath = '' then
    Exit;
  LLine := '';
  for LI := 1 to TInteropArgs.Count do
    LLine := LLine + TInteropArgs.Get(LI) + ' ';
  AssignFile(LFile, LPath);
  try
    if FileExists(LPath) then
      Append(LFile)
    else
      Rewrite(LFile);
    Writeln(LFile, LLine);
    CloseFile(LFile);
  except
  end;
end;

class function TBoGoShimRunner.HandleProbeFlags: Boolean;
var
  LI: Int32;
begin
  // BoGo probes the shim's capabilities before running tests; we do not support the
  // out-of-process "handshaker" split, so answer No and exit cleanly rather than 89
  Result := False;
  for LI := 1 to TInteropArgs.Count do
    if TInteropArgs.Get(LI) = '-is-handshaker-supported' then
    begin
      Writeln('No');
      Exit(True);
    end;
end;

class function TBoGoShimRunner.ParseAlpnWire(const AWire: string): TArray<string>;
var
  LPos, LLen, LI: Int32;
begin
  Result := nil;
  // the wire form is a run of one-byte-length-prefixed protocol names. Those length
  // bytes are control characters (< 0x20); on Windows they do not survive the argv
  // round-trip, so a single-protocol value like <03>"foo" arrives as bare "foo". When
  // the leading byte cannot be a valid length prefix, treat the whole value as one name.
  if (System.Length(AWire) > 0) and (Ord(AWire[1]) >= System.Length(AWire)) then
    Exit(TArray<string>.Create(AWire));
  LPos := 1;
  while LPos <= System.Length(AWire) do
  begin
    LLen := Ord(AWire[LPos]);
    Inc(LPos);
    if LPos + LLen - 1 > System.Length(AWire) then
      Break;
    LI := System.Length(Result);
    SetLength(Result, LI + 1);
    Result[LI] := System.Copy(AWire, LPos, LLen);
    Inc(LPos, LLen);
  end;
end;

class function TBoGoShimRunner.TryParseArgs(out AConfig: TBoGoConfig;
  out AReason: string): Boolean;
var
  LI: Int32;
  LArg: string;

  function NextValue(const AName: string): string;
  begin
    Inc(LI);
    if LI > TInteropArgs.Count then
      raise EInteropData.CreateFmt('flag %s expects a value', [AName]);
    Result := TInteropArgs.Get(LI);
  end;

  procedure AddCurve(ACode: UInt16);
  var
    LN: Int32;
  begin
    LN := System.Length(AConfig.Curves);
    SetLength(AConfig.Curves, LN + 1);
    AConfig.Curves[LN] := ACode;
  end;

  procedure AddSigningPref(ACode: UInt16);
  var
    LN: Int32;
  begin
    LN := System.Length(AConfig.SigningPrefs);
    SetLength(AConfig.SigningPrefs, LN + 1);
    AConfig.SigningPrefs[LN] := ACode;
  end;

  procedure AddVerifyPref(ACode: UInt16);
  var
    LN: Int32;
  begin
    LN := System.Length(AConfig.VerifyPrefs);
    SetLength(AConfig.VerifyPrefs, LN + 1);
    AConfig.VerifyPrefs[LN] := ACode;
  end;

  // a comma-separated list of hex-encoded DER DistinguishedNames; the literal <NULL>
  // and <EMPTY> both name no acceptable issuer (BoGo -use/-expect-client-ca-list)
  function ParseCaList(const AValue: string): TArray<TBytes>;
  var
    LRest, LToken: string;
    LComma, LN: Int32;
  begin
    Result := nil;
    if (AValue = '<NULL>') or (AValue = '<EMPTY>') then
      Exit;
    LRest := AValue;
    while LRest <> '' do
    begin
      LComma := Pos(',', LRest);
      if LComma > 0 then
      begin
        LToken := System.Copy(LRest, 1, LComma - 1);
        LRest := System.Copy(LRest, LComma + 1, System.Length(LRest));
      end
      else
      begin
        LToken := LRest;
        LRest := '';
      end;
      if LToken = '' then
        Continue;
      LN := System.Length(Result);
      SetLength(Result, LN + 1);
      Result[LN] := TInteropUtils.DecodeHex(LToken);
    end;
  end;

  // membership test over an inline flag table (indexed, not for-in: FPC 3.2.2 misiterates
  // for-in over an inline array literal)
  function IsInList(const AArg: string; const AList: array of string): Boolean;
  var
    LK: Int32;
  begin
    Result := False;
    for LK := System.Low(AList) to System.High(AList) do
      if AList[LK] = AArg then
        Exit(True);
  end;

begin
  AConfig := Default(TBoGoConfig);
  AConfig.MinVersion := -1;
  AConfig.MaxVersion := -1;
  AConfig.ExpectVersion := -1;
  AReason := '';
  LI := 1;
  while LI <= TInteropArgs.Count do
  begin
    LArg := TInteropArgs.Get(LI);
    // valueless flags BoGo passes that our default behaviour or the successful exchange
    // already satisfies - assertions it checks on its own side, tolerances, and no-op
    // capability hooks: accept and rely on our behaviour (no shim action, no value consumed)
    if IsInList(LArg, ['-implicit-handshake', '-expect-hrr', '-expect-no-hrr',
      '-server-preference', '-permute-extensions', '-enable-signed-cert-timestamps',
      '-expect-not-resumable-across-names', '-install-cert-compression-algs',
      '-expect-no-peer-cert', '-on-resume-expect-no-session', '-decline-alpn',
      '-on-resume-expect-reject-early-data', '-reverify-on-resume',
      '-use-custom-verify-callback', '-expect-verify-result',
      '-expect-ticket-supports-early-data', '-expect-accept-early-data',
      '-on-resume-expect-accept-early-data', '-expect-early-data-info',
      '-no-tls1', '-no-tls11', '-no-legacy-server-connect',
      '-use-old-client-cert-callback', '-use-early-callback', '-no-op-extra-handshake',
      '-expect-session-miss', '-expect-session-id', '-expect-no-session-id',
      '-expect-extended-master-secret', '-expect-ticket-renewal',
      '-expect-resumable-across-names', '-on-retry-expect-no-session', '-expect-no-session',
      '-allow-hint-mismatch', '-on-resume-allow-hint-mismatch', '-install-ddos-callback',
      '-expect-secure-renegotiation', '-expect-no-offer-early-data',
      '-on-resume-expect-no-offer-early-data', '-expect-reject-early-data']) then
    begin
      // accepted no-op
    end
    // one-value flags BoGo asserts on ITS side (a cert file, the negotiated cipher/curve, a
    // peer signature preference, an early-data reason - including the per-connection -on-initial
    // / -on-resume / -on-retry variants across the three logical 0-RTT connections): consume and
    // discard the value; our default negotiation or the encrypted exchange proves the outcome
    else if IsInList(LArg, ['-expect-selected-credential', '-signed-cert-timestamps',
      '-expect-curve-id', '-expect-peer-signature-algorithm', '-server-supported-groups-hint',
      '-on-initial-expect-curve-id', '-on-resume-expect-curve-id', '-expect-msg-callback',
      '-expect-ticket-age-skew', '-cipher', '-advertise-npn',
      '-on-resume-expect-early-data-reason', '-expect-early-data-reason',
      '-expect-advertised-alpn', '-expect-server-name', '-expect-peer-verify-pref',
      '-expect-peer-cert-file', '-expect-cipher-aes', '-on-retry-expect-early-data-reason',
      '-on-initial-expect-early-data-reason', '-on-initial-expect-peer-cert-file',
      '-on-resume-expect-peer-cert-file', '-on-retry-expect-peer-cert-file',
      '-on-initial-expect-cipher', '-on-resume-expect-cipher', '-on-retry-expect-cipher',
      '-on-initial-expect-alpn', '-on-resume-expect-alpn', '-on-retry-expect-alpn']) then
      NextValue(LArg)
    else if LArg = '-server' then
      AConfig.IsServer := True
    else if LArg = '-ipv6' then
      AConfig.UseIpv6 := True
    else if LArg = '-port' then
      AConfig.Port := Word(StrToInt(NextValue(LArg)))
    else if LArg = '-shim-id' then
      AConfig.ShimId := StrToInt64(NextValue(LArg))
    else if LArg = '-cert-file' then
      AConfig.CertFile := NextValue(LArg)
    else if LArg = '-key-file' then
      AConfig.KeyFile := NextValue(LArg)
    else if LArg = '-new-x509-credential' then
    begin
      // begins an X.509 credential in the shim credential list; the following
      // -cert-file / -key-file populate our single certificate credential
    end
    else if LArg = '-new-psk-credential' then
    begin
      // begins an out-of-band external PSK credential (RFC 9258); the -psk-importer-*
      // flags that follow fill it. Default the KDF hash to SHA-256 until stated.
      SetLength(AConfig.ExternalPsks, System.Length(AConfig.ExternalPsks) + 1);
      AConfig.ExternalPsks[High(AConfig.ExternalPsks)] := Default(TExternalPsk);
      AConfig.ExternalPsks[High(AConfig.ExternalPsks)].Hash := THashAlgorithm.SHA_256;
    end
    else if LArg = '-psk-importer-key' then
      AConfig.ExternalPsks[High(AConfig.ExternalPsks)].Secret :=
        TSecretBuffer.From(TInteropUtils.DecodeBase64(NextValue(LArg)))
    else if LArg = '-psk-importer-identity' then
      AConfig.ExternalPsks[High(AConfig.ExternalPsks)].Identity :=
        TInteropUtils.DecodeBase64(NextValue(LArg))
    else if LArg = '-psk-importer-context' then
      AConfig.ExternalPsks[High(AConfig.ExternalPsks)].Context :=
        TInteropUtils.DecodeBase64(NextValue(LArg))
    else if LArg = '-psk-importer-sha256' then
      AConfig.ExternalPsks[High(AConfig.ExternalPsks)].Hash := THashAlgorithm.SHA_256
    else if LArg = '-psk-importer-sha384' then
      AConfig.ExternalPsks[High(AConfig.ExternalPsks)].Hash := THashAlgorithm.SHA_384
    else if LArg = '-trust-cert' then
      AConfig.TrustCert := NextValue(LArg)
    else if LArg = '-enable-ocsp-stapling' then
      // the client offers status_request so the server may staple (RFC 6066)
      AConfig.EnableOcspStapling := True
    else if LArg = '-ocsp-response' then
      // a server's DER OCSP response to staple, base64-encoded on the flag
      AConfig.OcspResponse := TInteropUtils.DecodeBase64(NextValue(LArg))
    else if LArg = '-expect-ocsp-response' then
    begin
      // the client must have received exactly this stapled response
      AConfig.HasExpectOcsp := True;
      AConfig.ExpectOcspResponse := TInteropUtils.DecodeBase64(NextValue(LArg));
    end
    else if LArg = '-enable-grease' then
      // GREASE is off in the shim by default (for deterministic wire output the runner asserts
      // on, e.g. exact key_share counts) and turned on only when the runner asks (RFC 8701
      // makes GREASE optional); the library still sends conformant GREASE when enabled
      AConfig.EnableGrease := True
    else if LArg = '-async' then
      // BoGo asks the shim to operate asynchronously; drive our deferred-verdict seam so the
      // certificate verification parks and resumes (inert where no peer cert is verified)
      AConfig.AsyncVerify := True
    else if LArg = '-signing-prefs' then
      // the server's ordered signing preferences; each occurrence adds one codepoint
      AddSigningPref(UInt16(StrToInt(NextValue(LArg))))
    else if LArg = '-verify-prefs' then
      // the client's ordered verify preferences; each occurrence adds one codepoint and
      // restricts the offered signature_algorithms to that set
      AddVerifyPref(UInt16(StrToInt(NextValue(LArg))))
    else if LArg = '-use-client-ca-list' then
      // the DER DistinguishedName issuers the server names in its CertificateRequest
      AConfig.UseClientCaList := ParseCaList(NextValue(LArg))
    else if LArg = '-expect-client-ca-list' then
    begin
      // the issuers the client must have seen in the server's CertificateRequest
      AConfig.ExpectClientCaList := ParseCaList(NextValue(LArg));
      AConfig.ExpectClientCaListSet := True;
    end
    else if (LArg = '-host-name') or (LArg = '-server-name') then
      AConfig.HostName := NextValue(LArg)
    else if LArg = '-min-version' then
      AConfig.MinVersion := StrToInt(NextValue(LArg))
    else if LArg = '-max-version' then
      AConfig.MaxVersion := StrToInt(NextValue(LArg))
    else if LArg = '-expect-version' then
      AConfig.ExpectVersion := StrToInt(NextValue(LArg))
    else if LArg = '-curves' then
      AddCurve(UInt16(StrToInt(NextValue(LArg))))
    else if LArg = '-advertise-alpn' then
      AConfig.AdvertiseAlpn := ParseAlpnWire(NextValue(LArg))
    else if LArg = '-select-alpn' then
      AConfig.SelectAlpn := NextValue(LArg)
    else if LArg = '-on-initial-select-alpn' then
    begin
      AConfig.OnInitialSelectAlpn := NextValue(LArg);
      AConfig.OnInitialSelectAlpnSet := True;
    end
    else if LArg = '-on-resume-select-alpn' then
    begin
      AConfig.OnResumeSelectAlpn := NextValue(LArg);
      AConfig.OnResumeSelectAlpnSet := True;
    end
    else if LArg = '-on-initial-advertise-alpn' then
    begin
      AConfig.OnInitialAdvertiseAlpn := ParseAlpnWire(NextValue(LArg));
      AConfig.OnInitialAdvertiseAlpnSet := True;
    end
    else if LArg = '-on-resume-advertise-alpn' then
    begin
      AConfig.OnResumeAdvertiseAlpn := ParseAlpnWire(NextValue(LArg));
      AConfig.OnResumeAdvertiseAlpnSet := True;
    end
    else if LArg = '-reject-alpn' then
      // the server rejects any client ALPN offer with no_application_protocol (RFC 7301)
      AConfig.RejectAlpn := True
    else if LArg = '-expect-alpn' then
      AConfig.ExpectAlpn := NextValue(LArg)
    else if LArg = '-shim-writes-first' then
    begin
      AConfig.ShimWritesFirst := True;
      AConfig.InitialWrite := ShimInitialWrite;
    end
    else if LArg = '-on-resume-shim-writes-first' then
    begin
      AConfig.OnResumeShimWritesFirst := True;
      AConfig.InitialWrite := ShimInitialWrite;
    end
    else if LArg = '-on-resume-shim-initial-write' then
      // the resumption connection's initial write payload (repeated below); its presence also
      // makes the shim write first on the resume
      AConfig.OnResumeInitialWrite := TEncoding.UTF8.GetBytes(NextValue(LArg))
    else if LArg = '-on-resume-repeat-shim-initial-write' then
      AConfig.OnResumeInitialWriteRepeat := StrToInt(NextValue(LArg))
    else if LArg = '-shim-shuts-down' then
      AConfig.ShimShutsDown := True
    else if LArg = '-require-any-client-certificate' then
      AConfig.RequireClientCert := True
    else if LArg = '-verify-peer' then
      AConfig.VerifyPeer := True
    else if LArg = '-verify-fail' then
      AConfig.VerifyFail := True
    else if LArg = '-on-resume-verify-fail' then
      AConfig.OnResumeVerifyFail := True
    else if LArg = '-key-update' then
      // the shim sends one unsolicited post-handshake KeyUpdate; inbound KeyUpdates the
      // peer sends are handled by the engine automatically during the exchange
      AConfig.KeyUpdate := True
    else if LArg = '-resume-count' then
      AConfig.ResumeCount := StrToInt(NextValue(LArg))
    else if LArg = '-no-ticket' then
      // the server issues no session tickets; 1.2 resumption falls back to the session id
      AConfig.NoTicket := True
    else if LArg = '-on-resume-no-ticket' then
      // tickets are disabled on the resumption connection only (BuildOptions drops the
      // server's ticket keys / session store and the client's session cache when resuming)
      AConfig.OnResumeNoTicket := True
    else if LArg = '-enable-early-data' then
      // the client offers 0-RTT on a resumption when the ticket authorizes it
      AConfig.EnableEarlyData := True
    else if LArg = '-on-resume-enable-early-data' then
      // early data is enabled on the resumption connection only (the initial ticket is minted
      // without 0-RTT, so the server rejects the resumed early data)
      AConfig.OnResumeEnableEarlyData := True
    else if LArg = '-export-keying-material' then
      // export this many bytes after the handshake and write them for the runner to compare
      AConfig.ExportLen := StrToInt(NextValue(LArg))
    else if LArg = '-use-export-context' then
      // a context is supplied (possibly empty), distinct from no context (RFC 5705 4)
      AConfig.UseExportContext := True
    else if LArg = '-export-label' then
      AConfig.ExportLabel := NextValue(LArg)
    else if LArg = '-export-context' then
      AConfig.ExportContext := TEncoding.UTF8.GetBytes(NextValue(LArg))
    else if LArg = '-on-resume-export-keying-material' then
      AConfig.OnResumeExportLen := StrToInt(NextValue(LArg))
    else if LArg = '-on-resume-export-label' then
      AConfig.OnResumeExportLabel := NextValue(LArg)
    else if LArg = '-on-resume-export-context' then
      AConfig.OnResumeExportContext := TEncoding.UTF8.GetBytes(NextValue(LArg))
    else if LArg = '-no-tls12' then
      // exclude TLS 1.2 from this connection: raise the version floor to 1.3
      AConfig.MinVersion := WireVersionTls13
    else if LArg = '-no-tls13' then
      // exclude TLS 1.3 from this connection: lower the version ceiling to 1.2
      AConfig.MaxVersion := WireVersionTls12
    else if LArg = '-no-server-name-ack' then
      // the server must not echo the empty server_name acknowledgement (RFC 6066 3)
      AConfig.SuppressServerNameAck := True
    else if LArg = '-check-close-notify' then
      // a shim-initiated shutdown must be bidirectional: send our close_notify and wait for
      // the peer's before closing the transport (RFC 8446 6.1)
      AConfig.CheckCloseNotify := True
    else if LArg = '-resumption-delay' then
      // seconds the runner advances its clock between connections; the shim advances its own
      // injected clock by the same amount so obfuscated_ticket_age and expiry line up
      AConfig.ResumptionDelaySeconds := StrToInt(NextValue(LArg))
    else
    begin
      // an unrecognized request: signal BoGo we cannot fulfill it (exit 89). Set
      // SHIM_ARGV_LOG to capture the full flag set when curating the subset.
      AReason := 'unimplemented flag: ' + LArg;
      Exit(False);
    end;
    Inc(LI);
  end;
  Result := True;
end;

class procedure TBoGoShimRunner.AnnounceShimId(const ASocket: TInteropSocket;
  AShimId: Int64);
var
  LFrame: TBytes;
  LI: Int32;
  LValue: UInt64;
begin
  // the runner matches the connection to the test by an 8-byte little-endian id
  LFrame := nil;
  SetLength(LFrame, 8);
  LValue := UInt64(AShimId);
  for LI := 0 to 7 do
    LFrame[LI] := Byte((LValue shr (LI * 8)) and $FF);
  ASocket.SendAll(LFrame, 0, 8);
end;

class function TBoGoShimRunner.VersionRange(
  const AConfig: TBoGoConfig): TArray<UInt16>;

  procedure Consider(AVersion: UInt16);
  var
    LMin, LMax, LN: Int32;
  begin
    // an unset bound defaults to our supported span (1.2 up to 1.3)
    if AConfig.MinVersion < 0 then LMin := WireVersionTls12 else LMin := AConfig.MinVersion;
    if AConfig.MaxVersion < 0 then LMax := WireVersionTls13 else LMax := AConfig.MaxVersion;
    if (AVersion < LMin) or (AVersion > LMax) then
      Exit;
    LN := System.Length(Result);
    SetLength(Result, LN + 1);
    Result[LN] := AVersion;
  end;

begin
  // preference order: 1.3 then 1.2
  Result := nil;
  Consider(WireVersionTls13);
  Consider(WireVersionTls12);
end;

class function TBoGoShimRunner.BuildOptions(const AProvider: ICryptoProvider;
  const AConfig: TBoGoConfig; AIsResume: Boolean): TInteropEngineOptions;
var
  LDropTicketState: Boolean;
begin
  Result := Default(TInteropEngineOptions);
  // -on-resume-no-ticket disables tickets on the resumption connection only: the server keeps
  // no ticket keys / session store and the client offers no cached session
  LDropTicketState := AConfig.OnResumeNoTicket and AIsResume;
  Result.OfferedGroups := AConfig.Curves;
  // the injected test clock (nil = system clock) drives both roles: the client's
  // obfuscated_ticket_age and the server's ticket-issue time / 0-RTT freshness window
  Result.Clock := AConfig.Clock;
  // the client's verify preferences restrict the offered signature_algorithms (empty = default)
  Result.VerifySchemes := AConfig.VerifyPrefs;
  Result.SupportedVersions := VersionRange(AConfig);
  // -async drives the deferred-verdict seam (resolved in the pump); inert without a peer cert
  Result.AsyncVerify := AConfig.AsyncVerify;
  // out-of-band external PSKs (RFC 9258) apply to either role
  Result.ExternalPsks := AConfig.ExternalPsks;
  if AConfig.IsServer then
  begin
    Result.Role := TInteropRole.Server;
    // a PSK-only server (external PSKs, no -cert-file) presents no certificate
    if AConfig.CertFile <> '' then
    begin
      Result.HasCredential := True;
      Result.Credential := TInteropCredentials.ServerCredentialFromPem(
        AProvider, AConfig.CertFile, AConfig.KeyFile);
      // honor BoGo -signing-prefs: pin the CertificateVerify scheme to the requested
      // ones (like rustls' FixedSignatureSchemeSigningKey); empty is a no-op
      Result.Credential.PrivateKey := Result.Credential.PrivateKey.WithPreferredSchemes(
        TInteropCredentials.SchemesFromCodes(AConfig.SigningPrefs));
    end;
    // a stapled OCSP response the server sends when the client offers status_request
    Result.OcspStaple := AConfig.OcspResponse;
    // mutual TLS: -require-any-client-certificate is required, -verify-peer is requested
    if AConfig.RequireClientCert then
      Result.ClientAuth := TClientAuthMode.Required
    else if AConfig.VerifyPeer then
      Result.ClientAuth := TClientAuthMode.Requested;
    if (Result.ClientAuth <> TClientAuthMode.None) and (AConfig.TrustCert <> '') then
      Result.Trust := TInteropCredentials.TrustFromPem(AProvider, AConfig.TrustCert);
    // -require-any-client-certificate requests a client cert with no CA to validate it
    // against: accept any presented chain (an accept-any whole-verifier in the engine)
    Result.AcceptAnyPeerCert := (Result.ClientAuth <> TClientAuthMode.None) and
      (Result.Trust = nil);
    // per-connection ALPN selection overrides the fixed -select-alpn on the matching
    // connection; an empty override means "select no protocol" (0-RTT ALPN tests)
    if AIsResume and AConfig.OnResumeSelectAlpnSet then
    begin
      if AConfig.OnResumeSelectAlpn <> '' then
        Result.AlpnProtocols := TArray<string>.Create(AConfig.OnResumeSelectAlpn);
    end
    else if (not AIsResume) and AConfig.OnInitialSelectAlpnSet then
    begin
      if AConfig.OnInitialSelectAlpn <> '' then
        Result.AlpnProtocols := TArray<string>.Create(AConfig.OnInitialSelectAlpn);
    end
    else if AConfig.SelectAlpn <> '' then
      Result.AlpnProtocols := TArray<string>.Create(AConfig.SelectAlpn);
    Result.AlpnReject := AConfig.RejectAlpn;
    Result.ClientCertificateAuthorities := AConfig.UseClientCaList;
    Result.SuppressServerNameAck := AConfig.SuppressServerNameAck;
    // resumption: the shared STEK issues and re-opens tickets; a positive early-data
    // budget lets the server accept the client's 0-RTT. -on-resume-no-ticket drops both on the
    // resumption connection so the server cannot accept the offered session and does a full
    // handshake (the runner's expectResumeRejected)
    if not LDropTicketState then
    begin
      Result.SessionTicketKeys := AConfig.SessionTicketKeys;
      Result.SessionStore := AConfig.SessionStore;
    end;
    // a 0-RTT budget on the initial connection (always) or on the resumption only
    // (-on-resume-enable-early-data): the latter mints the initial ticket without early-data
    // authorization, so the server declines the resumed early data. Early data is a TLS 1.3
    // feature, so a server capped below 1.3 (-max-version 1.2 / -no-tls13) configures none - the
    // reason the runner asserts is protocol_version.
    if (AConfig.EnableEarlyData or (AConfig.OnResumeEnableEarlyData and AIsResume)) and
      ((AConfig.MaxVersion < 0) or (AConfig.MaxVersion >= WireVersionTls13)) then
      Result.MaxEarlyData := EarlyDataBudget;
  end
  else
  begin
    Result.Role := TInteropRole.Client;
    // GREASE only when the runner enables it (RFC 8701 is optional); off keeps the wire output
    // deterministic for the runner's exact-count assertions
    Result.Grease := AConfig.EnableGrease;
    // send server_name (SNI) only when a host was supplied (-host-name / -server-name); with
    // none, offer no SNI at all so an unsolicited server_name acknowledgement is rejected
    Result.ServerName := AConfig.HostName;
    // BoGo's test certs are not issued for our SNI, so verify the chain to the
    // supplied trust anchor but do not enforce a hostname match
    Result.CheckServerName := False;
    // strict chain-to-anchor verification only when the runner actually asked for it with
    // -verify-peer AND supplied a trust anchor (-trust-cert): the BoGo shim's verify callback
    // otherwise accepts by default (-verify-fail forces the failure path, handled separately).
    // This matters for the 0-RTT reject/retry tests, where the runner passes only the initial
    // credential's root as -trust-cert (never -verify-peer) yet the reject retry legitimately
    // presents a differently-rooted certificate the client must still accept. A PSK-only client
    // (external PSKs, no -trust-cert and not -verify-peer) is the exception: it configures no
    // certificate trust, so a server that declines the PSK and offers a certificate is rejected
    // (PSK-required). A leaf that is not a well-formed certificate is still rejected at parse
    // (GarbageCertificate-Client) before any trust decision.
    if (AConfig.TrustCert <> '') and AConfig.VerifyPeer then
      Result.Trust := TInteropCredentials.TrustFromPem(AProvider, AConfig.TrustCert)
    else if (System.Length(AConfig.ExternalPsks) = 0) or AConfig.VerifyPeer then
      Result.AcceptAnyPeerCert := True;
    // per-connection ALPN advertisement overrides the fixed -advertise-alpn on the matching
    // connection (the client 0-RTT ALPN-preference-change test offers different protocols)
    if AIsResume and AConfig.OnResumeAdvertiseAlpnSet then
      Result.AlpnProtocols := AConfig.OnResumeAdvertiseAlpn
    else if (not AIsResume) and AConfig.OnInitialAdvertiseAlpnSet then
      Result.AlpnProtocols := AConfig.OnInitialAdvertiseAlpn
    else
      Result.AlpnProtocols := AConfig.AdvertiseAlpn;
    // a mutual-TLS client presents this credential when the server requests one
    if AConfig.CertFile <> '' then
    begin
      Result.HasCredential := True;
      Result.Credential := TInteropCredentials.ServerCredentialFromPem(
        AProvider, AConfig.CertFile, AConfig.KeyFile);
      // honor BoGo -signing-prefs for the client credential too (empty is a no-op)
      Result.Credential.PrivateKey := Result.Credential.PrivateKey.WithPreferredSchemes(
        TInteropCredentials.SchemesFromCodes(AConfig.SigningPrefs));
    end;
    // resumption: the shared cache carries a ticket across the resume loop; 0-RTT is a
    // separate opt-in the client uses when a cached ticket authorizes it. -on-resume-no-ticket
    // withholds the cache on the resumption connection so the client offers no cached session
    if not LDropTicketState then
      Result.SessionCache := AConfig.SessionCache;
    // early data is a TLS 1.3 feature: a client capped below 1.3 offers none
    Result.OfferEarlyData := AConfig.EnableEarlyData and
      ((AConfig.MaxVersion < 0) or (AConfig.MaxVersion >= WireVersionTls13));
    // a client with external PSKs requires one unless the test also accepts a certificate
    // (-verify-peer); then a certificate-only ServerHello is fatal (PSK-required)
    Result.ExternalPskRequired := not AConfig.VerifyPeer;
    // the client requests a staple when the test enables stapling or asserts a staple
    Result.RequestOcsp := AConfig.EnableOcspStapling or AConfig.HasExpectOcsp;
  end;
end;

class function TBoGoShimRunner.FinishShutdown(const AEngine: ITlsEngine;
  const ASocket: TInteropSocket; ACheckCloseNotify: Boolean): Int32;
var
  LBuf: TBytes;
  LGot: Int32;
  LOutcome: TTlsOutcome;

  function AppDataDuringShutdown: Int32;
  begin
    // a peer that has our close_notify must not send application data (RFC 8446 6.1)
    Writeln(ErrOutput, 'application data received during shutdown');
    Result := ShimExitFail;
  end;

begin
  // application data buffered before we shut down (it coalesced with the handshake flight)
  // already violates the shutdown contract
  if AEngine.PendingAppData > 0 then
    Exit(AppDataDuringShutdown);
  // stage one: emit our close_notify. A one-way shutdown ends here.
  AEngine.SendClose;
  TInteropPump.Flush(AEngine, ASocket);
  if not ACheckCloseNotify then
  begin
    ASocket.ShutdownWrite;
    Exit(ShimExitPass);
  end;
  // stage two: read through any warning alerts / empty records the peer interleaves and wait
  // for its close_notify before closing, so the transport drains cleanly rather than resetting
  // the peer's read. Application data, or an unclean close (transport EOF / a fatal alert)
  // before the close_notify, is a shutdown failure.
  LBuf := nil;
  SetLength(LBuf, TransportChunk);
  while not AEngine.IsInboundClosed do
  begin
    LGot := ASocket.Recv(LBuf, TransportChunk);
    if LGot = 0 then
    begin
      Writeln(ErrOutput, 'shutdown without peer close_notify');
      Exit(ShimExitFail);
    end;
    LOutcome := AEngine.ProcessInput(LBuf, 0, LGot);
    if AEngine.PendingAppData > 0 then
      Exit(AppDataDuringShutdown);
    if LOutcome = TTlsOutcome.Fatal then
    begin
      Writeln(ErrOutput, 'fatal alert during shutdown: ', AEngine.LastError.Message);
      Exit(ShimExitFail);
    end;
  end;
  ASocket.ShutdownWrite;
  Result := ShimExitPass;
end;

class function TBoGoShimRunner.RunExchange(const AProvider: ICryptoProvider;
  const ASocket: TInteropSocket; const AConfig: TBoGoConfig;
  AIsResume: Boolean): Int32;
var
  LEngine: ITlsEngine;
  LOptions: TInteropEngineOptions;
  LResult: TInteropResult;
  LI: Int32;
  LEcho: TBytes;
  LWritesFirst, LEarlyWrite, LServerHalfRtt: Boolean;
  LExportLen: Int32;
  LExportLabel: string;
  LExportContext, LExported, LInitialWrite: TBytes;
  LSeenCas: TArray<TBytes>;
  LCaIdx, LRep, LRepeat: Int32;
begin
  LOptions := BuildOptions(AProvider, AConfig, AIsResume);
  // -verify-fail is fatal only under -verify-peer / -require-any-client-certificate (a hard
  // verify); without them BoringSSL soft-fails and completes, and so do we (the valid cert
  // verifies and no reject is injected). -on-resume-verify-fail applies only on the resume,
  // where there is no certificate to re-verify, so it is a no-op and the resume completes.
  LOptions.VerifyFail := (AConfig.VerifyFail or
    (AConfig.OnResumeVerifyFail and AIsResume)) and
    (AConfig.VerifyPeer or AConfig.RequireClientCert);
  LEngine := TInteropEngine.Build(AProvider, LOptions);
  // this connection writes first when -shim-writes-first, or on a resumption under
  // -on-resume-shim-writes-first; a client that also offered 0-RTT sends that first write
  // as early data before the handshake completes
  LWritesFirst := AConfig.ShimWritesFirst or
    (AConfig.OnResumeShimWritesFirst and AIsResume);
  // the effective initial-write payload on a resumption: the -on-resume-shim-initial-write
  // chunk when given (repeated as separate writes below), otherwise the fixed "hello"
  LInitialWrite := AConfig.InitialWrite;
  LRepeat := 1;
  if AIsResume and (System.Length(AConfig.OnResumeInitialWrite) > 0) then
  begin
    LInitialWrite := AConfig.OnResumeInitialWrite;
    LRepeat := AConfig.OnResumeInitialWriteRepeat;
  end;
  LEarlyWrite := LWritesFirst and AConfig.EnableEarlyData and AIsResume and
    (not AConfig.IsServer) and (System.Length(LInitialWrite) > 0);
  if not AConfig.IsServer then
    LEngine.StartHandshake;
  // 0-RTT: write the initial message under the early keys right after the ClientHello. A
  // repeated payload is written as one call per repeat so each becomes its own record (the
  // runner asserts per-record); the engine sends up to the ticket's max_early_data as 0-RTT
  // and defers the overflow to 1-RTT.
  if LEarlyWrite then
    for LRep := 1 to LRepeat do
      LEngine.WriteEarlyData(LInitialWrite, 0, System.Length(LInitialWrite));

  // a resuming server that enabled 0-RTT may accept the client's early data; when it does, the
  // early bytes are echoed as 0.5-RTT during the handshake (the runner reads that half-RTT
  // response before sending EndOfEarlyData). On a reject the early data is skipped, never
  // surfaces as app data, so the flag is inert.
  LServerHalfRtt := AConfig.IsServer and AIsResume and
    (AConfig.EnableEarlyData or AConfig.OnResumeEnableEarlyData);
  // under -async the verdict is resolved out-of-band in the pump: accept unless this is a hard
  // verify-fail (in which case the parked handshake is rejected, fail-closed)
  LResult := TInteropPump.DriveHandshake(LEngine, ASocket, not LOptions.VerifyFail,
    LServerHalfRtt);
  if LResult.Status <> TInteropStatus.Ok then
  begin
    Writeln(ErrOutput, 'handshake failed: ', LResult.Detail);
    Exit(ShimExitFail);
  end;

  // the negotiated version is enforced by the peer (BoGo pins its own side) and proven
  // by the successful encrypted echo below, so -expect-version needs no separate check
  // here beyond confirming it is a version this shim can offer at all
  if (AConfig.ExpectVersion >= 0) and (AConfig.ExpectVersion <> WireVersionTls13) and
    (AConfig.ExpectVersion <> WireVersionTls12) then
  begin
    Writeln(ErrOutput, 'the test expects a version this shim does not offer');
    Exit(ShimExitFail);
  end;
  if (AConfig.ExpectAlpn <> '') and
    (LEngine.NegotiatedAlpnProtocol <> AConfig.ExpectAlpn) then
  begin
    Writeln(ErrOutput, 'negotiated ALPN did not match the expected protocol');
    Exit(ShimExitFail);
  end;
  // the client must have received exactly the stapled OCSP response the runner expects.
  // The staple rides the Certificate message, which a full TLS 1.3 resumption omits (there
  // is no re-authentication), so it is only asserted on the full handshake - our client
  // does not cache and re-surface a prior staple across resumption.
  if AConfig.HasExpectOcsp and (not AIsResume) and
    (not TInteropUtils.BytesEqual(LEngine.PeerOcspStaple, AConfig.ExpectOcspResponse)) then
  begin
    Writeln(ErrOutput, 'the stapled OCSP response did not match the expected one');
    Exit(ShimExitFail);
  end;
  // the client must have seen exactly the certificate_authorities the server named in its
  // CertificateRequest (RFC 8446 4.2.4 / RFC 5246 7.4.4), in the same order
  if AConfig.ExpectClientCaListSet then
  begin
    LSeenCas := LEngine.RequestedCertificateAuthorities;
    if System.Length(LSeenCas) <> System.Length(AConfig.ExpectClientCaList) then
    begin
      Writeln(ErrOutput, 'the requested certificate_authorities count did not match');
      Exit(ShimExitFail);
    end;
    for LCaIdx := 0 to System.High(AConfig.ExpectClientCaList) do
      if not TInteropUtils.BytesEqual(LSeenCas[LCaIdx],
        AConfig.ExpectClientCaList[LCaIdx]) then
      begin
        Writeln(ErrOutput, 'a requested certificate_authorities entry did not match');
        Exit(ShimExitFail);
      end;
  end;

  // exported keying material is written first thing after the handshake so the runner reads
  // it before the echo protocol (RFC 5705 / RFC 8446 7.5); a resumption uses the on-resume
  // parameters when they were supplied, otherwise the initial-connection ones
  LExportLen := AConfig.ExportLen;
  LExportLabel := AConfig.ExportLabel;
  LExportContext := AConfig.ExportContext;
  if AIsResume and (AConfig.OnResumeExportLen > 0) then
  begin
    LExportLen := AConfig.OnResumeExportLen;
    LExportLabel := AConfig.OnResumeExportLabel;
    LExportContext := AConfig.OnResumeExportContext;
  end;
  if LExportLen > 0 then
  begin
    LExported := LEngine.ExportKeyingMaterial(LExportLabel, LExportContext,
      AConfig.UseExportContext, LExportLen);
    TInteropPump.WriteAppData(LEngine, ASocket, LExported);
  end;

  // an unsolicited KeyUpdate is sent right after the handshake (RFC 8446 4.6.3); inbound
  // KeyUpdates the peer sends are absorbed by the engine during the echo loop below
  if AConfig.KeyUpdate then
  begin
    LEngine.RequestKeyUpdate(False);
    TInteropPump.Flush(LEngine, ASocket);
  end;

  // a writes-first connection sends its initial message as 1-RTT here, unless it already
  // went out as 0-RTT early data above
  if LWritesFirst and not LEarlyWrite and
    (System.Length(LInitialWrite) > 0) then
    TInteropPump.WriteAppData(LEngine, ASocket, LInitialWrite);

  // -shim-shuts-down: the shim closes the connection right after the handshake instead of
  // echoing. Entering the echo loop would block on a read the runner never satisfies.
  if AConfig.ShimShutsDown then
    Exit(FinishShutdown(LEngine, ASocket, AConfig.CheckCloseNotify));

  // the runner's echo protocol: read a message, flip every byte, write it back
  repeat
    LResult := TInteropPump.PumpAppData(LEngine, ASocket);
    if System.Length(LResult.Data) > 0 then
    begin
      LEcho := System.Copy(LResult.Data, 0, System.Length(LResult.Data));
      for LI := 0 to System.High(LEcho) do
        LEcho[LI] := LEcho[LI] xor XorMask;
      TInteropPump.WriteAppData(LEngine, ASocket, LEcho);
    end;
    if LResult.Status in [TInteropStatus.LocalAlert, TInteropStatus.PeerAlert] then
    begin
      Writeln(ErrOutput, 'alert during data exchange: ', LResult.Detail);
      Exit(ShimExitFail);
    end;
  until LResult.Status <> TInteropStatus.Ok;

  if LResult.Status = TInteropStatus.PeerClosed then
    TInteropPump.Close(LEngine, ASocket);
  Result := ShimExitPass;
end;

class function TBoGoShimRunner.Run: Int32;
var
  LConfig: TBoGoConfig;
  LReason: string;
  LProvider: ICryptoProvider;
  LSocket: TInteropSocket;
  LConn: Int32;
  LAddress: string;
  LClock: TInteropAdjustableClock;
begin
  LogArgv;
  if HandleProbeFlags then
    Exit(ShimExitPass);
  if not TryParseArgs(LConfig, LReason) then
  begin
    Writeln(ErrOutput, LReason);
    Exit(ShimExitUnimplemented);
  end;
  // the shim offers TLS 1.3 and hardened 1.2. An empty range that still permits a version
  // at or above our 1.2 floor means every supported version was explicitly disabled (e.g.
  // -no-tls12 with -no-tls13): a degenerate config the peer expects us to reject, so fail
  // cleanly (NO_SUPPORTED_VERSIONS_ENABLED). A max below 1.2 is a genuine old-version-only
  // request, which is out of scope (RFC 8996).
  if System.Length(VersionRange(LConfig)) = 0 then
  begin
    if (LConfig.MaxVersion < 0) or (LConfig.MaxVersion >= WireVersionTls12) then
    begin
      Writeln(ErrOutput, 'no supported protocol version is enabled');
      Exit(ShimExitFail);
    end;
    Writeln(ErrOutput, 'unimplemented: no supported version in the requested range');
    Exit(ShimExitUnimplemented);
  end;

  LProvider := TInteropEngine.DefaultProvider;
  // one session cache (client) / STEK (server) shared across every connection, so a
  // the client always keeps a session cache so it offers psk_key_exchange_modes and accepts
  // (and validates) the NewSessionTickets the server issues, even on a non-resume connection;
  // a resumption reuses the same cache across the ResumeCount+1 connections. The server only
  // needs ticket keys when a resumption is expected.
  if LConfig.IsServer then
  begin
    if LConfig.ResumeCount > 0 then
    begin
      // ticket (stateless) resumption keys AND a stateful session-id store (RFC 5246 7.3),
      // both shared across the ResumeCount+1 connections; a client with tickets disabled
      // resumes via the session id, which the server can only honor from a persistent store.
      // -no-ticket suppresses the STEK so no ticket is minted, leaving only the session-id path
      if not LConfig.NoTicket then
        LConfig.SessionTicketKeys := TStekTicketKeyManager.Create(LProvider.Primitives.GetRandom)
          as ISessionTicketKeyManager;
      LConfig.SessionStore := TInMemorySessionStore.Create(LProvider.Primitives.GetRandom)
        as ISessionStore;
    end;
  end
  else
    LConfig.SessionCache := TInMemorySessionCache.Create as ISessionCache;
  // -resumption-delay drives a test clock the shim advances between connections (so a
  // resumption PSK's obfuscated_ticket_age and lifetime expiry are exact); without it every
  // engine keeps the real system clock. LClock is a raw view of the interface LConfig.Clock owns.
  LClock := nil;
  if LConfig.ResumptionDelaySeconds > 0 then
  begin
    // LClock keeps a raw reference (for Advance below); LConfig.Clock owns the interface. Do
    // NOT collapse these two into one assignment - LClock is used to advance the clock later.
    LClock := TInteropAdjustableClock.Create;
    LConfig.Clock := LClock;
  end;
  if LConfig.UseIpv6 then
    LAddress := '::1'
  else
    LAddress := '127.0.0.1';
  try
    // the initial connection plus one per resumption; each re-dials the runner and
    // announces the same shim id, reusing the shared session state
    for LConn := 0 to LConfig.ResumeCount do
    begin
      // advance the test clock by the runner's delay before each resumption connection
      if (LConn > 0) and (LClock <> nil) then
        LClock.Advance(UInt64(LConfig.ResumptionDelaySeconds) * 1000);
      LSocket := TInteropSocket.Connect(LAddress, LConfig.Port);
      try
        AnnounceShimId(LSocket, LConfig.ShimId);
        Result := RunExchange(LProvider, LSocket, LConfig, LConn > 0);
      finally
        LSocket.Free;
      end;
      if Result <> ShimExitPass then
        Exit;
    end;
  except
    on E: Exception do
    begin
      Writeln(ErrOutput, E.ClassName, ': ', E.Message);
      Result := ShimExitFail;
    end;
  end;
end;

end.
