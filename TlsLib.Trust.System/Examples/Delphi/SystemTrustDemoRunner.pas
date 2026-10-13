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
/// offline checks of the OS trust delegate over whatever platform engine the build targets (the
/// Android X509TrustManager on a device). Each check is self-contained and needs no network: a
/// three-tier chain is supplied as bytes, the intermediate reaches the OS engine only through the
/// context, and the verdicts are read straight from the delegate verifiers. The empty-chain check
/// is the delegate's own guard and never reaches the engine.
/// The host-roots cells GET live sites with the host's own root passed beside the OS roots and
/// compare each outcome with what that root should and should not change.
/// </summary>
unit SystemTrustDemoRunner;

interface

uses
  System.SysUtils,
  TlpTlsAlert,
  TlpTrustPolicy,
  TlpITlsConfig,
  TlpOSSystemTrust;

type
  THostRoot = (hrNone, hrUnrelated, hrBadSsl, hrIsrgX1, hrSelfSigned);

  THostRootCell = record
    Title: string;
    Url: string;
    HostRoot: THostRoot;
    ExpectConnect: Boolean;
    NeedsNsc: Boolean;
  end;

  TGetOutcome = (goConnected, goRefused, goUnreachable, goFailed);

  TSystemTrustDemoRunner = class sealed(TObject)
  strict private
    /// <summary>One live GET. A nil AConfig trusts the OS store alone (UseSystemTrust); otherwise
    /// AConfig decides. ADetail is the tail of the result line. The network must not run on the UI
    /// thread (mobile platforms forbid it).</summary>
    class function HttpsGet(const AUrl: string; const AConfig: ITlsClientConfig;
      out ADetail: string): TGetOutcome; static;
    /// <summary>One live GET over the OS system trust store. Returns a human line.</summary>
    class function RunSystemTrustGet(const AUrl: string): string; static;
    class function RootBlob(ARoot: THostRoot): TBytes; static;
    class function HostRootConfig(AMode: TSystemTrustMode; ARoot: THostRoot)
      : ITlsClientConfig; static;
    class function HostRootModes: TArray<TSystemTrustMode>; static;
    class function ModeName(AMode: TSystemTrustMode): string; static;
    /// <summary>One cell in one mode: the GET with the cell's host root, then PASS or FAIL against
    /// what the cell expects. SKIP when the network is unreachable.</summary>
    class function RunHostRootCell(AMode: TSystemTrustMode;
      const ACell: THostRootCell): string; static;
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
    /// <summary>The host-roots cells in every mode this platform has: a heading per mode, then one
    /// "PASS: ...", "FAIL: ..." or "SKIP: ..." line per cell. AUrl is the public site for the first
    /// cell. Blocks on the network, so call it off the UI thread.</summary>
    class function RunHostRoots(const AUrl: string): TArray<string>; static;
  end;

implementation

uses
  System.StrUtils,
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
  TlpITrustAnchorStore,
  TlpICryptoProvider,
  TlpDefaultCryptoProvider,
  TlpTlsPresets,
  TlpSystemTrustBase,
  TlpSystemTrustFacade,
  TlpSystemTrustExceptions;

const
  TimeoutMs = 15000;
  PublicSiteUrl = 'https://postman-echo.com/get';
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
  // the root untrusted-root.badssl.com presents (sha256 43194b56f17cd0b72be548b35ae93adb1664e4023d1d7d0957f5bab66a31fe3d);
  // no OS store trusts it, so it is the host's own root for that site
  BadSslRootPem =
    '-----BEGIN CERTIFICATE-----'#10 +
    'MIIGfjCCBGagAwIBAgIJAJeg/PrX5Sj9MA0GCSqGSIb3DQEBCwUAMIGBMQswCQYD'#10 +
    'VQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNU2FuIEZyYW5j'#10 +
    'aXNjbzEPMA0GA1UECgwGQmFkU1NMMTQwMgYDVQQDDCtCYWRTU0wgVW50cnVzdGVk'#10 +
    'IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5MB4XDTE2MDcwNzA2MzEzNVoXDTM2'#10 +
    'MDcwMjA2MzEzNVowgYExCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlh'#10 +
    'MRYwFAYDVQQHDA1TYW4gRnJhbmNpc2NvMQ8wDQYDVQQKDAZCYWRTU0wxNDAyBgNV'#10 +
    'BAMMK0JhZFNTTCBVbnRydXN0ZWQgUm9vdCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkw'#10 +
    'ggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDKQtPMhEH073gis/HISWAi'#10 +
    'bOEpCtOsatA3JmeVbaWal8O/5ZO5GAn9dFVsGn0CXAHR6eUKYDAFJLa/3AhjBvWa'#10 +
    'tnQLoXaYlCvBjodjLEaFi8ckcJHrAYG9qZqioRQ16Yr8wUTkbgZf+er/Z55zi1yn'#10 +
    'CnhWth7kekvrwVDGP1rApeLqbhYCSLeZf5W/zsjLlvJni9OrU7U3a9msvz8mcCOX'#10 +
    'fJX9e3VbkD/uonIbK2SvmAGMaOj/1k0dASkZtMws0Bk7m1pTQL+qXDM/h3BQZJa5'#10 +
    'DwTcATaa/Qnk6YHbj/MaS5nzCSmR0Xmvs/3CulQYiZJ3kypns1KdqlGuwkfiCCgD'#10 +
    'yWJy7NE9qdj6xxLdqzne2DCyuPrjFPS0mmYimpykgbPnirEPBF1LW3GJc9yfhVXE'#10 +
    'Cc8OY8lWzxazDNNbeSRDpAGbBeGSQXGjAbliFJxwLyGzZ+cG+G8lc+zSvWjQu4Xp'#10 +
    'GJ+dOREhQhl+9U8oyPX34gfKo63muSgo539hGylqgQyzj+SX8OgK1FXXb2LS1gxt'#10 +
    'VIR5Qc4MmiEG2LKwPwfU8Yi+t5TYjGh8gaFv6NnksoX4hU42gP5KvjYggDpR+NSN'#10 +
    'CGQSWHfZASAYDpxjrOo+rk4xnO+sbuuMk7gORsrl+jgRT8F2VqoR9Z3CEdQxcCjR'#10 +
    '5FsfTymZCk3GfIbWKkaeLQIDAQABo4H2MIHzMB0GA1UdDgQWBBRvx4NzSbWnY/91'#10 +
    '3m1u/u37l6MsADCBtgYDVR0jBIGuMIGrgBRvx4NzSbWnY/913m1u/u37l6MsAKGB'#10 +
    'h6SBhDCBgTELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNV'#10 +
    'BAcMDVNhbiBGcmFuY2lzY28xDzANBgNVBAoMBkJhZFNTTDE0MDIGA1UEAwwrQmFk'#10 +
    'U1NMIFVudHJ1c3RlZCBSb290IENlcnRpZmljYXRlIEF1dGhvcml0eYIJAJeg/PrX'#10 +
    '5Sj9MAwGA1UdEwQFMAMBAf8wCwYDVR0PBAQDAgEGMA0GCSqGSIb3DQEBCwUAA4IC'#10 +
    'AQBQU9U8+jTRT6H9AIFm6y50tXTg/ySxRNmeP1Ey9Zf4jUE6yr3Q8xBv9gTFLiY1'#10 +
    'qW2qfkDSmXVdBkl/OU3+xb5QOG5hW7wVolWQyKREV5EvUZXZxoH7LVEMdkCsRJDK'#10 +
    'wYEKnEErFls5WPXY3bOglBOQqAIiuLQ0f77a2HXULDdQTn5SueW/vrA4RJEKuWxU'#10 +
    'iD9XPnVZ9tPtky2Du7wcL9qhgTddpS/NgAuLO4PXh2TQ0EMCll5reZ5AEr0NSLDF'#10 +
    'c/koDv/EZqB7VYhcPzr1bhQgbv1dl9NZU0dWKIMkRE/T7vZ97I3aPZqIapC2ulrf'#10 +
    'KrlqjXidwrGFg8xbiGYQHPx3tHPZxoM5WG2voI6G3s1/iD+B4V6lUEvivd3f6tq7'#10 +
    'd1V/3q1sL5DNv7TvaKGsq8g5un0TAkqaewJQ5fXLigF/yYu5a24/GUD783MdAPFv'#10 +
    'gWz8F81evOyRfpf9CAqIswMF+T6Dwv3aw5L9hSniMrblkg+ai0K22JfoBcGOzMtB'#10 +
    'Ke/Ps2Za56dTRoY/a4r62hrcGxufXd0mTdPaJLw3sJeHYjLxVAYWQq4QKJQWDgTS'#10 +
    'dAEWyN2WXaBFPx5c8KIW95Eu8ShWE00VVC3oA4emoZ2nrzBXLrUScifY6VaYYkkR'#10 +
    '2O2tSqU8Ri3XRdgpNPDWp8ZL49KhYGYo3R/k98gnMHiY5g=='#10 +
    '-----END CERTIFICATE-----'#10;
  // the self-signed *.badssl.com leaf self-signed.badssl.com presents (sha256 3963935f5553a2e0db9d53fa9a2d09747216a8e2f68e2079d632205f7b014ee8), valid to 2028-10-05
  SelfSignedLeafPem =
    '-----BEGIN CERTIFICATE-----'#10 +
    'MIIDeTCCAmGgAwIBAgIJAKtFizM4Gg5IMA0GCSqGSIb3DQEBCwUAMGIxCzAJBgNV'#10 +
    'BAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRYwFAYDVQQHDA1TYW4gRnJhbmNp'#10 +
    'c2NvMQ8wDQYDVQQKDAZCYWRTU0wxFTATBgNVBAMMDCouYmFkc3NsLmNvbTAeFw0y'#10 +
    'NjEwMDYyMTAwMTdaFw0yODEwMDUyMTAwMTdaMGIxCzAJBgNVBAYTAlVTMRMwEQYD'#10 +
    'VQQIDApDYWxpZm9ybmlhMRYwFAYDVQQHDA1TYW4gRnJhbmNpc2NvMQ8wDQYDVQQK'#10 +
    'DAZCYWRTU0wxFTATBgNVBAMMDCouYmFkc3NsLmNvbTCCASIwDQYJKoZIhvcNAQEB'#10 +
    'BQADggEPADCCAQoCggEBAMIE7PiM7gTCs9hQ1XBYzJMY61yoaEmwIrX5lZ6xKyx2'#10 +
    'PmzAS2BMTOqytMAPgLaw+XLJhgL5XEFdEyt/ccRLvOmULlA3pmccYYz2QULFRtMW'#10 +
    'hyefdOsKnRFSJiFzbIRMeVXk0WvoBj1IFVKtsyjbqv9u/2CVSndrOfEk0TG23U3A'#10 +
    'xPxTuW1CrbV8/q71FdIzSOciccfCFHpsKOo3St/qbLVytH5aohbcabFXRNsKEqve'#10 +
    'ww9HdFxBIuGa+RuT5q0iBikusbpJHAwnnqP7i/dAcgCskgjZjFeEU4EFy+b+a1SY'#10 +
    'QCeFxxC7c3DvaRhBB0VVfPlkPz0sw6l865MaTIbRyoUCAwEAAaMyMDAwCQYDVR0T'#10 +
    'BAIwADAjBgNVHREEHDAaggwqLmJhZHNzbC5jb22CCmJhZHNzbC5jb20wDQYJKoZI'#10 +
    'hvcNAQELBQADggEBAGnCNdgCm8TJSktAdUeWVdB5JmyXnVrG581jHUk+G8iO5qOF'#10 +
    'SETzzlRuqVyT+FUfiy4oN4un8w7TsOnf1OHrNtjzY/UUKI/Jdn0j+BP+g2Q9FQiM'#10 +
    'zijjy1whoIP86664djYkUKZIfw+Oj8M8UQRaYFMZ0tQbGilb3KDATIOVTClDG4Mm'#10 +
    'Li0FnGcje+K7e6xE2BEeFHOHkOj8HOD5FBD5xzqSqV3eTEYFOPRJOnXXJ4j2+0u0'#10 +
    'A28LpGp/srbX7Z3tw7YsSKTyAydiPU6n2yXFpUc7VaVcEW/w6fnw2UIJySyLDti9'#10 +
    '3WHYOMamHLVzWvhPCQsri+/FK+C+gZLBtjiP5Tw='#10 +
    '-----END CERTIFICATE-----'#10;
  // ISRG Root X1 (sha256 96bcec06264976f37460779acf28c5a7cfe8a3c0aae11a8ffcee05c0bddf08c6), the OS root letsencrypt.org chains to
  IsrgX1RootPem =
    '-----BEGIN CERTIFICATE-----'#10 +
    'MIIFazCCA1OgAwIBAgIRAIIQz7DSQONZRGPgu2OCiwAwDQYJKoZIhvcNAQELBQAw'#10 +
    'TzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2Vh'#10 +
    'cmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMTUwNjA0MTEwNDM4'#10 +
    'WhcNMzUwNjA0MTEwNDM4WjBPMQswCQYDVQQGEwJVUzEpMCcGA1UEChMgSW50ZXJu'#10 +
    'ZXQgU2VjdXJpdHkgUmVzZWFyY2ggR3JvdXAxFTATBgNVBAMTDElTUkcgUm9vdCBY'#10 +
    'MTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAK3oJHP0FDfzm54rVygc'#10 +
    'h77ct984kIxuPOZXoHj3dcKi/vVqbvYATyjb3miGbESTtrFj/RQSa78f0uoxmyF+'#10 +
    '0TM8ukj13Xnfs7j/EvEhmkvBioZxaUpmZmyPfjxwv60pIgbz5MDmgK7iS4+3mX6U'#10 +
    'A5/TR5d8mUgjU+g4rk8Kb4Mu0UlXjIB0ttov0DiNewNwIRt18jA8+o+u3dpjq+sW'#10 +
    'T8KOEUt+zwvo/7V3LvSye0rgTBIlDHCNAymg4VMk7BPZ7hm/ELNKjD+Jo2FR3qyH'#10 +
    'B5T0Y3HsLuJvW5iB4YlcNHlsdu87kGJ55tukmi8mxdAQ4Q7e2RCOFvu396j3x+UC'#10 +
    'B5iPNgiV5+I3lg02dZ77DnKxHZu8A/lJBdiB3QW0KtZB6awBdpUKD9jf1b0SHzUv'#10 +
    'KBds0pjBqAlkd25HN7rOrFleaJ1/ctaJxQZBKT5ZPt0m9STJEadao0xAH0ahmbWn'#10 +
    'OlFuhjuefXKnEgV4We0+UXgVCwOPjdAvBbI+e0ocS3MFEvzG6uBQE3xDk3SzynTn'#10 +
    'jh8BCNAw1FtxNrQHusEwMFxIt4I7mKZ9YIqioymCzLq9gwQbooMDQaHWBfEbwrbw'#10 +
    'qHyGO0aoSCqI3Haadr8faqU9GY/rOPNk3sgrDQoo//fb4hVC1CLQJ13hef4Y53CI'#10 +
    'rU7m2Ys6xt0nUW7/vGT1M0NPAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNV'#10 +
    'HRMBAf8EBTADAQH/MB0GA1UdDgQWBBR5tFnme7bl5AFzgAiIyBpY9umbbjANBgkq'#10 +
    'hkiG9w0BAQsFAAOCAgEAVR9YqbyyqFDQDLHYGmkgJykIrGF1XIpu+ILlaS/V9lZL'#10 +
    'ubhzEFnTIZd+50xx+7LSYK05qAvqFyFWhfFQDlnrzuBZ6brJFe+GnY+EgPbk6ZGQ'#10 +
    '3BebYhtF8GaV0nxvwuo77x/Py9auJ/GpsMiu/X1+mvoiBOv/2X/qkSsisRcOj/KK'#10 +
    'NFtY2PwByVS5uCbMiogziUwthDyC3+6WVwW6LLv3xLfHTjuCvjHIInNzktHCgKQ5'#10 +
    'ORAzI4JMPJ+GslWYHb4phowim57iaztXOoJwTdwJx4nLCgdNbOhdjsnvzqvHu7Ur'#10 +
    'TkXWStAmzOVyyghqpZXjFaH3pO3JLF+l+/+sKAIuvtd7u+Nxe5AW0wdeRlN8NwdC'#10 +
    'jNPElpzVmbUq4JUagEiuTDkHzsxHpFKVK7q4+63SM1N95R1NbdWhscdCb+ZAJzVc'#10 +
    'oyi3B43njTOQ5yOf+1CceWxG1bQVs5ZufpsMljq4Ui0/1lvh+wjChP4kqKOJ2qxq'#10 +
    '4RgqsahDYVvTH9w7jXbyLeiNdd8XM2w9U/t7y0Ff/9yi0GE44Za4rF2LN9d11TPA'#10 +
    'mRGunUHBcnWEvgJBQl9nJEiU0Zsnvgc/ubhPgXRR4Xq37Z0j4r7g1SgEEzwxA57d'#10 +
    'emyPxgcYxn/eR44/KJ4EBs+lVDR3veyJm+kXQ99b21/+jh5Xos1AnX5iItreGCc='#10 +
    '-----END CERTIFICATE-----'#10;

  HostRootCells: array[0..7] of THostRootCell = (
    (Title: 'public site, unrelated host root'; Url: PublicSiteUrl;
      HostRoot: hrUnrelated; ExpectConnect: True; NeedsNsc: False),
    (Title: 'untrusted-root.badssl.com, its root as host root';
      Url: 'https://untrusted-root.badssl.com/'; HostRoot: hrBadSsl; ExpectConnect: True;
      NeedsNsc: False),
    (Title: 'untrusted-root.badssl.com, no host root';
      Url: 'https://untrusted-root.badssl.com/'; HostRoot: hrNone; ExpectConnect: False;
      NeedsNsc: False),
    (Title: 'expired.badssl.com, host root present (expiry is final)';
      Url: 'https://expired.badssl.com/'; HostRoot: hrBadSsl; ExpectConnect: False;
      NeedsNsc: False),
    (Title: 'wrong.host.badssl.com, host root present (name is final)';
      Url: 'https://wrong.host.badssl.com/'; HostRoot: hrBadSsl; ExpectConnect: False;
      NeedsNsc: False),
    (Title: 'self-signed.badssl.com, unrelated host root';
      Url: 'https://self-signed.badssl.com/'; HostRoot: hrUnrelated; ExpectConnect: False;
      NeedsNsc: False),
    (Title: 'letsencrypt.org, wrong network-security-config pin, its own OS root as host root (a pin failure is final)';
      Url: 'https://letsencrypt.org/'; HostRoot: hrIsrgX1; ExpectConnect: False; NeedsNsc: True),
    (Title: 'self-signed.badssl.com, domain-config host, its own certificate as host root (host roots do not apply)';
      Url: 'https://self-signed.badssl.com/'; HostRoot: hrSelfSigned; ExpectConnect: False;
      NeedsNsc: True));

{ TSystemTrustDemoRunner }

class function TSystemTrustDemoRunner.HttpsGet(const AUrl: string;
  const AConfig: ITlsClientConfig; out ADetail: string): TGetOutcome;
var
  LHttp: TIdHTTP;
  LIO: TTlsLibIOHandlerSocket;
  LBody: string;
begin
  LHttp := TIdHTTP.Create(nil);
  try
    LIO := TTlsLibIOHandlerSocket.Create(LHttp);
    // No config: trust the OS store only - no RootCertFile, no CustomTrustStore
    if AConfig = nil then
      LIO.SSLOptions.UseSystemTrust := True
    else
      LIO.SSLOptions.ClientConfig := AConfig;
    LHttp.IOHandler := LIO;
    LHttp.HandleRedirects := True;
    LHttp.ConnectTimeout := TimeoutMs;
    LHttp.ReadTimeout := TimeoutMs;
    LHttp.Request.UserAgent := 'TlsLib4Pascal-SystemTrust';
    try
      LBody := LHttp.Get(AUrl);
      ADetail := Format('%d bytes, status %d', [Length(LBody), LHttp.ResponseCode]);
      Result := goConnected;
    except
      on E: EIdSocketError do
      begin
        ADetail := E.Message;
        Result := goUnreachable;
      end;
      on E: ETlsStreamError do
      begin
        if E.HasAlert then
          ADetail := Format('TLS alert %d - %s', [Ord(E.Alert), E.Message])
        else
          ADetail := E.Message;
        Result := goRefused;
      end;
      on E: Exception do
      begin
        ADetail := Format('%s: %s', [E.ClassName, E.Message]);
        Result := goFailed;
      end;
    end;
  finally
    LHttp.Free;
  end;
end;

class function TSystemTrustDemoRunner.RunSystemTrustGet(const AUrl: string): string;
var
  LDetail: string;
begin
  case HttpsGet(AUrl, nil, LDetail) of
    goConnected:
      Result := 'PASS: ' + LDetail + ' over OS-verified TLS';
    goUnreachable:
      Result := 'SKIP: network unreachable (' + LDetail + ')';
  else
    Result := 'FAIL: ' + LDetail;
  end;
end;

class function TSystemTrustDemoRunner.RootBlob(ARoot: THostRoot): TBytes;
begin
  case ARoot of
    hrUnrelated:
      Result := TDataEncoding.HexDecode(RootHex);
    hrBadSsl:
      Result := TEncoding.ASCII.GetBytes(BadSslRootPem);
    hrIsrgX1:
      Result := TEncoding.ASCII.GetBytes(IsrgX1RootPem);
    hrSelfSigned:
      Result := TEncoding.ASCII.GetBytes(SelfSignedLeafPem);
  else
    Result := nil;
  end;
end;

class function TSystemTrustDemoRunner.HostRootConfig(AMode: TSystemTrustMode;
  ARoot: THostRoot): ITlsClientConfig;
var
  LCrypto: ICryptoProvider;
  LPkix: IPkixProvider;
  LHostRoots: ITrustAnchorStore;
begin
  LCrypto := TDefaultCryptoProvider.Create as ICryptoProvider;
  LPkix := TDefaultPkixProvider.Create as IPkixProvider;
  LHostRoots := nil;
  if ARoot <> hrNone then
    LHostRoots := TTrustAnchorStore.Create(LPkix.Certificates.LoadChain(RootBlob(ARoot)))
      as ITrustAnchorStore;
  Result := TTlsPresets.Compatible(LCrypto, LPkix).Client
    .WithServerVerification(TSystemTrust.ServerVerification(LPkix, AMode, LHostRoots).Build)
    .Build;
end;

class function TSystemTrustDemoRunner.HostRootModes: TArray<TSystemTrustMode>;
begin
  // Anchors is a second engine only where Default is the OS one; elsewhere they are the same
  if TOSSystemTrust.Supports(TSystemTrustMode.Anchors) and
    TOSSystemTrust.Supports(TSystemTrustMode.Delegate) then
    Result := TArray<TSystemTrustMode>.Create(TSystemTrustMode.Default, TSystemTrustMode.Anchors)
  else
    Result := TArray<TSystemTrustMode>.Create(TSystemTrustMode.Default);
end;

class function TSystemTrustDemoRunner.ModeName(AMode: TSystemTrustMode): string;
begin
  if AMode = TSystemTrustMode.Anchors then
    Exit('Anchors (own validator over the harvested OS roots)');
  if TOSSystemTrust.Supports(TSystemTrustMode.Delegate) then
    Result := 'Default = Delegate (OS engine)'
  else
    Result := 'Default = Anchors (own validator over the harvested OS roots)';
end;

class function TSystemTrustDemoRunner.RunHostRootCell(AMode: TSystemTrustMode;
  const ACell: THostRootCell): string;
var
  LOutcome: TGetOutcome;
  LDetail, LExpected, LGot: string;
  LMet: Boolean;
begin
{$IFNDEF ANDROID}
  if ACell.NeedsNsc then
    Exit(Format('SKIP: %s: needs the Android network-security-config', [ACell.Title]));
{$ENDIF}
  try
    LOutcome := HttpsGet(ACell.Url, HostRootConfig(AMode, ACell.HostRoot), LDetail);
  except
    on E: Exception do
      Exit(Format('FAIL: %s: %s: %s', [ACell.Title, E.ClassName, E.Message]));
  end;
  if LOutcome = goUnreachable then
    Exit(Format('SKIP: %s: network unreachable (%s)', [ACell.Title, LDetail]));
  LMet := (ACell.ExpectConnect and (LOutcome = goConnected)) or
    (not ACell.ExpectConnect and (LOutcome = goRefused));
  if ACell.ExpectConnect then
    LExpected := 'connect'
  else
    LExpected := 'refuse';
  case LOutcome of
    goConnected: LGot := 'connected';
    goRefused: LGot := 'refused';
  else
    LGot := 'errored';
  end;
  Result := Format('%s: %s: expected %s, %s (%s)',
    [IfThen(LMet, 'PASS', 'FAIL'), ACell.Title, LExpected, LGot, LDetail]);
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
  LAlert, LRefusal: TTlsAlertDescription;
begin
  LLeaf := TDataEncoding.HexDecode(LeafHex);
  LIssuer := TDataEncoding.HexDecode(IssuerHex);
  // the refusal comes first so a verdict the engine remembered from the accepted chain cannot
  // be what lets the second call pass or fail
  if VerifyClient(nil, TArray<TBytes>.Create(LLeaf), LAlert) then
    Exit('FAIL: intermediates: the same leaf verified with no intermediate supplied');
  LRefusal := LAlert;
{$IFDEF ANDROID}
  // the platform reports a path that ends in no configured anchor as unknown_ca
  if LRefusal <> TTlsAlertDescription.UnknownCa then
    Exit(Format('FAIL: intermediates: the leaf was refused with alert %d, expected unknown_ca',
      [Ord(LRefusal)]));
{$ENDIF}
  if not VerifyClient(TArray<TBytes>.Create(LIssuer), TArray<TBytes>.Create(LLeaf), LAlert) then
    Exit(Format('FAIL: intermediates: a leaf-only chain was refused though its issuer was ' +
      'supplied (alert %d)', [Ord(LAlert)]));
  Result := Format('PASS: intermediates: leaf-only chain verified through a supplied ' +
    'intermediate and was refused without it (alert %d)', [Ord(LRefusal)]);
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
{$IFDEF ANDROID}
  Result := 'FAIL: live fetch: accepted, but the Android engine has no network-revocation setting';
{$ELSE}
  Result := 'INFO: live fetch: accepted, so this engine fetches live revocation';
{$ENDIF}
end;

class function TSystemTrustDemoRunner.Run(const AUrl: string): TArray<string>;
var
  LGet: string;
  LChecks: TArray<string>;
  LI: Integer;
begin
  LGet := RunSystemTrustGet(AUrl);
  LChecks := RunChecks;
  SetLength(Result, System.Length(LChecks) + 2);
  Result[0] := LGet;
  Result[1] := 'OS-delegate checks:';
  for LI := 0 to System.High(LChecks) do
    Result[LI + 2] := '  ' + LChecks[LI];
end;

class function TSystemTrustDemoRunner.RunHostRoots(const AUrl: string): TArray<string>;
var
  LModes: TArray<TSystemTrustMode>;
  LCell: THostRootCell;
  LSteps: TArray<string>;
  LMode, LCellIndex, LLine, LStep: Integer;
begin
  LModes := HostRootModes;
  LSteps := nil;
{$IFDEF ANDROID}
  LSteps := TArray<string>.Create(
    'MANUAL: a user-installed CA must not become trusted (apps targeting API 24+ ignore user CAs):',
    '  1. Take badssl-untrusted-root.crt from the demo folder in the repo (sha256 43194b56...fe3d).',
    '  2. Copy it to the phone.',
    '  3. Settings > Security > Encryption & credentials > Install a certificate > CA certificate.',
    '  4. Run these cells again: "untrusted-root.badssl.com, no host root" must still PASS (refused).');
{$ENDIF}
  SetLength(Result, System.Length(LModes) * (System.Length(HostRootCells) + 1) +
    System.Length(LSteps));
  LLine := 0;
  for LMode := 0 to System.High(LModes) do
  begin
    Result[LLine] := 'Host roots, mode ' + ModeName(LModes[LMode]) + ':';
    Inc(LLine);
    for LCellIndex := 0 to System.High(HostRootCells) do
    begin
      LCell := HostRootCells[LCellIndex];
      if LCellIndex = 0 then
        LCell.Url := AUrl;
      Result[LLine] := '  ' + RunHostRootCell(LModes[LMode], LCell);
      Inc(LLine);
    end;
  end;
  for LStep := 0 to System.High(LSteps) do
  begin
    Result[LLine] := LSteps[LStep];
    Inc(LLine);
  end;
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
