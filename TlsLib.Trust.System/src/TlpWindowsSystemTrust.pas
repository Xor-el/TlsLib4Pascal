{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpWindowsSystemTrust;

{$I ..\..\TlsLib\src\Include\TlsLib.inc}

interface

{$IFDEF TLSLIB_MSWINDOWS}

uses
  Windows,
  Generics.Collections,
  SysUtils,
  TlpTlsAlert,
  TlpTrustPolicy,
  TlpSystemTrustBase,
  TlpIPlatformChainEngine;

type
  /// <summary>
  /// Harvests the Windows machine/user trust anchors from the "ROOT" system store,
  /// keeping only roots whose effective trust purpose permits TLS server authentication
  /// and subtracting any certificate present in the "Disallowed" store so OS distrust is
  /// honored. The intermediate-cache "CA" store is deliberately not harvested (its entries
  /// are cached intermediates, not anchors). Emits neutral DER.
  /// </summary>
  TWindowsRootSource = class sealed(TSystemRootSource)
  strict protected
    function HarvestRoots: TArray<TBytes>; override;
    function SourceName: string; override;
  end;

  /// <summary>
  /// The Windows platform chain engine behind the OS trust delegate: builds and trusts a
  /// certificate path with crypt32 (the OS ROOT store for a server certificate, an exclusive
  /// engine over the configured client-CA anchors for a client certificate), consuming the
  /// handshake OCSP staple and the OS revocation cache, and reports the tri-state revocation
  /// outcome. Cache-only inline (no socket) or, from the async park, network-enabled for
  /// revocation only (AIA disabled). Posture, the strength policy, the staple decision and the
  /// identity post-checks belong to the delegate that owns it. Stateless and thread-reusable.
  /// </summary>
  TWindowsChainEngine = class sealed(TInterfacedObject, IPlatformChainEngine)
  public
    function Capabilities: TPlatformChainCapabilities;
    function EvaluateServer(const ARequest: TPlatformChainRequest;
      out AResult: TPlatformChainResult; out AAlert: TTlsAlertDescription): Boolean;
    function EvaluateClient(const ARequest: TPlatformChainRequest;
      out AResult: TPlatformChainResult; out AAlert: TTlsAlertDescription): Boolean;
  end;

{$ENDIF}

implementation

{$IFDEF TLSLIB_MSWINDOWS}

const
  CRYPT32_DLL = 'crypt32.dll';

  X509_ASN_ENCODING = $00000001;
  PKCS_7_ASN_ENCODING = $00010000;
  MY_ENCODING_TYPE = X509_ASN_ENCODING or PKCS_7_ASN_ENCODING;

  CERT_STORE_PROV_MEMORY = PAnsiChar(2);
  CERT_STORE_ADD_ALWAYS = 4;
  CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL = $00000004;
  // revocation over the whole chain except the root, bounded by one accumulative timeout so
  // a cache-only build (no socket) settles promptly instead of per-element stalls
  CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT = $40000000;
  CERT_CHAIN_REVOCATION_ACCUMULATIVE_TIMEOUT = $08000000;
  // live mode uses the network for revocation only; the presented intermediates already seed the
  // path, so an AIA fetch would just build a different one (a divergent verdict, not a stronger one)
  CERT_CHAIN_DISABLE_AIA = $00002000;
  // the SSL policy flag set that ignores every revocation-unknown outcome, so an effective-Soft
  // evaluation soft-fails on a missing/offline responder AND still reports a real error (e.g. a
  // name mismatch) that a single dwError would otherwise mask behind CRYPT_E_NO_REVOCATION_CHECK
  CERT_CHAIN_POLICY_IGNORE_ALL_REV_UNKNOWN_FLAGS = $00000F00;
  // CERT_TRUST_STATUS.dwErrorStatus bits inspected alongside the policy dwError in live mode
  CERT_TRUST_REVOCATION_STATUS_UNKNOWN = $00000040;
  CERT_TRUST_IS_OFFLINE_REVOCATION = $01000000;
  // the leaf property crypt32 reads a stapled OCSP response from, so revocation is decided
  // from the handshake staple without a network fetch
  CERT_OCSP_RESPONSE_PROP_ID = 70;

  USAGE_MATCH_TYPE_AND = $00000000;
  AUTHTYPE_SERVER = 2;
  AUTHTYPE_CLIENT = 1;
  CERT_CHAIN_POLICY_SSL = PAnsiChar(4);

  SZOID_PKIX_KP_SERVER_AUTH: PAnsiChar = '1.3.6.1.5.5.7.3.1';
  SZOID_PKIX_KP_CLIENT_AUTH: PAnsiChar = '1.3.6.1.5.5.7.3.2';
  // anyExtendedKeyUsage: a root carrying it is valid for every purpose, server auth included
  SZOID_ANY_ENHANCED_KEY_USAGE: PAnsiChar = '2.5.29.37.0';

  // CertGetEnhancedKeyUsage sets this as last-error when a certificate has neither an EKU
  // extension nor a trust-purpose property: it is then valid for all uses (not disabled)
  CRYPT_E_NOT_FOUND = DWORD($80092004);

  // the configured client-CA anchors are the only trusted roots for the client-auth chain engine;
  // the CA flag lets a non-self-signed anchor still root a path
  CERT_CHAIN_EXCLUSIVE_ENABLE_CA_FLAG = $00000001;

  // CertVerifyCertificateChainPolicy dwError values worth mapping precisely.
  CERT_E_EXPIRED = DWORD($800B0101);
  CERT_E_VALIDITYPERIODNESTING = DWORD($800B0102);
  CERT_E_UNTRUSTEDROOT = DWORD($800B0109);
  CERT_E_CHAINING = DWORD($800B010A);
  CERT_E_REVOKED = DWORD($800B010C);
  CERT_E_WRONG_USAGE = DWORD($800B0110);
  CERT_E_UNTRUSTEDCA = DWORD($800B0112);
  TRUST_E_CERT_SIGNATURE = DWORD($80096004);
  // a definitive revocation from the chain engine: crypt32 reports CRYPT_E_REVOKED, while the
  // wintrust/authenticode path uses CERT_E_REVOKED - map both so a revoked leaf is never generic
  CERT_E_REVOKED_ALT = DWORD($80092010); // CRYPT_E_REVOKED
  // revocation could not be completed (no cached data / responder unreachable): indeterminate
  CRYPT_E_NO_REVOCATION_CHECK = DWORD($80092012);
  CRYPT_E_REVOCATION_OFFLINE = DWORD($80092013);

type
  HCERTSTORE = Pointer;

  CRYPT_DATA_BLOB = record
    cbData: DWORD;
    pbData: PByte;
  end;

  PCERT_CONTEXT = ^CERT_CONTEXT;

  CERT_CONTEXT = record
    dwCertEncodingType: DWORD;
    pbCertEncoded: PByte;
    cbCertEncoded: DWORD;
    pCertInfo: Pointer;
    hCertStore: HCERTSTORE;
  end;

  CERT_ENHKEY_USAGE = record
    cUsageIdentifier: DWORD;
    rgpszUsageIdentifier: Pointer;
  end;

  CERT_USAGE_MATCH = record
    dwType: DWORD;
    Usage: CERT_ENHKEY_USAGE;
  end;

  CERT_CHAIN_PARA = record
    cbSize: DWORD;
    RequestedUsage: CERT_USAGE_MATCH;
  end;

  // the extended CERT_CHAIN_PARA (cbSize covers the extra fields): the live path uses
  // dwUrlRetrievalTimeout to bound the OS revocation fetch to the host's deadline
  CERT_CHAIN_PARA_EX = record
    cbSize: DWORD;
    RequestedUsage: CERT_USAGE_MATCH;
    RequestedIssuancePolicy: CERT_USAGE_MATCH;
    dwUrlRetrievalTimeout: DWORD;
    fCheckRevocationFreshnessTime: BOOL;
    dwRevocationFreshnessTime: DWORD;
    pftCacheResync: Pointer;
    pStrongSignPara: Pointer;
    dwStrongSignFlags: DWORD;
  end;

  CERT_CHAIN_POLICY_PARA = record
    cbSize: DWORD;
    dwFlags: DWORD;
    pvExtraPolicyPara: Pointer;
  end;

  CERT_CHAIN_POLICY_STATUS = record
    cbSize: DWORD;
    dwError: DWORD;
    lChainIndex: LongInt;
    lElementIndex: LongInt;
    pvExtraPolicyStatus: Pointer;
  end;

  SSL_EXTRA_CERT_CHAIN_POLICY_PARA = record
    cbSize: DWORD;
    dwAuthType: DWORD;
    fdwChecks: DWORD;
    pwszServerName: PWideChar;
  end;

  CERT_CHAIN_ENGINE_CONFIG = record
    cbSize: DWORD;
    hRestrictedRoot: HCERTSTORE;
    hRestrictedTrust: HCERTSTORE;
    hRestrictedOther: HCERTSTORE;
    cAdditionalStore: DWORD;
    rghAdditionalStore: Pointer;
    dwFlags: DWORD;
    dwUrlRetrievalTimeout: DWORD;
    MaximumCachedCertificates: DWORD;
    CycleDetectionModulus: DWORD;
    hExclusiveRoot: HCERTSTORE;
    hExclusiveTrustedPeople: HCERTSTORE;
    dwExclusiveFlags: DWORD;
  end;

  CERT_TRUST_STATUS = record
    dwInfoStatus: DWORD;
    dwErrorStatus: DWORD;
  end;

  PCERT_CHAIN_ELEMENT = ^CERT_CHAIN_ELEMENT;

  CERT_CHAIN_ELEMENT = record
    cbSize: DWORD;
    pCertContext: PCERT_CONTEXT;
    TrustStatus: CERT_TRUST_STATUS;
    pRevocationInfo: Pointer;
    pIssuanceUsage: Pointer;
    pApplicationUsage: Pointer;
    pwszExtendedErrorInfo: PWideChar;
  end;

  PPCERT_CHAIN_ELEMENT = ^PCERT_CHAIN_ELEMENT;
  PCERT_SIMPLE_CHAIN = ^CERT_SIMPLE_CHAIN;

  CERT_SIMPLE_CHAIN = record
    cbSize: DWORD;
    TrustStatus: CERT_TRUST_STATUS;
    cElement: DWORD;
    rgpElement: PPCERT_CHAIN_ELEMENT;
    pTrustListInfo: Pointer;
    fHasRevocationFreshnessTime: BOOL;
    dwRevocationFreshnessTime: DWORD;
  end;

  PPCERT_SIMPLE_CHAIN = ^PCERT_SIMPLE_CHAIN;
  PCERT_CHAIN_CONTEXT = ^CERT_CHAIN_CONTEXT;

  CERT_CHAIN_CONTEXT = record
    cbSize: DWORD;
    TrustStatus: CERT_TRUST_STATUS;
    cChain: DWORD;
    rgpChain: PPCERT_SIMPLE_CHAIN;
    cLowerQualityChainContext: DWORD;
    rgpLowerQualityChainContext: Pointer;
    fHasRevocationFreshnessTime: BOOL;
    dwRevocationFreshnessTime: DWORD;
  end;

  TCertOpenSystemStoreWFunc = function(AProv: Pointer;
    ASubsystemProtocol: PWideChar): HCERTSTORE; stdcall;
  TCertCloseStoreFunc = function(ACertStore: HCERTSTORE; AFlags: DWORD)
    : BOOL; stdcall;
  TCertEnumCertificatesInStoreFunc = function(ACertStore: HCERTSTORE;
    APrevCertContext: PCERT_CONTEXT): PCERT_CONTEXT; stdcall;
  TCertCreateCertificateContextFunc = function(ACertEncodingType: DWORD;
    ACertEncoded: PByte; ACertEncodedSize: DWORD): PCERT_CONTEXT; stdcall;
  TCertFreeCertificateContextFunc = function(ACertContext: PCERT_CONTEXT)
    : BOOL; stdcall;
  TCertSetCertificateContextPropertyFunc = function(ACertContext: PCERT_CONTEXT;
    APropId: DWORD; AFlags: DWORD; APvData: Pointer): BOOL; stdcall;
  TCertOpenStoreFunc = function(AStoreProvider: PAnsiChar;
    AEncodingType: DWORD; ACryptProv: Pointer; AFlags: DWORD; APara: Pointer)
    : HCERTSTORE; stdcall;
  TCertAddEncodedCertificateToStoreFunc = function(ACertStore: HCERTSTORE;
    ACertEncodingType: DWORD; ACertEncoded: PByte; ACertEncodedSize: DWORD;
    AAddDisposition: DWORD; ACertContext: Pointer): BOOL; stdcall;
  // AChainPara is a pointer so either the plain CERT_CHAIN_PARA (inline) or the extended
  // CERT_CHAIN_PARA_EX (live, with a fetch timeout) can be passed
  TCertGetCertificateChainFunc = function(AChainEngine: Pointer;
    ACertContext: PCERT_CONTEXT; ATime: Pointer; AAdditionalStore: HCERTSTORE;
    AChainPara: Pointer; AFlags: DWORD; AReserved: Pointer;
    var AChainContext: Pointer): BOOL; stdcall;
  TCertFreeCertificateChainProc = procedure(AChainContext: Pointer); stdcall;
  TCertVerifyCertificateChainPolicyFunc = function(APolicyOID: PAnsiChar;
    AChainContext: Pointer; const APolicyPara: CERT_CHAIN_POLICY_PARA;
    var APolicyStatus: CERT_CHAIN_POLICY_STATUS): BOOL; stdcall;
  TCertCreateCertificateChainEngineFunc = function(
    const AConfig: CERT_CHAIN_ENGINE_CONFIG; var AChainEngine: Pointer): BOOL; stdcall;
  TCertFreeCertificateChainEngineProc = procedure(AChainEngine: Pointer); stdcall;
  // reads the effective enhanced key usage (extension intersected with the admin trust-purpose
  // property when dwFlags = 0); the two-call size/decode pattern fills a CERT_ENHKEY_USAGE
  TCertGetEnhancedKeyUsageFunc = function(ACertContext: PCERT_CONTEXT; AFlags: DWORD;
    AUsage: Pointer; var ASize: DWORD): BOOL; stdcall;

  /// <summary>
  /// Resolves the crypt32 entry points once via LoadLibrary + GetProcAddress, so
  /// the optional package imposes no implicit crypt32 import and an absent entry
  /// point leaves the reader not ready (callers fail closed).
  /// </summary>
  TWindowsTrustApi = class sealed
  strict private
  class var
    FReady: Boolean;
    FModule: THandle;
    FCertOpenSystemStoreW: TCertOpenSystemStoreWFunc;
    FCertCloseStore: TCertCloseStoreFunc;
    FCertEnumCertificatesInStore: TCertEnumCertificatesInStoreFunc;
    FCertCreateCertificateContext: TCertCreateCertificateContextFunc;
    FCertFreeCertificateContext: TCertFreeCertificateContextFunc;
    FCertSetCertificateContextProperty: TCertSetCertificateContextPropertyFunc;
    FCertOpenStore: TCertOpenStoreFunc;
    FCertAddEncodedCertificateToStore: TCertAddEncodedCertificateToStoreFunc;
    FCertGetCertificateChain: TCertGetCertificateChainFunc;
    FCertFreeCertificateChain: TCertFreeCertificateChainProc;
    FCertVerifyCertificateChainPolicy: TCertVerifyCertificateChainPolicyFunc;
    FCertCreateCertificateChainEngine: TCertCreateCertificateChainEngineFunc;
    FCertFreeCertificateChainEngine: TCertFreeCertificateChainEngineProc;
    FCertGetEnhancedKeyUsage: TCertGetEnhancedKeyUsageFunc;
    class function GetProc(const AName: AnsiString): Pointer; static;
    /// <summary>True if the root's effective enhanced key usage (its EKU extension intersected
    /// with the admin trust-purpose property) permits TLS server authentication: valid for all
    /// uses (no EKU/property), or the list contains serverAuth or anyExtendedKeyUsage. A root
    /// disabled for all purposes, or trusted only for a non-serverAuth purpose, returns False.</summary>
    class function IsServerAuthAnchor(AContext: PCERT_CONTEXT): Boolean; static;
    class procedure CollectStore(AStoreName: PWideChar;
      const AExclude: TDictionary<TBytes, Boolean>;
      const ADest: TList<TBytes>; AServerAuthOnly: Boolean); static;
    class function UnixMillisToFileTime(AMillisUtc: UInt64): FILETIME; static;
  private
    class procedure ResolveDynamicImports; static;
    /// <summary>Frees the loaded crypt32 module (unit teardown).</summary>
    class procedure ReleaseDynamicImports; static;
    /// <summary>Maps a definitive non-revocation chain-policy dwError to the fatal alert (expiry,
    /// untrusted root, wrong usage, name mismatch, catch-all bad_certificate). A revocation dwError
    /// is not handled here - it is classified into the tri-state outcome by ClassifyPolicyStatus.</summary>
    class procedure MapPolicyError(ADwError: DWORD;
      out AAlert: TTlsAlertDescription); static;
    /// <summary>The CertGetCertificateChain flags for a revocation level and network mode: cache-only
    /// inline (revocation added unless None), or network-enabled for a live check (whole-chain
    /// revocation with AIA disabled so the built path matches the presented one).</summary>
    class function ChainFlags(ARevocation: TPlatformRevocationCheck;
      ANetworkAllowed: Boolean): DWORD; static;
    /// <summary>The chain-policy dwFlags for a revocation level: BestEffort ignores a
    /// revocation-unknown (soft-fail without masking a real error); None and RequirePositive keep 0
    /// (None has nothing to be unknown, RequirePositive must reject an unknown).</summary>
    class function PolicyFlags(ARevocation: TPlatformRevocationCheck): DWORD; static;
    /// <summary>Turns the chain-policy dwError into the platform result: 0 is Good, a definitive
    /// revocation is Revoked, an unreachable/undecided revocation is Indeterminate (each with the
    /// OS-built path and the anchor exempt), and any other error is a False rejection with the
    /// mapped alert. A path that cannot be read is internal_error.</summary>
    class function ClassifyPolicyStatus(ADwError: DWORD; AChainCtx: Pointer;
      out AResult: TPlatformChainResult; out AAlert: TTlsAlertDescription): Boolean; static;
    /// <summary>The raw DER of the ROOT store (server-auth-capable roots only) minus the
    /// Disallowed store. Validation and de-duplication are the caller's responsibility.</summary>
    class function HarvestAnchors: TArray<TBytes>; static;
    /// <summary>Reads the DER of the end-entity simple chain the OS built (rgpChain[0]): element 0
    /// the leaf, the last element the anchor. False on any malformed field (no chain/element, nil
    /// or empty encoded cert) so the caller fails closed.</summary>
    class function ReadChainPath(AChainCtx: Pointer;
      out APath: TArray<TBytes>): Boolean; static;
    /// <summary>Runs the OS SSL server-authentication chain evaluation over the OS ROOT store,
    /// consuming the stapled OCSP response as cached revocation data, at the validation time
    /// ARequest.Clock supplies (nil = system time). ARequest.Revocation fixes the revocation flags
    /// and ARequest.NetworkAllowed the cache-only-vs-live mode (live bounds the fetch by
    /// ARequest.DeadlineMs). Returns True with the tri-state result (path + outcome) when the OS
    /// built and trusted a path; on a definitive non-revocation failure False with AAlert.</summary>
    class function EvaluateServer(const ARequest: TPlatformChainRequest;
      out AResult: TPlatformChainResult; out AAlert: TTlsAlertDescription): Boolean; static;
    /// <summary>Runs the OS chain evaluation for a peer CLIENT certificate against an exclusive-root
    /// engine built over ARequest.Anchors alone (never the OS/public roots), with the clientAuth EKU
    /// and the AUTHTYPE_CLIENT SSL policy (a client certificate is never stapled). Same revocation
    /// and network handling as the server path. Returns False with internal_error when the
    /// exclusive-engine entry point is unavailable.</summary>
    class function EvaluateClient(const ARequest: TPlatformChainRequest;
      out AResult: TPlatformChainResult; out AAlert: TTlsAlertDescription): Boolean; static;
  end;

{ TWindowsTrustApi }

class function TWindowsTrustApi.GetProc(const AName: AnsiString): Pointer;
begin
  Result := GetProcAddress(FModule, PAnsiChar(AName));
end;

class procedure TWindowsTrustApi.ResolveDynamicImports;
begin
  FReady := False;
  FModule := SafeLoadLibrary(CRYPT32_DLL, SEM_FAILCRITICALERRORS);
  if FModule = 0 then
    Exit;

  FCertOpenSystemStoreW := TCertOpenSystemStoreWFunc(
    GetProc('CertOpenSystemStoreW'));
  FCertCloseStore := TCertCloseStoreFunc(GetProc('CertCloseStore'));
  FCertEnumCertificatesInStore := TCertEnumCertificatesInStoreFunc(
    GetProc('CertEnumCertificatesInStore'));
  FCertCreateCertificateContext := TCertCreateCertificateContextFunc(
    GetProc('CertCreateCertificateContext'));
  FCertFreeCertificateContext := TCertFreeCertificateContextFunc(
    GetProc('CertFreeCertificateContext'));
  FCertSetCertificateContextProperty := TCertSetCertificateContextPropertyFunc(
    GetProc('CertSetCertificateContextProperty'));
  FCertOpenStore := TCertOpenStoreFunc(GetProc('CertOpenStore'));
  FCertAddEncodedCertificateToStore := TCertAddEncodedCertificateToStoreFunc(
    GetProc('CertAddEncodedCertificateToStore'));
  FCertGetCertificateChain := TCertGetCertificateChainFunc(
    GetProc('CertGetCertificateChain'));
  FCertFreeCertificateChain := TCertFreeCertificateChainProc(
    GetProc('CertFreeCertificateChain'));
  FCertVerifyCertificateChainPolicy := TCertVerifyCertificateChainPolicyFunc(
    GetProc('CertVerifyCertificateChainPolicy'));
  // reads the effective trust purpose so the anchor harvest keeps only server-auth roots
  FCertGetEnhancedKeyUsage := TCertGetEnhancedKeyUsageFunc(
    GetProc('CertGetEnhancedKeyUsage'));
  // the exclusive-root chain engine (client-auth delegate) is optional and not part of FReady:
  // an OS lacking it simply cannot serve the OS client delegate, not the whole package
  FCertCreateCertificateChainEngine := TCertCreateCertificateChainEngineFunc(
    GetProc('CertCreateCertificateChainEngine'));
  FCertFreeCertificateChainEngine := TCertFreeCertificateChainEngineProc(
    GetProc('CertFreeCertificateChainEngine'));

  FReady := System.Assigned(FCertOpenSystemStoreW) and
    System.Assigned(FCertCloseStore) and
    System.Assigned(FCertEnumCertificatesInStore) and
    System.Assigned(FCertCreateCertificateContext) and
    System.Assigned(FCertFreeCertificateContext) and
    System.Assigned(FCertOpenStore) and
    System.Assigned(FCertAddEncodedCertificateToStore) and
    System.Assigned(FCertGetCertificateChain) and
    System.Assigned(FCertFreeCertificateChain) and
    System.Assigned(FCertVerifyCertificateChainPolicy) and
    System.Assigned(FCertGetEnhancedKeyUsage);
end;

class procedure TWindowsTrustApi.ReleaseDynamicImports;
begin
  if FModule <> 0 then
  begin
    FreeLibrary(FModule);
    FModule := 0;
  end;
end;

class function TWindowsTrustApi.IsServerAuthAnchor(AContext: PCERT_CONTEXT): Boolean;
var
  LSize: DWORD;
  LBuf: TBytes;
  LUsage: ^CERT_ENHKEY_USAGE;
  LOids: ^PAnsiChar;
  LI: DWORD;
begin
  // read the EFFECTIVE enhanced key usage = the certificate's own EKU extension intersected with
  // the admin-configured trust-purpose property (dwFlags = 0, what the chain engine applies).
  if not System.Assigned(FCertGetEnhancedKeyUsage) then
    Exit(True); // cannot evaluate purpose: do not over-restrict (FReady already gates on it)
  LSize := 0;
  SetLastError(0);
  if not FCertGetEnhancedKeyUsage(AContext, 0, nil, LSize) then
    // no EKU extension and no property leaves last-error CRYPT_E_NOT_FOUND: valid for all uses
    Exit(GetLastError = CRYPT_E_NOT_FOUND);
  if LSize < SizeOf(CERT_ENHKEY_USAGE) then
    Exit(False);
  SetLength(LBuf, LSize);
  // reset last-error before the decode call: the sizing call above may have left a stale
  // CRYPT_E_NOT_FOUND that would otherwise make a disabled (empty-usage) root look unrestricted
  SetLastError(0);
  LUsage := Pointer(@LBuf[0]);
  if not FCertGetEnhancedKeyUsage(AContext, 0, LUsage, LSize) then
    Exit(GetLastError = CRYPT_E_NOT_FOUND);
  if LUsage^.cUsageIdentifier = 0 then
    // empty usage set: "all uses" only when CRYPT_E_NOT_FOUND, else disabled for every purpose
    Exit(GetLastError = CRYPT_E_NOT_FOUND);
  LOids := LUsage^.rgpszUsageIdentifier;
  for LI := 0 to LUsage^.cUsageIdentifier - 1 do
  begin
    if (StrComp(LOids^, SZOID_PKIX_KP_SERVER_AUTH) = 0) or
      (StrComp(LOids^, SZOID_ANY_ENHANCED_KEY_USAGE) = 0) then
      Exit(True);
    Inc(LOids);
  end;
  Result := False;
end;

class procedure TWindowsTrustApi.CollectStore(AStoreName: PWideChar;
  const AExclude: TDictionary<TBytes, Boolean>; const ADest: TList<TBytes>;
  AServerAuthOnly: Boolean);
var
  LStore: HCERTSTORE;
  LContext: PCERT_CONTEXT;
  LDer: TBytes;
begin
  LDer := nil;
  LStore := FCertOpenSystemStoreW(nil, AStoreName);
  if LStore = nil then
    Exit;
  try
    LContext := FCertEnumCertificatesInStore(LStore, nil);
    while LContext <> nil do
    begin
      if (LContext^.cbCertEncoded > 0) and (LContext^.pbCertEncoded <> nil) and
        ((not AServerAuthOnly) or IsServerAuthAnchor(LContext)) then
      begin
        SetLength(LDer, LContext^.cbCertEncoded);
        Move(LContext^.pbCertEncoded^, LDer[0], LContext^.cbCertEncoded);
        if (AExclude = nil) or (not AExclude.ContainsKey(LDer)) then
          ADest.Add(Copy(LDer, 0, Length(LDer)));
      end;
      LContext := FCertEnumCertificatesInStore(LStore, LContext);
    end;
  finally
    FCertCloseStore(LStore, 0);
  end;
end;

class function TWindowsTrustApi.HarvestAnchors: TArray<TBytes>;
var
  LDisallowed, LTrusted: TList<TBytes>;
  LExclude: TDictionary<TBytes, Boolean>;
  LI: Integer;
begin
  Result := nil;
  if not FReady then
    Exit;
  LDisallowed := TList<TBytes>.Create;
  try
    // Distrust first, so it can be subtracted from the trusted store.
    CollectStore('Disallowed', nil, LDisallowed, False);
    LExclude := TDictionary<TBytes, Boolean>.Create;
    try
      for LI := 0 to LDisallowed.Count - 1 do
        LExclude.AddOrSetValue(LDisallowed[LI], True);
      LTrusted := TList<TBytes>.Create;
      try
        // ROOT only, filtered to server-auth-capable roots: the "CA" store holds cached
        // intermediates, not anchors, and roots disabled or scoped to a non-serverAuth purpose
        // must not become standalone trust anchors
        CollectStore('ROOT', LExclude, LTrusted, True);
        Result := LTrusted.ToArray;
      finally
        LTrusted.Free;
      end;
    finally
      LExclude.Free;
    end;
  finally
    LDisallowed.Free;
  end;
end;

class function TWindowsTrustApi.UnixMillisToFileTime(AMillisUtc: UInt64): FILETIME;
const
  // FILETIME counts 100ns ticks from 1601-01-01, so scale ms by 10000 and add the ticks
  // between the 1601 and 1970 (Unix) epochs
  TicksPerMillisecond = UInt64(10000);
  UnixEpochInTicks = UInt64(116444736000000000);
var
  LTicks: UInt64;
begin
  LTicks := AMillisUtc * TicksPerMillisecond + UnixEpochInTicks;
  Result.dwLowDateTime := DWORD(LTicks and $FFFFFFFF);
  Result.dwHighDateTime := DWORD(LTicks shr 32);
end;

class function TWindowsTrustApi.ReadChainPath(AChainCtx: Pointer;
  out APath: TArray<TBytes>): Boolean;
var
  LCtx: PCERT_CHAIN_CONTEXT;
  LSimple: PCERT_SIMPLE_CHAIN;
  LElem: PCERT_CHAIN_ELEMENT;
  LCert: PCERT_CONTEXT;
  LI: DWORD;
begin
  Result := False;
  APath := nil;
  if AChainCtx = nil then
    Exit;
  LCtx := PCERT_CHAIN_CONTEXT(AChainCtx);
  if (LCtx^.cChain = 0) or (LCtx^.rgpChain = nil) then
    Exit;
  LSimple := LCtx^.rgpChain^;
  if (LSimple = nil) or (LSimple^.cElement = 0) or (LSimple^.rgpElement = nil) then
    Exit;
  SetLength(APath, LSimple^.cElement);
  for LI := 0 to LSimple^.cElement - 1 do
  begin
    LElem := PPCERT_CHAIN_ELEMENT(PByte(LSimple^.rgpElement) +
      LI * SizeOf(Pointer))^;
    if LElem = nil then
      Exit;
    LCert := LElem^.pCertContext;
    if (LCert = nil) or (LCert^.pbCertEncoded = nil) or
      (LCert^.cbCertEncoded = 0) then
      Exit;
    SetLength(APath[LI], LCert^.cbCertEncoded);
    Move(LCert^.pbCertEncoded^, APath[LI][0], LCert^.cbCertEncoded);
  end;
  Result := True;
end;

class function TWindowsTrustApi.ChainFlags(ARevocation: TPlatformRevocationCheck;
  ANetworkAllowed: Boolean): DWORD;
begin
  if ANetworkAllowed then
    // live: whole-chain revocation over the network, AIA disabled so the built path matches the
    // presented one; the accumulative timeout bounds the whole build to the deadline
    Result := CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT or
      CERT_CHAIN_REVOCATION_ACCUMULATIVE_TIMEOUT or CERT_CHAIN_DISABLE_AIA
  else
  begin
    // cache-only inline (no socket); None skips revocation, otherwise it is checked against the
    // staple / OS cache
    Result := CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL;
    if ARevocation <> TPlatformRevocationCheck.None then
      Result := Result or CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT or
        CERT_CHAIN_REVOCATION_ACCUMULATIVE_TIMEOUT;
  end;
end;

class function TWindowsTrustApi.PolicyFlags(ARevocation: TPlatformRevocationCheck): DWORD;
begin
  // BestEffort ignores a revocation-unknown at the policy layer, so a missing/offline responder
  // soft-fails without masking a real error (e.g. a name mismatch); None and RequirePositive keep
  // dwFlags 0 so an unknown revocation surfaces (and, under RequirePositive, rejects)
  if ARevocation = TPlatformRevocationCheck.BestEffort then
    Result := CERT_CHAIN_POLICY_IGNORE_ALL_REV_UNKNOWN_FLAGS
  else
    Result := 0;
end;

class function TWindowsTrustApi.ClassifyPolicyStatus(ADwError: DWORD; AChainCtx: Pointer;
  out AResult: TPlatformChainResult; out AAlert: TTlsAlertDescription): Boolean;
var
  LOsPath: TArray<TBytes>;
begin
  Result := False;
  AResult := Default(TPlatformChainResult);
  if ADwError = 0 then
    AResult.Outcome := TLiveRevocationOutcome.Good
  else if (ADwError = CERT_E_REVOKED) or (ADwError = CERT_E_REVOKED_ALT) then
    // a definitive revocation from the chain engine
    AResult.Outcome := TLiveRevocationOutcome.Revoked
  else if (ADwError = CRYPT_E_NO_REVOCATION_CHECK) or
    (ADwError = CRYPT_E_REVOCATION_OFFLINE) then
    // revocation could not be reached or decided
    AResult.Outcome := TLiveRevocationOutcome.Indeterminate
  else
  begin
    // a definitive non-revocation trust failure: reject with the mapped alert
    MapPolicyError(ADwError, AAlert);
    Exit;
  end;
  // the OS-built path (leaf-first, ending at the anchor) is the validated chain; the anchor (last
  // element) is exempt from the strength policy the delegate applies over it
  if not ReadChainPath(AChainCtx, LOsPath) then
  begin
    AAlert := TTlsAlertDescription.InternalError;
    Exit;
  end;
  AResult.Path := LOsPath;
  AResult.PolicyExempt := TArray<TBytes>.Create(LOsPath[High(LOsPath)]);
  Result := True;
end;

class function TWindowsTrustApi.EvaluateServer(const ARequest: TPlatformChainRequest;
  out AResult: TPlatformChainResult; out AAlert: TTlsAlertDescription): Boolean;
var
  LLeaf: PCERT_CONTEXT;
  LStore: HCERTSTORE;
  LChain: Pointer;
  LUsageArr: array [0 .. 0] of PAnsiChar;
  LChainPara: CERT_CHAIN_PARA;
  LChainParaEx: CERT_CHAIN_PARA_EX;
  LParaPtr: Pointer;
  LPolicyPara: CERT_CHAIN_POLICY_PARA;
  LSslPara: SSL_EXTRA_CERT_CHAIN_POLICY_PARA;
  LStatus: CERT_CHAIN_POLICY_STATUS;
  LHost: string;
  LServerName: UnicodeString;
  LStapleBlob: CRYPT_DATA_BLOB;
  LFileTime: FILETIME;
  LTimePtr: Pointer;
  LFlags: DWORD;
  LI: Integer;
begin
  Result := False;
  AResult := Default(TPlatformChainResult);
  AAlert := TTlsAlertDescription.BadCertificate;

  if Length(ARequest.Chain) = 0 then
    Exit;

  if not FReady then
  begin
    AAlert := TTlsAlertDescription.InternalError;
    Exit;
  end;

  // the OS name check only ever sees a DNS host (empty for an IP literal); an IP is matched in
  // the library against iPAddress SANs by the delegate that owns this engine
  LHost := ARequest.ServerName.AsDns;

  LLeaf := FCertCreateCertificateContext(MY_ENCODING_TYPE, PByte(ARequest.Chain[0]),
    Length(ARequest.Chain[0]));
  if LLeaf = nil then
    Exit;

  LStore := FCertOpenStore(CERT_STORE_PROV_MEMORY, MY_ENCODING_TYPE, nil, 0, nil);
  LChain := nil;
  try
    // the staple, attached to the leaf, is read as cached revocation data (no responder fetch)
    if (Length(ARequest.OcspStaple) > 0) and
      System.Assigned(FCertSetCertificateContextProperty) then
    begin
      LStapleBlob.cbData := Length(ARequest.OcspStaple);
      LStapleBlob.pbData := PByte(ARequest.OcspStaple);
      FCertSetCertificateContextProperty(LLeaf, CERT_OCSP_RESPONSE_PROP_ID, 0,
        @LStapleBlob);
    end;

    // Feed the presented intermediates so the engine can build the path without an AIA fetch.
    if LStore <> nil then
    begin
      for LI := 1 to Length(ARequest.Chain) - 1 do
      begin
        if Length(ARequest.Chain[LI]) > 0 then
          FCertAddEncodedCertificateToStore(LStore, MY_ENCODING_TYPE,
            PByte(ARequest.Chain[LI]), Length(ARequest.Chain[LI]),
            CERT_STORE_ADD_ALWAYS, nil);
      end;
    end;

    LUsageArr[0] := SZOID_PKIX_KP_SERVER_AUTH;
    // network on: the extended para carries the fetch deadline; cache-only inline keeps the plain
    // para (a different cbSize changes which fields crypt32 reads)
    if ARequest.NetworkAllowed then
    begin
      FillChar(LChainParaEx, SizeOf(LChainParaEx), 0);
      LChainParaEx.cbSize := SizeOf(LChainParaEx);
      LChainParaEx.RequestedUsage.dwType := USAGE_MATCH_TYPE_AND;
      LChainParaEx.RequestedUsage.Usage.cUsageIdentifier := 1;
      LChainParaEx.RequestedUsage.Usage.rgpszUsageIdentifier := @LUsageArr[0];
      LChainParaEx.dwUrlRetrievalTimeout := ARequest.DeadlineMs;
      LParaPtr := @LChainParaEx;
    end
    else
    begin
      FillChar(LChainPara, SizeOf(LChainPara), 0);
      LChainPara.cbSize := SizeOf(LChainPara);
      LChainPara.RequestedUsage.dwType := USAGE_MATCH_TYPE_AND;
      LChainPara.RequestedUsage.Usage.cUsageIdentifier := 1;
      LChainPara.RequestedUsage.Usage.rgpszUsageIdentifier := @LUsageArr[0];
      LParaPtr := @LChainPara;
    end;

    LFlags := ChainFlags(ARequest.Revocation, ARequest.NetworkAllowed);

    // the injected clock pins the validation time; nil defers to system time
    LTimePtr := nil;
    if ARequest.Clock <> nil then
    begin
      LFileTime := UnixMillisToFileTime(ARequest.Clock.NowUnixMillis);
      LTimePtr := @LFileTime;
    end;

    if not FCertGetCertificateChain(nil, LLeaf, LTimePtr, LStore, LParaPtr,
      LFlags, nil, LChain) then
    begin
      AAlert := TTlsAlertDescription.UnknownCa;
      Exit;
    end;

    FillChar(LSslPara, SizeOf(LSslPara), 0);
    LSslPara.cbSize := SizeOf(LSslPara);
    LSslPara.dwAuthType := AUTHTYPE_SERVER;
    LSslPara.fdwChecks := 0;
    if LHost <> '' then
    begin
      LServerName := UnicodeString(LHost);
      LSslPara.pwszServerName := PWideChar(LServerName);
    end
    else
      LSslPara.pwszServerName := nil;

    FillChar(LPolicyPara, SizeOf(LPolicyPara), 0);
    LPolicyPara.cbSize := SizeOf(LPolicyPara);
    LPolicyPara.dwFlags := PolicyFlags(ARequest.Revocation);
    LPolicyPara.pvExtraPolicyPara := @LSslPara;

    FillChar(LStatus, SizeOf(LStatus), 0);
    LStatus.cbSize := SizeOf(LStatus);

    if not FCertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_SSL, LChain,
      LPolicyPara, LStatus) then
    begin
      AAlert := TTlsAlertDescription.BadCertificate;
      Exit;
    end;

    Result := ClassifyPolicyStatus(LStatus.dwError, LChain, AResult, AAlert);
  finally
    if LChain <> nil then
      FCertFreeCertificateChain(LChain);
    if LStore <> nil then
      FCertCloseStore(LStore, 0);
    FCertFreeCertificateContext(LLeaf);
  end;
end;

class procedure TWindowsTrustApi.MapPolicyError(ADwError: DWORD;
  out AAlert: TTlsAlertDescription);
begin
  case ADwError of
    CERT_E_EXPIRED, CERT_E_VALIDITYPERIODNESTING:
      AAlert := TTlsAlertDescription.CertificateExpired;
    CERT_E_UNTRUSTEDROOT, CERT_E_UNTRUSTEDCA, CERT_E_CHAINING,
      TRUST_E_CERT_SIGNATURE:
      AAlert := TTlsAlertDescription.UnknownCa;
    CERT_E_WRONG_USAGE:
      AAlert := TTlsAlertDescription.UnsupportedCertificate;
  else
    // CERT_E_CN_NO_MATCH and everything else map to bad_certificate.
    AAlert := TTlsAlertDescription.BadCertificate;
  end;
end;

class function TWindowsTrustApi.EvaluateClient(const ARequest: TPlatformChainRequest;
  out AResult: TPlatformChainResult; out AAlert: TTlsAlertDescription): Boolean;
var
  LLeaf: PCERT_CONTEXT;
  LRootStore, LInterStore: HCERTSTORE;
  LEngine, LChain: Pointer;
  LUsageArr: array [0 .. 0] of PAnsiChar;
  LChainPara: CERT_CHAIN_PARA;
  LChainParaEx: CERT_CHAIN_PARA_EX;
  LParaPtr: Pointer;
  LEngineConfig: CERT_CHAIN_ENGINE_CONFIG;
  LPolicyPara: CERT_CHAIN_POLICY_PARA;
  LSslPara: SSL_EXTRA_CERT_CHAIN_POLICY_PARA;
  LStatus: CERT_CHAIN_POLICY_STATUS;
  LFileTime: FILETIME;
  LTimePtr: Pointer;
  LFlags: DWORD;
  LI: Integer;
begin
  Result := False;
  AResult := Default(TPlatformChainResult);
  AAlert := TTlsAlertDescription.BadCertificate;

  if Length(ARequest.Chain) = 0 then
    Exit;

  // the exclusive-root engine is required for client-auth: without it a client could validate
  // against the OS/public roots, so fail closed rather than fall back to a weaker check
  if (not FReady) or (not System.Assigned(FCertCreateCertificateChainEngine)) or
    (not System.Assigned(FCertFreeCertificateChainEngine)) then
  begin
    AAlert := TTlsAlertDescription.InternalError;
    Exit;
  end;

  LLeaf := FCertCreateCertificateContext(MY_ENCODING_TYPE, PByte(ARequest.Chain[0]),
    Length(ARequest.Chain[0]));
  if LLeaf = nil then
    Exit;

  LRootStore := FCertOpenStore(CERT_STORE_PROV_MEMORY, MY_ENCODING_TYPE, nil, 0, nil);
  LInterStore := FCertOpenStore(CERT_STORE_PROV_MEMORY, MY_ENCODING_TYPE, nil, 0, nil);
  LEngine := nil;
  LChain := nil;
  try
    if (LRootStore = nil) or (LInterStore = nil) then
    begin
      AAlert := TTlsAlertDescription.InternalError;
      Exit;
    end;

    // the configured client-CA anchors are the ONLY trusted roots
    for LI := 0 to Length(ARequest.Anchors) - 1 do
      if Length(ARequest.Anchors[LI]) > 0 then
        FCertAddEncodedCertificateToStore(LRootStore, MY_ENCODING_TYPE,
          PByte(ARequest.Anchors[LI]), Length(ARequest.Anchors[LI]),
          CERT_STORE_ADD_ALWAYS, nil);
    // the presented intermediates seed path building (no AIA fetch)
    for LI := 1 to Length(ARequest.Chain) - 1 do
      if Length(ARequest.Chain[LI]) > 0 then
        FCertAddEncodedCertificateToStore(LInterStore, MY_ENCODING_TYPE,
          PByte(ARequest.Chain[LI]), Length(ARequest.Chain[LI]),
          CERT_STORE_ADD_ALWAYS, nil);

    FillChar(LEngineConfig, SizeOf(LEngineConfig), 0);
    LEngineConfig.cbSize := SizeOf(LEngineConfig);
    LEngineConfig.hExclusiveRoot := LRootStore;
    LEngineConfig.dwExclusiveFlags := CERT_CHAIN_EXCLUSIVE_ENABLE_CA_FLAG;
    if not FCertCreateCertificateChainEngine(LEngineConfig, LEngine) then
    begin
      AAlert := TTlsAlertDescription.InternalError;
      Exit;
    end;

    LUsageArr[0] := SZOID_PKIX_KP_CLIENT_AUTH;
    // network on: the extended para carries the fetch deadline; cache-only inline keeps the plain
    // para (a different cbSize changes which fields crypt32 reads)
    if ARequest.NetworkAllowed then
    begin
      FillChar(LChainParaEx, SizeOf(LChainParaEx), 0);
      LChainParaEx.cbSize := SizeOf(LChainParaEx);
      LChainParaEx.RequestedUsage.dwType := USAGE_MATCH_TYPE_AND;
      LChainParaEx.RequestedUsage.Usage.cUsageIdentifier := 1;
      LChainParaEx.RequestedUsage.Usage.rgpszUsageIdentifier := @LUsageArr[0];
      LChainParaEx.dwUrlRetrievalTimeout := ARequest.DeadlineMs;
      LParaPtr := @LChainParaEx;
    end
    else
    begin
      FillChar(LChainPara, SizeOf(LChainPara), 0);
      LChainPara.cbSize := SizeOf(LChainPara);
      LChainPara.RequestedUsage.dwType := USAGE_MATCH_TYPE_AND;
      LChainPara.RequestedUsage.Usage.cUsageIdentifier := 1;
      LChainPara.RequestedUsage.Usage.rgpszUsageIdentifier := @LUsageArr[0];
      LParaPtr := @LChainPara;
    end;

    LFlags := ChainFlags(ARequest.Revocation, ARequest.NetworkAllowed);

    LTimePtr := nil;
    if ARequest.Clock <> nil then
    begin
      LFileTime := UnixMillisToFileTime(ARequest.Clock.NowUnixMillis);
      LTimePtr := @LFileTime;
    end;

    if not FCertGetCertificateChain(LEngine, LLeaf, LTimePtr, LInterStore, LParaPtr,
      LFlags, nil, LChain) then
    begin
      AAlert := TTlsAlertDescription.UnknownCa;
      Exit;
    end;

    FillChar(LSslPara, SizeOf(LSslPara), 0);
    LSslPara.cbSize := SizeOf(LSslPara);
    LSslPara.dwAuthType := AUTHTYPE_CLIENT;
    LSslPara.fdwChecks := 0;
    LSslPara.pwszServerName := nil;

    FillChar(LPolicyPara, SizeOf(LPolicyPara), 0);
    LPolicyPara.cbSize := SizeOf(LPolicyPara);
    LPolicyPara.dwFlags := PolicyFlags(ARequest.Revocation);
    LPolicyPara.pvExtraPolicyPara := @LSslPara;

    FillChar(LStatus, SizeOf(LStatus), 0);
    LStatus.cbSize := SizeOf(LStatus);

    if not FCertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_SSL, LChain,
      LPolicyPara, LStatus) then
    begin
      AAlert := TTlsAlertDescription.BadCertificate;
      Exit;
    end;

    Result := ClassifyPolicyStatus(LStatus.dwError, LChain, AResult, AAlert);
  finally
    if LChain <> nil then
      FCertFreeCertificateChain(LChain);
    if LEngine <> nil then
      FCertFreeCertificateChainEngine(LEngine);
    if LInterStore <> nil then
      FCertCloseStore(LInterStore, 0);
    if LRootStore <> nil then
      FCertCloseStore(LRootStore, 0);
    FCertFreeCertificateContext(LLeaf);
  end;
end;

{ TWindowsRootSource }

function TWindowsRootSource.HarvestRoots: TArray<TBytes>;
var
  LRaw: TArray<TBytes>;
  LI: Integer;
  LAcc: TSystemRootAccumulator;
begin
  Result := nil;
  LRaw := TWindowsTrustApi.HarvestAnchors;
  LAcc := TSystemRootAccumulator.Create;
  try
    for LI := 0 to Length(LRaw) - 1 do
      AddUnique(LAcc, LRaw[LI]);
    Result := LAcc.ToArray;
  finally
    LAcc.Free;
  end;
end;

function TWindowsRootSource.SourceName: string;
begin
  Result := 'Windows';
end;

{ TWindowsChainEngine }

function TWindowsChainEngine.Capabilities: TPlatformChainCapabilities;
begin
  // crypt32 can fetch live revocation, render a cached revocation outcome, and match the DNS host
  Result := [TPlatformChainCapability.LiveFetch, TPlatformChainCapability.CachedRevocation,
    TPlatformChainCapability.DnsIdentity];
end;

function TWindowsChainEngine.EvaluateServer(const ARequest: TPlatformChainRequest;
  out AResult: TPlatformChainResult; out AAlert: TTlsAlertDescription): Boolean;
begin
  Result := TWindowsTrustApi.EvaluateServer(ARequest, AResult, AAlert);
end;

function TWindowsChainEngine.EvaluateClient(const ARequest: TPlatformChainRequest;
  out AResult: TPlatformChainResult; out AAlert: TTlsAlertDescription): Boolean;
begin
  Result := TWindowsTrustApi.EvaluateClient(ARequest, AResult, AAlert);
end;

initialization
  TWindowsTrustApi.ResolveDynamicImports;

finalization
  TWindowsTrustApi.ReleaseDynamicImports;

{$ENDIF}

end.
