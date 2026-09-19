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
  TlpICryptoProvider,
  TlpICertificateTrust,
  TlpICertificateVerifierSource,
  TlpCertificateStrengthPolicy,
  TlpChainAlgorithmPolicy,
  TlpTrustPolicy,
  TlpLiveRevocation,
  TlpIClock,
  TlpServerName,
  TlpSystemTrustExceptions,
  TlpSystemTrustBase,
  TlpOSLiveRevocation;

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
  /// Delegates verification to the Windows chain engine: builds the chain with URL
  /// retrieval forced cache-only (no socket), consuming the handshake OCSP staple as
  /// cached revocation data, then applies the SSL server policy (server-auth EKU + host
  /// name). The revocation posture governs an indeterminate outcome (offline/unchecked):
  /// accepted under Soft, rejected under Hard; a definitive Revoked always rejects. The
  /// injected clock supplies the validation time; nil uses system time. Fail-closed; maps
  /// the policy error to the matching fatal alert.
  /// </summary>
  TWindowsDelegateVerifier = class sealed(TInterfacedObject, IServerCertificateVerifier)
  strict private
    FProvider: ICryptoProvider;
    FPosture: TRevocationPosture;
    FFetch: TSystemTrustFetch;
    FClock: ITlsClock;
    FStrengthPolicy: TCertificateStrengthPolicy;
    FAdvertised: TArray<UInt16>;
  public
    constructor Create(const AProvider: ICryptoProvider;
      APosture: TRevocationPosture; AFetch: TSystemTrustFetch; const AClock: ITlsClock;
      const AStrengthPolicy: TCertificateStrengthPolicy;
      const AAdvertised: TArray<UInt16>);
    function VerifyServerCertificate(const AChain: TArray<TBytes>;
      const AServerName: TServerName; const AOcspStaple: TBytes;
      out AValidatedChain: TArray<TBytes>;
      out AAlert: TTlsAlertDescription): Boolean;
  end;

  /// <summary>
  /// The Windows OS-native live-revocation resolver: re-runs the crypt32 chain engine with network
  /// fetch enabled (revocation only, AIA disabled) off the engine thread in the async park, and
  /// classifies the outcome for the shared base. Host-owned; assign ResolveVerdict to the seam.
  /// </summary>
  TWindowsLiveRevocationResolver = class sealed(TOSLiveRevocationResolver)
  strict private
    FProvider: ICryptoProvider;
    FClock: ITlsClock;
    FStrengthPolicy: TCertificateStrengthPolicy;
    FAdvertised: TArray<UInt16>;
    FDeadlineMs: Cardinal;
  strict protected
    function EvaluateLive(const AChain: TArray<TBytes>; const AHostName: string;
      const AStaple: TBytes; out AOutcome: TLiveRevocationOutcome;
      out ARejectAlert: TTlsAlertDescription): Boolean; override;
  public
    constructor Create(const AProvider: ICryptoProvider; APosture: TRevocationPosture;
      const AClock: ITlsClock; const AStrengthPolicy: TCertificateStrengthPolicy;
      const AAdvertised: TArray<UInt16>; ADeadlineMs: Cardinal;
      const AFallback: TCertificateVerdictResolver);
  end;

  /// <summary>
  /// The Windows server-certificate verifier source: builds a delegate verifier from the
  /// connection's trust context, so its revocation posture and clock are injected the same
  /// way the built-in verifier receives them. AFetch fixes cache-only vs live inline behaviour.
  /// </summary>
  TWindowsServerVerifierSource = class sealed(TInterfacedObject,
    IServerCertificateVerifierSource)
  strict private
    FFetch: TSystemTrustFetch;
  public
    constructor Create(AFetch: TSystemTrustFetch);
    function CreateServerVerifier(const AContext: TServerTrustContext)
      : IServerCertificateVerifier;
  end;

  /// <summary>
  /// Verifies a peer CLIENT certificate (mTLS) via the Windows chain engine, restricted to an
  /// exclusive trust root built from the configured client-CA anchors alone - never the OS or
  /// public-web-PKI roots. Applies the AUTHTYPE_CLIENT SSL policy (clientAuth EKU); posture and
  /// clock are handled exactly as the server delegate (a client certificate is not stapled).
  /// </summary>
  TWindowsClientDelegateVerifier = class sealed(TInterfacedObject,
    IClientCertificateVerifier)
  strict private
    FProvider: ICryptoProvider;
    FAnchors: TArray<TBytes>;
    FPosture: TRevocationPosture;
    FFetch: TSystemTrustFetch;
    FClock: ITlsClock;
    FStrengthPolicy: TCertificateStrengthPolicy;
    FAdvertised: TArray<UInt16>;
  public
    constructor Create(const AProvider: ICryptoProvider;
      const AAnchors: TArray<TBytes>; APosture: TRevocationPosture;
      AFetch: TSystemTrustFetch; const AClock: ITlsClock;
      const AStrengthPolicy: TCertificateStrengthPolicy;
      const AAdvertised: TArray<UInt16>);
    function VerifyClientCertificate(const AChain: TArray<TBytes>;
      out AValidatedChain: TArray<TBytes>;
      out AAlert: TTlsAlertDescription): Boolean;
  end;

  /// <summary>
  /// The Windows OS-native live-revocation resolver for a peer CLIENT certificate (mTLS): re-runs
  /// the exclusive-root crypt32 chain engine over the configured client-CA anchors with network
  /// fetch enabled (revocation only, AIA disabled) off the engine thread in the async park, and
  /// classifies the outcome for the shared base. Host-owned; assign ResolveVerdict to the seam.
  /// </summary>
  TWindowsClientLiveRevocationResolver = class sealed(TOSLiveRevocationResolver)
  strict private
    FProvider: ICryptoProvider;
    FAnchors: TArray<TBytes>;
    FClock: ITlsClock;
    FStrengthPolicy: TCertificateStrengthPolicy;
    FAdvertised: TArray<UInt16>;
    FDeadlineMs: Cardinal;
  strict protected
    function EvaluateLive(const AChain: TArray<TBytes>; const AHostName: string;
      const AStaple: TBytes; out AOutcome: TLiveRevocationOutcome;
      out ARejectAlert: TTlsAlertDescription): Boolean; override;
  public
    constructor Create(const AProvider: ICryptoProvider;
      const AAnchors: TArray<TBytes>; APosture: TRevocationPosture;
      const AClock: ITlsClock; const AStrengthPolicy: TCertificateStrengthPolicy;
      const AAdvertised: TArray<UInt16>; ADeadlineMs: Cardinal;
      const AFallback: TCertificateVerdictResolver);
  end;

  /// <summary>
  /// The Windows client-certificate verifier source: builds a client delegate over the client-CA
  /// anchors in the context (the exclusive trust root), with the connection's posture and clock.
  /// AFetch fixes cache-only vs live inline behaviour (Live defers an indeterminate revocation to
  /// the async park).
  /// </summary>
  TWindowsClientVerifierSource = class sealed(TInterfacedObject,
    IClientCertificateVerifierSource)
  strict private
    FFetch: TSystemTrustFetch;
  public
    constructor Create(AFetch: TSystemTrustFetch);
    function CreateClientVerifier(const AContext: TClientTrustContext)
      : IClientCertificateVerifier;
  end;

{$ENDIF}

implementation

{$IFDEF TLSLIB_MSWINDOWS}

resourcestring
  SLiveNeedsAsyncVerdict =
    'OS-native live revocation needs the async certificate verdict enabled (it defers the live ' +
    'check to the out-of-band park); call WithAsyncCertificateVerdict, or use cache-only trust';

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

  // the configured client-CA anchors are the only trusted roots for the client-auth chain engine
  // (RFC-agnostic H3 fix); the CA flag lets a non-self-signed anchor still root a path
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
    /// <summary>Maps a non-zero chain-policy dwError to the fatal alert, posture-aware: an
    /// indeterminate revocation outcome is accepted (True) under a non-Hard posture, a definitive
    /// Revoked and every other error reject (False, AAlert set). Shared by both role delegates.</summary>
    class function MapPolicyError(ADwError: DWORD; APosture: TRevocationPosture;
      out AAlert: TTlsAlertDescription): Boolean; static;
    /// <summary>The raw DER of the ROOT store (server-auth-capable roots only) minus the
    /// Disallowed store. Validation and de-duplication are the caller's responsibility.</summary>
    class function HarvestAnchors: TArray<TBytes>; static;
    /// <summary>Reads the DER of the end-entity simple chain the OS built (rgpChain[0]): element 0
    /// the leaf, the last element the anchor. False on any malformed field (no chain/element, nil
    /// or empty encoded cert) so the caller fails closed.</summary>
    class function ReadChainPath(AChainCtx: Pointer;
      out APath: TArray<TBytes>): Boolean; static;
    /// <summary>Runs the chain-algorithm/key-strength policy over the OS-built path with the OS
    /// anchor (the last element) exempt, so the leaf and every intermediate are checked. A nil
    /// provider or empty path is internal_error.</summary>
    class function ApplyStrengthPolicy(const AOsPath: TArray<TBytes>;
      const AProvider: ICryptoProvider;
      const APolicy: TCertificateStrengthPolicy; const AAdvertised: TArray<UInt16>;
      out AAlert: TTlsAlertDescription): Boolean; static;
    /// <summary>Runs the OS SSL-server chain evaluation with URL retrieval cache-only,
    /// consuming the stapled OCSP response as cached revocation data, at the validation time
    /// AClock supplies (nil = system time). APosture governs an indeterminate revocation
    /// outcome (accept under Soft, reject under Hard; a definitive Revoked always rejects).
    /// Returns True when trusted; on rejection False with AAlert set to the matching fatal
    /// alert.</summary>
    class function EvaluateChain(const AChain: TArray<TBytes>;
      const AHostName: string; const AOcspStaple: TBytes;
      APosture: TRevocationPosture; AFetch: TSystemTrustFetch;
      const AClock: ITlsClock;
      const AProvider: ICryptoProvider;
      const AStrengthPolicy: TCertificateStrengthPolicy;
      const AAdvertised: TArray<UInt16>;
      out AValidatedChain: TArray<TBytes>;
      out AAlert: TTlsAlertDescription): Boolean; static;
    /// <summary>Runs the OS SSL-server chain evaluation LIVE (network fetch enabled, revocation
    /// only - AIA disabled), at APosture, bounded by ADeadlineMs, over the OS-built path with the
    /// strength policy applied. Returns the tri-state revocation outcome; on a definitive
    /// non-revocation trust failure returns False with AAlert set. For the off-engine-thread park
    /// resolver only - never inline (it blocks on a socket).</summary>
    class function EvaluateServerLive(const AChain: TArray<TBytes>;
      const AHostName: string; const AStaple: TBytes; ADeadlineMs: Cardinal;
      const AClock: ITlsClock; const AProvider: ICryptoProvider;
      const AStrengthPolicy: TCertificateStrengthPolicy;
      const AAdvertised: TArray<UInt16>; out AOutcome: TLiveRevocationOutcome;
      out AAlert: TTlsAlertDescription): Boolean; static;
    /// <summary>Runs the OS chain evaluation for a peer CLIENT certificate against an
    /// exclusive-root engine built over AAnchors alone (never the OS/public roots), with the
    /// clientAuth EKU and the AUTHTYPE_CLIENT SSL policy. Same posture and clock handling as the
    /// server path (a client certificate is never stapled). AFetch fixes the inline behaviour:
    /// CacheOnly (no socket) or Live, where a Hard revocation-unknown is deferred (effective-Soft)
    /// so the handshake parks and the live resolver decides. Returns False with internal_error when
    /// the exclusive-engine entry point is unavailable.</summary>
    class function EvaluateClientChain(const AChain, AAnchors: TArray<TBytes>;
      APosture: TRevocationPosture; AFetch: TSystemTrustFetch; const AClock: ITlsClock;
      const AProvider: ICryptoProvider;
      const AStrengthPolicy: TCertificateStrengthPolicy;
      const AAdvertised: TArray<UInt16>;
      out AValidatedChain: TArray<TBytes>;
      out AAlert: TTlsAlertDescription): Boolean; static;
    /// <summary>Runs the CLIENT-certificate chain evaluation LIVE (network fetch enabled, revocation
    /// only - AIA disabled) against the exclusive-root engine over AAnchors, bounded by ADeadlineMs,
    /// over the OS-built path with the strength policy applied. Returns the tri-state revocation
    /// outcome; on a definitive non-revocation trust failure returns False with AAlert set. For the
    /// off-engine-thread park resolver only - never inline (it blocks on a socket).</summary>
    class function EvaluateClientLive(const AChain, AAnchors: TArray<TBytes>;
      ADeadlineMs: Cardinal; const AClock: ITlsClock; const AProvider: ICryptoProvider;
      const AStrengthPolicy: TCertificateStrengthPolicy;
      const AAdvertised: TArray<UInt16>; out AOutcome: TLiveRevocationOutcome;
      out AAlert: TTlsAlertDescription): Boolean; static;
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

class function TWindowsTrustApi.ApplyStrengthPolicy(const AOsPath: TArray<TBytes>;
  const AProvider: ICryptoProvider; const APolicy: TCertificateStrengthPolicy;
  const AAdvertised: TArray<UInt16>; out AAlert: TTlsAlertDescription): Boolean;
begin
  Result := False;
  if (AProvider = nil) or (Length(AOsPath) = 0) then
  begin
    AAlert := TTlsAlertDescription.InternalError;
    Exit;
  end;
  // exempt the OS anchor (last path element); leaf and intermediates are checked
  Result := TChainAlgorithmPolicy.Check(AProvider.Certificates, AOsPath,
    TArray<TBytes>.Create(AOsPath[High(AOsPath)]), APolicy, AAdvertised, AAlert);
end;

class function TWindowsTrustApi.EvaluateChain(const AChain: TArray<TBytes>;
  const AHostName: string; const AOcspStaple: TBytes;
  APosture: TRevocationPosture; AFetch: TSystemTrustFetch;
  const AClock: ITlsClock;
  const AProvider: ICryptoProvider;
  const AStrengthPolicy: TCertificateStrengthPolicy;
  const AAdvertised: TArray<UInt16>;
  out AValidatedChain: TArray<TBytes>;
  out AAlert: TTlsAlertDescription): Boolean;
var
  LLeaf: PCERT_CONTEXT;
  LStore: HCERTSTORE;
  LChain: Pointer;
  LUsageArr: array [0 .. 0] of PAnsiChar;
  LChainPara: CERT_CHAIN_PARA;
  LPolicyPara: CERT_CHAIN_POLICY_PARA;
  LSslPara: SSL_EXTRA_CERT_CHAIN_POLICY_PARA;
  LStatus: CERT_CHAIN_POLICY_STATUS;
  LServerName: UnicodeString;
  LStapleBlob: CRYPT_DATA_BLOB;
  LFileTime: FILETIME;
  LTimePtr: Pointer;
  LFlags: DWORD;
  LI: Integer;
  LOsPath: TArray<TBytes>;
  LEffectivePosture: TRevocationPosture;
begin
  Result := False;
  AValidatedChain := nil;
  AAlert := TTlsAlertDescription.BadCertificate;

  if Length(AChain) = 0 then
    Exit;

  if not FReady then
  begin
    AAlert := TTlsAlertDescription.InternalError;
    Exit;
  end;

  // live mode defers an indeterminate revocation to the async park: run the inline check as
  // effective-Soft (accept indeterminate; a definitive cached Revoked and every trust failure
  // still reject) so the handshake reaches the park, where the live re-check applies the real
  // posture. Configured Hard cache-only keeps its fail-closed inline behaviour.
  LEffectivePosture := APosture;
  if (AFetch = TSystemTrustFetch.Live) and (APosture = TRevocationPosture.Hard) then
    LEffectivePosture := TRevocationPosture.Soft;

  LLeaf := FCertCreateCertificateContext(MY_ENCODING_TYPE, PByte(AChain[0]),
    Length(AChain[0]));
  if LLeaf = nil then
    Exit;

  LStore := FCertOpenStore(CERT_STORE_PROV_MEMORY, MY_ENCODING_TYPE, nil, 0, nil);
  LChain := nil;
  try
    // the staple, attached to the leaf, is read as cached revocation data (no responder fetch)
    if (Length(AOcspStaple) > 0) and
      System.Assigned(FCertSetCertificateContextProperty) then
    begin
      LStapleBlob.cbData := Length(AOcspStaple);
      LStapleBlob.pbData := PByte(AOcspStaple);
      FCertSetCertificateContextProperty(LLeaf, CERT_OCSP_RESPONSE_PROP_ID, 0,
        @LStapleBlob);
    end;

    // Feed the presented intermediates so the engine can build the path without
    // any network fetch.
    if LStore <> nil then
    begin
      for LI := 1 to Length(AChain) - 1 do
      begin
        if Length(AChain[LI]) > 0 then
          FCertAddEncodedCertificateToStore(LStore, MY_ENCODING_TYPE,
            PByte(AChain[LI]), Length(AChain[LI]), CERT_STORE_ADD_ALWAYS, nil);
      end;
    end;

    LUsageArr[0] := SZOID_PKIX_KP_SERVER_AUTH;
    FillChar(LChainPara, SizeOf(LChainPara), 0);
    LChainPara.cbSize := SizeOf(LChainPara);
    LChainPara.RequestedUsage.dwType := USAGE_MATCH_TYPE_AND;
    LChainPara.RequestedUsage.Usage.cUsageIdentifier := 1;
    LChainPara.RequestedUsage.Usage.rgpszUsageIdentifier := @LUsageArr[0];

    // Off skips revocation; otherwise it is checked cache-only (staple/cached data, no socket)
    LFlags := CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL;
    if LEffectivePosture <> TRevocationPosture.Off then
      LFlags := LFlags or CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT or
        CERT_CHAIN_REVOCATION_ACCUMULATIVE_TIMEOUT;

    // the injected clock pins the validation time; nil defers to system time
    LTimePtr := nil;
    if AClock <> nil then
    begin
      LFileTime := UnixMillisToFileTime(AClock.NowUnixMillis);
      LTimePtr := @LFileTime;
    end;

    if not FCertGetCertificateChain(nil, LLeaf, LTimePtr, LStore, @LChainPara,
      LFlags, nil, LChain) then
    begin
      AAlert := TTlsAlertDescription.UnknownCa;
      Exit;
    end;

    FillChar(LSslPara, SizeOf(LSslPara), 0);
    LSslPara.cbSize := SizeOf(LSslPara);
    LSslPara.dwAuthType := AUTHTYPE_SERVER;
    LSslPara.fdwChecks := 0;
    if AHostName <> '' then
    begin
      LServerName := UnicodeString(AHostName);
      LSslPara.pwszServerName := PWideChar(LServerName);
    end
    else
      LSslPara.pwszServerName := nil;

    FillChar(LPolicyPara, SizeOf(LPolicyPara), 0);
    LPolicyPara.cbSize := SizeOf(LPolicyPara);
    // effective-Soft ignores revocation-unknown at the policy layer, so a missing/offline
    // responder soft-fails without masking a real error (e.g. a name mismatch); configured Hard
    // keeps dwFlags 0 so an unknown revocation still rejects
    if LEffectivePosture = TRevocationPosture.Soft then
      LPolicyPara.dwFlags := CERT_CHAIN_POLICY_IGNORE_ALL_REV_UNKNOWN_FLAGS
    else
      LPolicyPara.dwFlags := 0;
    LPolicyPara.pvExtraPolicyPara := @LSslPara;

    FillChar(LStatus, SizeOf(LStatus), 0);
    LStatus.cbSize := SizeOf(LStatus);

    if not FCertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_SSL, LChain,
      LPolicyPara, LStatus) then
    begin
      AAlert := TTlsAlertDescription.BadCertificate;
      Exit;
    end;

    if LStatus.dwError <> 0 then
    begin
      Result := MapPolicyError(LStatus.dwError, LEffectivePosture, AAlert);
      Exit;
    end;
    // trusted: policy over the OS-built path
    if not ReadChainPath(LChain, LOsPath) then
    begin
      AAlert := TTlsAlertDescription.InternalError;
      Exit;
    end;
    Result := ApplyStrengthPolicy(LOsPath, AProvider, AStrengthPolicy,
      AAdvertised, AAlert);
    // the OS-built path (leaf-first, ending at the anchor) is the validated chain a key-pin
    // over the delegate must match against
    if Result then
      AValidatedChain := LOsPath;
  finally
    if LChain <> nil then
      FCertFreeCertificateChain(LChain);
    if LStore <> nil then
      FCertCloseStore(LStore, 0);
    FCertFreeCertificateContext(LLeaf);
  end;
end;

class function TWindowsTrustApi.EvaluateServerLive(const AChain: TArray<TBytes>;
  const AHostName: string; const AStaple: TBytes; ADeadlineMs: Cardinal;
  const AClock: ITlsClock; const AProvider: ICryptoProvider;
  const AStrengthPolicy: TCertificateStrengthPolicy;
  const AAdvertised: TArray<UInt16>; out AOutcome: TLiveRevocationOutcome;
  out AAlert: TTlsAlertDescription): Boolean;
var
  LLeaf: PCERT_CONTEXT;
  LStore: HCERTSTORE;
  LChain: Pointer;
  LUsageArr: array [0 .. 0] of PAnsiChar;
  LChainPara: CERT_CHAIN_PARA_EX;
  LPolicyPara: CERT_CHAIN_POLICY_PARA;
  LSslPara: SSL_EXTRA_CERT_CHAIN_POLICY_PARA;
  LStatus: CERT_CHAIN_POLICY_STATUS;
  LServerName: UnicodeString;
  LStapleBlob: CRYPT_DATA_BLOB;
  LFileTime: FILETIME;
  LTimePtr: Pointer;
  LFlags: DWORD;
  LI: Integer;
  LOsPath: TArray<TBytes>;
begin
  Result := False;
  AOutcome := TLiveRevocationOutcome.Indeterminate;
  AAlert := TTlsAlertDescription.BadCertificate;

  if Length(AChain) = 0 then
    Exit;
  if not FReady then
  begin
    AAlert := TTlsAlertDescription.InternalError;
    Exit;
  end;

  LLeaf := FCertCreateCertificateContext(MY_ENCODING_TYPE, PByte(AChain[0]),
    Length(AChain[0]));
  if LLeaf = nil then
    Exit;

  LStore := FCertOpenStore(CERT_STORE_PROV_MEMORY, MY_ENCODING_TYPE, nil, 0, nil);
  LChain := nil;
  try
    // prefer a current stapled response: attached to the leaf it answers the leaf's revocation
    // from the handshake, so the OS only reaches the network for what the staple did not cover
    if (Length(AStaple) > 0) and System.Assigned(FCertSetCertificateContextProperty) then
    begin
      LStapleBlob.cbData := Length(AStaple);
      LStapleBlob.pbData := PByte(AStaple);
      FCertSetCertificateContextProperty(LLeaf, CERT_OCSP_RESPONSE_PROP_ID, 0, @LStapleBlob);
    end;
    // seed the presented intermediates; the network is used for revocation only (AIA disabled)
    if LStore <> nil then
      for LI := 1 to Length(AChain) - 1 do
        if Length(AChain[LI]) > 0 then
          FCertAddEncodedCertificateToStore(LStore, MY_ENCODING_TYPE,
            PByte(AChain[LI]), Length(AChain[LI]), CERT_STORE_ADD_ALWAYS, nil);

    LUsageArr[0] := SZOID_PKIX_KP_SERVER_AUTH;
    FillChar(LChainPara, SizeOf(LChainPara), 0);
    LChainPara.cbSize := SizeOf(LChainPara);
    LChainPara.RequestedUsage.dwType := USAGE_MATCH_TYPE_AND;
    LChainPara.RequestedUsage.Usage.cUsageIdentifier := 1;
    LChainPara.RequestedUsage.Usage.rgpszUsageIdentifier := @LUsageArr[0];
    LChainPara.dwUrlRetrievalTimeout := ADeadlineMs;

    // live: whole-chain revocation over the network, AIA disabled so the built path matches the
    // presented one; the accumulative timeout bounds the whole build to the deadline
    LFlags := CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT or
      CERT_CHAIN_REVOCATION_ACCUMULATIVE_TIMEOUT or CERT_CHAIN_DISABLE_AIA;

    LTimePtr := nil;
    if AClock <> nil then
    begin
      LFileTime := UnixMillisToFileTime(AClock.NowUnixMillis);
      LTimePtr := @LFileTime;
    end;

    if not FCertGetCertificateChain(nil, LLeaf, LTimePtr, LStore, @LChainPara,
      LFlags, nil, LChain) then
    begin
      AAlert := TTlsAlertDescription.UnknownCa;
      Exit;
    end;

    FillChar(LSslPara, SizeOf(LSslPara), 0);
    LSslPara.cbSize := SizeOf(LSslPara);
    LSslPara.dwAuthType := AUTHTYPE_SERVER;
    LSslPara.fdwChecks := 0;
    if AHostName <> '' then
    begin
      LServerName := UnicodeString(AHostName);
      LSslPara.pwszServerName := PWideChar(LServerName);
    end
    else
      LSslPara.pwszServerName := nil;

    // query the Hard way (dwFlags 0): a revocation-unknown outcome surfaces so it is classified
    // as Indeterminate, not silently accepted - the resolver then applies posture and fallback
    FillChar(LPolicyPara, SizeOf(LPolicyPara), 0);
    LPolicyPara.cbSize := SizeOf(LPolicyPara);
    LPolicyPara.dwFlags := 0;
    LPolicyPara.pvExtraPolicyPara := @LSslPara;

    FillChar(LStatus, SizeOf(LStatus), 0);
    LStatus.cbSize := SizeOf(LStatus);

    if not FCertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_SSL, LChain,
      LPolicyPara, LStatus) then
    begin
      AAlert := TTlsAlertDescription.BadCertificate;
      Exit;
    end;

    if LStatus.dwError = 0 then
    begin
      // trusted and revocation was actually checked: run the strength policy over the OS path
      if not ReadChainPath(LChain, LOsPath) then
      begin
        AAlert := TTlsAlertDescription.InternalError;
        Exit;
      end;
      if not ApplyStrengthPolicy(LOsPath, AProvider, AStrengthPolicy, AAdvertised, AAlert) then
        Exit;
      AOutcome := TLiveRevocationOutcome.Good;
      Result := True;
    end
    else if (LStatus.dwError = CERT_E_REVOKED) or
      (LStatus.dwError = CERT_E_REVOKED_ALT) then
    begin
      AOutcome := TLiveRevocationOutcome.Revoked;
      Result := True;
    end
    else if (LStatus.dwError = CRYPT_E_NO_REVOCATION_CHECK) or
      (LStatus.dwError = CRYPT_E_REVOCATION_OFFLINE) then
    begin
      // revocation could not be reached or decided: indeterminate. The inline pass already rejected
      // every definitive trust failure before the park (a name mismatch is rejected inline via the
      // IGNORE_ALL_REV_UNKNOWN flags, not deferred), so the policy dwError is authoritative for the
      // revocation question and the benign chain-status info bits do not gate it.
      AOutcome := TLiveRevocationOutcome.Indeterminate;
      Result := True;
    end
    else
      // a real trust failure the live re-evaluation surfaced: reject outright
      Result := MapPolicyError(LStatus.dwError, TRevocationPosture.Hard, AAlert);
  finally
    if LChain <> nil then
      FCertFreeCertificateChain(LChain);
    if LStore <> nil then
      FCertCloseStore(LStore, 0);
    FCertFreeCertificateContext(LLeaf);
  end;
end;

class function TWindowsTrustApi.MapPolicyError(ADwError: DWORD;
  APosture: TRevocationPosture; out AAlert: TTlsAlertDescription): Boolean;
begin
  Result := False;
  case ADwError of
    CERT_E_EXPIRED, CERT_E_VALIDITYPERIODNESTING:
      AAlert := TTlsAlertDescription.CertificateExpired;
    CERT_E_UNTRUSTEDROOT, CERT_E_UNTRUSTEDCA, CERT_E_CHAINING,
      TRUST_E_CERT_SIGNATURE:
      AAlert := TTlsAlertDescription.UnknownCa;
    CERT_E_REVOKED, CERT_E_REVOKED_ALT:
      // a definitive Revoked rejects under every posture
      AAlert := TTlsAlertDescription.CertificateRevoked;
    CRYPT_E_NO_REVOCATION_CHECK, CRYPT_E_REVOCATION_OFFLINE:
      // revocation was indeterminate: Soft accepts, Hard rejects
      if APosture <> TRevocationPosture.Hard then
        Result := True
      else
        AAlert := TTlsAlertDescription.BadCertificateStatusResponse;
    CERT_E_WRONG_USAGE:
      AAlert := TTlsAlertDescription.UnsupportedCertificate;
  else
    // CERT_E_CN_NO_MATCH and everything else map to bad_certificate.
    AAlert := TTlsAlertDescription.BadCertificate;
  end;
end;

class function TWindowsTrustApi.EvaluateClientChain(const AChain,
  AAnchors: TArray<TBytes>; APosture: TRevocationPosture; AFetch: TSystemTrustFetch;
  const AClock: ITlsClock;
  const AProvider: ICryptoProvider;
  const AStrengthPolicy: TCertificateStrengthPolicy;
  const AAdvertised: TArray<UInt16>;
  out AValidatedChain: TArray<TBytes>;
  out AAlert: TTlsAlertDescription): Boolean;
var
  LLeaf: PCERT_CONTEXT;
  LRootStore, LInterStore: HCERTSTORE;
  LEngine, LChain: Pointer;
  LUsageArr: array [0 .. 0] of PAnsiChar;
  LChainPara: CERT_CHAIN_PARA;
  LEngineConfig: CERT_CHAIN_ENGINE_CONFIG;
  LPolicyPara: CERT_CHAIN_POLICY_PARA;
  LSslPara: SSL_EXTRA_CERT_CHAIN_POLICY_PARA;
  LStatus: CERT_CHAIN_POLICY_STATUS;
  LFileTime: FILETIME;
  LTimePtr: Pointer;
  LFlags: DWORD;
  LI: Integer;
  LOsPath: TArray<TBytes>;
  LEffectivePosture: TRevocationPosture;
begin
  Result := False;
  AValidatedChain := nil;
  AAlert := TTlsAlertDescription.BadCertificate;

  if Length(AChain) = 0 then
    Exit;

  // live mode defers an indeterminate revocation to the async park: run the inline check as
  // effective-Soft (accept indeterminate; a definitive cached Revoked and every trust failure
  // still reject) so the handshake reaches the park, where the live re-check applies the real
  // posture. Configured Hard cache-only keeps its fail-closed inline behaviour.
  LEffectivePosture := APosture;
  if (AFetch = TSystemTrustFetch.Live) and (APosture = TRevocationPosture.Hard) then
    LEffectivePosture := TRevocationPosture.Soft;

  // the exclusive-root engine is required for client-auth: without it a client could validate
  // against the OS/public roots, so fail closed rather than fall back to a weaker check
  if (not FReady) or (not System.Assigned(FCertCreateCertificateChainEngine)) or
    (not System.Assigned(FCertFreeCertificateChainEngine)) then
  begin
    AAlert := TTlsAlertDescription.InternalError;
    Exit;
  end;

  LLeaf := FCertCreateCertificateContext(MY_ENCODING_TYPE, PByte(AChain[0]),
    Length(AChain[0]));
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
    for LI := 0 to Length(AAnchors) - 1 do
      if Length(AAnchors[LI]) > 0 then
        FCertAddEncodedCertificateToStore(LRootStore, MY_ENCODING_TYPE,
          PByte(AAnchors[LI]), Length(AAnchors[LI]), CERT_STORE_ADD_ALWAYS, nil);
    // the presented intermediates seed path building (no network fetch)
    for LI := 1 to Length(AChain) - 1 do
      if Length(AChain[LI]) > 0 then
        FCertAddEncodedCertificateToStore(LInterStore, MY_ENCODING_TYPE,
          PByte(AChain[LI]), Length(AChain[LI]), CERT_STORE_ADD_ALWAYS, nil);

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
    FillChar(LChainPara, SizeOf(LChainPara), 0);
    LChainPara.cbSize := SizeOf(LChainPara);
    LChainPara.RequestedUsage.dwType := USAGE_MATCH_TYPE_AND;
    LChainPara.RequestedUsage.Usage.cUsageIdentifier := 1;
    LChainPara.RequestedUsage.Usage.rgpszUsageIdentifier := @LUsageArr[0];

    LFlags := CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL;
    if LEffectivePosture <> TRevocationPosture.Off then
      LFlags := LFlags or CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT or
        CERT_CHAIN_REVOCATION_ACCUMULATIVE_TIMEOUT;

    LTimePtr := nil;
    if AClock <> nil then
    begin
      LFileTime := UnixMillisToFileTime(AClock.NowUnixMillis);
      LTimePtr := @LFileTime;
    end;

    if not FCertGetCertificateChain(LEngine, LLeaf, LTimePtr, LInterStore, @LChainPara,
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
    // effective-Soft (configured Soft, or Live deferring a Hard to the park) ignores a
    // revocation-unknown at the policy layer; effective-Hard keeps dwFlags 0 so it rejects
    if LEffectivePosture = TRevocationPosture.Soft then
      LPolicyPara.dwFlags := CERT_CHAIN_POLICY_IGNORE_ALL_REV_UNKNOWN_FLAGS
    else
      LPolicyPara.dwFlags := 0;
    LPolicyPara.pvExtraPolicyPara := @LSslPara;

    FillChar(LStatus, SizeOf(LStatus), 0);
    LStatus.cbSize := SizeOf(LStatus);

    if not FCertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_SSL, LChain,
      LPolicyPara, LStatus) then
    begin
      AAlert := TTlsAlertDescription.BadCertificate;
      Exit;
    end;

    if LStatus.dwError <> 0 then
    begin
      Result := MapPolicyError(LStatus.dwError, LEffectivePosture, AAlert);
      Exit;
    end;
    // trusted: policy over the OS-built path
    if not ReadChainPath(LChain, LOsPath) then
    begin
      AAlert := TTlsAlertDescription.InternalError;
      Exit;
    end;
    Result := ApplyStrengthPolicy(LOsPath, AProvider, AStrengthPolicy,
      AAdvertised, AAlert);
    if Result then
      AValidatedChain := LOsPath;
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

class function TWindowsTrustApi.EvaluateClientLive(const AChain, AAnchors: TArray<TBytes>;
  ADeadlineMs: Cardinal; const AClock: ITlsClock; const AProvider: ICryptoProvider;
  const AStrengthPolicy: TCertificateStrengthPolicy;
  const AAdvertised: TArray<UInt16>; out AOutcome: TLiveRevocationOutcome;
  out AAlert: TTlsAlertDescription): Boolean;
var
  LLeaf: PCERT_CONTEXT;
  LRootStore, LInterStore: HCERTSTORE;
  LEngine, LChain: Pointer;
  LUsageArr: array [0 .. 0] of PAnsiChar;
  LChainPara: CERT_CHAIN_PARA_EX;
  LEngineConfig: CERT_CHAIN_ENGINE_CONFIG;
  LPolicyPara: CERT_CHAIN_POLICY_PARA;
  LSslPara: SSL_EXTRA_CERT_CHAIN_POLICY_PARA;
  LStatus: CERT_CHAIN_POLICY_STATUS;
  LFileTime: FILETIME;
  LTimePtr: Pointer;
  LFlags: DWORD;
  LI: Integer;
  LOsPath: TArray<TBytes>;
begin
  Result := False;
  AOutcome := TLiveRevocationOutcome.Indeterminate;
  AAlert := TTlsAlertDescription.BadCertificate;

  if Length(AChain) = 0 then
    Exit;
  // the exclusive-root engine is required for client-auth: the live re-check trusts the configured
  // client-CA anchors alone, never the OS/public roots
  if (not FReady) or (not System.Assigned(FCertCreateCertificateChainEngine)) or
    (not System.Assigned(FCertFreeCertificateChainEngine)) then
  begin
    AAlert := TTlsAlertDescription.InternalError;
    Exit;
  end;

  LLeaf := FCertCreateCertificateContext(MY_ENCODING_TYPE, PByte(AChain[0]),
    Length(AChain[0]));
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
    for LI := 0 to Length(AAnchors) - 1 do
      if Length(AAnchors[LI]) > 0 then
        FCertAddEncodedCertificateToStore(LRootStore, MY_ENCODING_TYPE,
          PByte(AAnchors[LI]), Length(AAnchors[LI]), CERT_STORE_ADD_ALWAYS, nil);
    // the presented intermediates seed path building; the network is used for revocation only
    for LI := 1 to Length(AChain) - 1 do
      if Length(AChain[LI]) > 0 then
        FCertAddEncodedCertificateToStore(LInterStore, MY_ENCODING_TYPE,
          PByte(AChain[LI]), Length(AChain[LI]), CERT_STORE_ADD_ALWAYS, nil);

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
    FillChar(LChainPara, SizeOf(LChainPara), 0);
    LChainPara.cbSize := SizeOf(LChainPara);
    LChainPara.RequestedUsage.dwType := USAGE_MATCH_TYPE_AND;
    LChainPara.RequestedUsage.Usage.cUsageIdentifier := 1;
    LChainPara.RequestedUsage.Usage.rgpszUsageIdentifier := @LUsageArr[0];
    LChainPara.dwUrlRetrievalTimeout := ADeadlineMs;

    // live: whole-chain revocation over the network, AIA disabled so the built path matches the
    // anchored/presented one; the accumulative timeout bounds the build to the deadline
    LFlags := CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT or
      CERT_CHAIN_REVOCATION_ACCUMULATIVE_TIMEOUT or CERT_CHAIN_DISABLE_AIA;

    LTimePtr := nil;
    if AClock <> nil then
    begin
      LFileTime := UnixMillisToFileTime(AClock.NowUnixMillis);
      LTimePtr := @LFileTime;
    end;

    if not FCertGetCertificateChain(LEngine, LLeaf, LTimePtr, LInterStore, @LChainPara,
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

    // query the Hard way (dwFlags 0): a revocation-unknown outcome surfaces so it is classified
    // Indeterminate, not silently accepted - the resolver then applies posture and fallback
    FillChar(LPolicyPara, SizeOf(LPolicyPara), 0);
    LPolicyPara.cbSize := SizeOf(LPolicyPara);
    LPolicyPara.dwFlags := 0;
    LPolicyPara.pvExtraPolicyPara := @LSslPara;

    FillChar(LStatus, SizeOf(LStatus), 0);
    LStatus.cbSize := SizeOf(LStatus);

    if not FCertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_SSL, LChain,
      LPolicyPara, LStatus) then
    begin
      AAlert := TTlsAlertDescription.BadCertificate;
      Exit;
    end;

    if LStatus.dwError = 0 then
    begin
      // trusted and revocation was actually checked: run the strength policy over the OS path
      if not ReadChainPath(LChain, LOsPath) then
      begin
        AAlert := TTlsAlertDescription.InternalError;
        Exit;
      end;
      if not ApplyStrengthPolicy(LOsPath, AProvider, AStrengthPolicy, AAdvertised, AAlert) then
        Exit;
      AOutcome := TLiveRevocationOutcome.Good;
      Result := True;
    end
    else if (LStatus.dwError = CERT_E_REVOKED) or
      (LStatus.dwError = CERT_E_REVOKED_ALT) then
    begin
      AOutcome := TLiveRevocationOutcome.Revoked;
      Result := True;
    end
    else if (LStatus.dwError = CRYPT_E_NO_REVOCATION_CHECK) or
      (LStatus.dwError = CRYPT_E_REVOCATION_OFFLINE) then
    begin
      // revocation could not be reached or decided: indeterminate. The inline pass already rejected
      // every definitive trust failure before the park (a name mismatch cannot reach here - it is
      // rejected inline), so the policy dwError is authoritative for the revocation question and the
      // benign chain-status info bits (no-name-constraint, invalid-extension) do not gate it.
      AOutcome := TLiveRevocationOutcome.Indeterminate;
      Result := True;
    end
    else
      // a real trust failure the live re-evaluation surfaced: reject outright
      Result := MapPolicyError(LStatus.dwError, TRevocationPosture.Hard, AAlert);
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

{ TWindowsDelegateVerifier }

constructor TWindowsDelegateVerifier.Create(const AProvider: ICryptoProvider;
  APosture: TRevocationPosture; AFetch: TSystemTrustFetch; const AClock: ITlsClock;
  const AStrengthPolicy: TCertificateStrengthPolicy;
  const AAdvertised: TArray<UInt16>);
begin
  inherited Create;
  FProvider := AProvider;
  FPosture := APosture;
  FFetch := AFetch;
  FClock := AClock;
  FStrengthPolicy := AStrengthPolicy;
  FAdvertised := AAdvertised;
end;

function TWindowsDelegateVerifier.VerifyServerCertificate(const AChain: TArray<TBytes>;
  const AServerName: TServerName; const AOcspStaple: TBytes;
  out AValidatedChain: TArray<TBytes>;
  out AAlert: TTlsAlertDescription): Boolean;
begin
  Result := TWindowsTrustApi.EvaluateChain(AChain, AServerName.ToString,
    AOcspStaple, FPosture, FFetch, FClock, FProvider, FStrengthPolicy, FAdvertised,
    AValidatedChain, AAlert);
end;

{ TWindowsLiveRevocationResolver }

constructor TWindowsLiveRevocationResolver.Create(const AProvider: ICryptoProvider;
  APosture: TRevocationPosture; const AClock: ITlsClock;
  const AStrengthPolicy: TCertificateStrengthPolicy;
  const AAdvertised: TArray<UInt16>; ADeadlineMs: Cardinal;
  const AFallback: TCertificateVerdictResolver);
begin
  inherited Create(APosture, AFallback);
  FProvider := AProvider;
  FClock := AClock;
  FStrengthPolicy := AStrengthPolicy;
  FAdvertised := AAdvertised;
  FDeadlineMs := ADeadlineMs;
end;

function TWindowsLiveRevocationResolver.EvaluateLive(const AChain: TArray<TBytes>;
  const AHostName: string; const AStaple: TBytes;
  out AOutcome: TLiveRevocationOutcome;
  out ARejectAlert: TTlsAlertDescription): Boolean;
begin
  Result := TWindowsTrustApi.EvaluateServerLive(AChain, AHostName, AStaple,
    FDeadlineMs, FClock, FProvider, FStrengthPolicy, FAdvertised, AOutcome, ARejectAlert);
end;

{ TWindowsClientLiveRevocationResolver }

constructor TWindowsClientLiveRevocationResolver.Create(const AProvider: ICryptoProvider;
  const AAnchors: TArray<TBytes>; APosture: TRevocationPosture; const AClock: ITlsClock;
  const AStrengthPolicy: TCertificateStrengthPolicy;
  const AAdvertised: TArray<UInt16>; ADeadlineMs: Cardinal;
  const AFallback: TCertificateVerdictResolver);
begin
  inherited Create(APosture, AFallback);
  FProvider := AProvider;
  FAnchors := AAnchors;
  FClock := AClock;
  FStrengthPolicy := AStrengthPolicy;
  FAdvertised := AAdvertised;
  FDeadlineMs := ADeadlineMs;
end;

function TWindowsClientLiveRevocationResolver.EvaluateLive(const AChain: TArray<TBytes>;
  const AHostName: string; const AStaple: TBytes;
  out AOutcome: TLiveRevocationOutcome;
  out ARejectAlert: TTlsAlertDescription): Boolean;
begin
  // a client certificate carries no host identity and is never stapled: AHostName/AStaple unused
  Result := TWindowsTrustApi.EvaluateClientLive(AChain, FAnchors, FDeadlineMs, FClock,
    FProvider, FStrengthPolicy, FAdvertised, AOutcome, ARejectAlert);
end;

{ TWindowsServerVerifierSource }

constructor TWindowsServerVerifierSource.Create(AFetch: TSystemTrustFetch);
begin
  inherited Create;
  FFetch := AFetch;
end;

function TWindowsServerVerifierSource.CreateServerVerifier(
  const AContext: TServerTrustContext): IServerCertificateVerifier;
begin
  // live inline defers an indeterminate revocation to the async park, so a park must be guaranteed;
  // without it the delegate would silently run cache-only Soft. Fail at engine creation (before IO).
  if (FFetch = TSystemTrustFetch.Live) and (not AContext.AsyncVerdictEnabled) then
    raise ESystemTrustUnsupportedTlsLibException.CreateRes(@SLiveNeedsAsyncVerdict);
  Result := TWindowsDelegateVerifier.Create(AContext.Provider,
    AContext.RevocationPosture, FFetch, AContext.Clock, AContext.StrengthPolicy,
    AContext.AdvertisedSignatureSchemes) as IServerCertificateVerifier;
end;

{ TWindowsClientDelegateVerifier }

constructor TWindowsClientDelegateVerifier.Create(const AProvider: ICryptoProvider;
  const AAnchors: TArray<TBytes>; APosture: TRevocationPosture;
  AFetch: TSystemTrustFetch; const AClock: ITlsClock;
  const AStrengthPolicy: TCertificateStrengthPolicy;
  const AAdvertised: TArray<UInt16>);
begin
  inherited Create;
  FProvider := AProvider;
  FAnchors := AAnchors;
  FPosture := APosture;
  FFetch := AFetch;
  FClock := AClock;
  FStrengthPolicy := AStrengthPolicy;
  FAdvertised := AAdvertised;
end;

function TWindowsClientDelegateVerifier.VerifyClientCertificate(
  const AChain: TArray<TBytes>; out AValidatedChain: TArray<TBytes>;
  out AAlert: TTlsAlertDescription): Boolean;
begin
  Result := TWindowsTrustApi.EvaluateClientChain(AChain, FAnchors, FPosture, FFetch,
    FClock, FProvider, FStrengthPolicy, FAdvertised, AValidatedChain, AAlert);
end;

{ TWindowsClientVerifierSource }

constructor TWindowsClientVerifierSource.Create(AFetch: TSystemTrustFetch);
begin
  inherited Create;
  FFetch := AFetch;
end;

function TWindowsClientVerifierSource.CreateClientVerifier(
  const AContext: TClientTrustContext): IClientCertificateVerifier;
var
  LAnchors: TArray<TBytes>;
begin
  // live inline defers an indeterminate revocation to the async park, so a park must be guaranteed;
  // without it the delegate would silently run cache-only Soft. Fail at engine creation (before IO).
  if (FFetch = TSystemTrustFetch.Live) and (not AContext.AsyncVerdictEnabled) then
    raise ESystemTrustUnsupportedTlsLibException.CreateRes(@SLiveNeedsAsyncVerdict);
  LAnchors := nil;
  if AContext.TrustStore <> nil then
    LAnchors := AContext.TrustStore.RootCertificates;
  Result := TWindowsClientDelegateVerifier.Create(AContext.Provider, LAnchors,
    AContext.RevocationPosture, FFetch, AContext.Clock, AContext.StrengthPolicy,
    AContext.AdvertisedSignatureSchemes) as IClientCertificateVerifier;
end;

initialization
  TWindowsTrustApi.ResolveDynamicImports;

finalization
  TWindowsTrustApi.ReleaseDynamicImports;

{$ENDIF}

end.
