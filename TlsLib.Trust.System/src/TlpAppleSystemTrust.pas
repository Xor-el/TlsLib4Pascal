{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpAppleSystemTrust;

{$I ..\..\TlsLib\src\Include\TlsLib.inc}

interface

uses
{$IF DEFINED(TLSLIB_MACOS) OR DEFINED(TLSLIB_IOS)}
{$IFDEF FPC}
{$LINKFRAMEWORK CoreFoundation}
{$LINKFRAMEWORK Security}
{$ENDIF}
  TlpPosixDynLib,
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
  TlpOSLiveRevocation,
{$IFEND}
  Generics.Collections,
  SysUtils,
  TlpTlsAlert;

type
  /// <summary>
  /// Maps Apple errSec OSStatus rejection codes to our TLS alert enum, so the
  /// delegate reports a granular alert instead of collapsing to unknown_ca.
  /// </summary>
  TAppleAlertMap = class sealed(TObject)
  public
    class function OsStatusToAlert(AStatus: Int32): TTlsAlertDescription; static;
  end;

{$IF DEFINED(TLSLIB_MACOS) OR DEFINED(TLSLIB_IOS)}

{$IFDEF TLSLIB_MACOS}
type
  /// <summary>
  /// Harvests trusted roots from the macOS keychain trust settings across the
  /// System, Admin and User domains, excluding any certificate whose trust
  /// setting result is Deny so OS distrust is honored. iOS has no equivalent
  /// enumeration API, so this store is macOS-only. Emits neutral DER.
  /// </summary>
  TAppleRootSource = class sealed(TSystemRootSource)
  strict protected
    function HarvestRoots: TArray<TBytes>; override;
    function SourceName: string; override;
  end;
{$ENDIF}

type
  /// <summary>
  /// Delegates server verification to Security.framework: SecTrust with an SSL server policy,
  /// network fetch disabled (cache-only). The revocation posture adds a revocation policy
  /// (Soft best-effort, Hard requires a positive response, Off none) and the injected clock
  /// pins the validation date; a stapled OCSP response is consumed as the cached response.
  /// Shared by macOS and iOS. Fail-closed.
  /// </summary>
  TAppleDelegateVerifier = class sealed(TInterfacedObject, IServerCertificateVerifier)
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
  /// The Apple OS-native live-revocation resolver: re-runs SecTrust with network fetch enabled
  /// (the revocation policy's network-disabled flag dropped, RequirePositiveResponse on) off the
  /// engine thread in the async park, and classifies the outcome for the shared base. Host-owned;
  /// assign ResolveVerdict to the seam. macOS and iOS.
  /// </summary>
  TAppleLiveRevocationResolver = class sealed(TOSLiveRevocationResolver)
  strict private
    FProvider: ICryptoProvider;
    FClock: ITlsClock;
    FStrengthPolicy: TCertificateStrengthPolicy;
    FAdvertised: TArray<UInt16>;
  strict protected
    function EvaluateLive(const AChain: TArray<TBytes>; const AHostName: string;
      const AStaple: TBytes; out AOutcome: TLiveRevocationOutcome;
      out ARejectAlert: TTlsAlertDescription): Boolean; override;
  public
    constructor Create(const AProvider: ICryptoProvider; APosture: TRevocationPosture;
      const AClock: ITlsClock; const AStrengthPolicy: TCertificateStrengthPolicy;
      const AAdvertised: TArray<UInt16>; const AFallback: TCertificateVerdictResolver);
  end;

  /// <summary>
  /// The Apple server-certificate verifier source: builds a delegate from the connection's
  /// trust context, so its revocation posture and clock are injected the same way the built-in
  /// verifier receives them. AFetch fixes cache-only vs live inline behaviour.
  /// </summary>
  TAppleServerVerifierSource = class sealed(TInterfacedObject,
    IServerCertificateVerifierSource)
  strict private
    FFetch: TSystemTrustFetch;
  public
    constructor Create(AFetch: TSystemTrustFetch);
    function CreateServerVerifier(const AContext: TServerTrustContext)
      : IServerCertificateVerifier;
  end;

  /// <summary>
  /// Verifies a peer CLIENT certificate (mTLS) via Security.framework, restricted to an
  /// exclusive trust root built from the configured client-CA anchors alone (anchors-only) -
  /// never the OS or public-web-PKI roots. Applies the client SSL policy; posture and clock are
  /// handled as the server delegate (a client certificate is not stapled). Fail-closed.
  /// </summary>
  TAppleClientDelegateVerifier = class sealed(TInterfacedObject,
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
  /// The Apple OS-native live-revocation resolver for a peer CLIENT certificate (mTLS): re-runs
  /// SecTrust anchors-only over the configured client-CA anchors with network fetch enabled and
  /// RequirePositiveResponse on, off the engine thread in the async park, and classifies the outcome
  /// for the shared base. Host-owned; assign ResolveVerdict to the seam. macOS and iOS.
  /// </summary>
  TAppleClientLiveRevocationResolver = class sealed(TOSLiveRevocationResolver)
  strict private
    FProvider: ICryptoProvider;
    FAnchors: TArray<TBytes>;
    FClock: ITlsClock;
    FStrengthPolicy: TCertificateStrengthPolicy;
    FAdvertised: TArray<UInt16>;
  strict protected
    function EvaluateLive(const AChain: TArray<TBytes>; const AHostName: string;
      const AStaple: TBytes; out AOutcome: TLiveRevocationOutcome;
      out ARejectAlert: TTlsAlertDescription): Boolean; override;
  public
    constructor Create(const AProvider: ICryptoProvider;
      const AAnchors: TArray<TBytes>; APosture: TRevocationPosture;
      const AClock: ITlsClock; const AStrengthPolicy: TCertificateStrengthPolicy;
      const AAdvertised: TArray<UInt16>; const AFallback: TCertificateVerdictResolver);
  end;

  /// <summary>
  /// The Apple client-certificate verifier source: builds a client delegate over the client-CA
  /// anchors in the context (the exclusive trust root), with the connection's posture and clock.
  /// AFetch fixes cache-only vs live inline behaviour (Live defers an indeterminate revocation to
  /// the async park).
  /// </summary>
  TAppleClientVerifierSource = class sealed(TInterfacedObject,
    IClientCertificateVerifierSource)
  strict private
    FFetch: TSystemTrustFetch;
  public
    constructor Create(AFetch: TSystemTrustFetch);
    function CreateClientVerifier(const AContext: TClientTrustContext)
      : IClientCertificateVerifier;
  end;

{$IFEND}

implementation

resourcestring
  SLiveNeedsAsyncVerdict =
    'OS-native live revocation needs the async certificate verdict enabled (it defers the live ' +
    'check to the out-of-band park); call WithAsyncCertificateVerdict, or use cache-only trust';

const
  // errSec OSStatus values (SecBase.h) whose meaning we surface as a granular alert.
  ErrSecCertificateExpired = -67818;
  ErrSecCertificateNotValidYet = -67819;
  ErrSecCertificateRevoked = -67820;
  // revocation could not be completed to a positive answer (Hard require-positive): indeterminate
  ErrSecIncompleteCertRevocationCheck = -67635;
  ErrSecInvalidExtendedKeyUsage = -67609;
  ErrSecHostNameMismatch = -67602;

{ TAppleAlertMap }

class function TAppleAlertMap.OsStatusToAlert(
  AStatus: Int32): TTlsAlertDescription;
begin
  case AStatus of
    ErrSecCertificateExpired, ErrSecCertificateNotValidYet:
      Result := TTlsAlertDescription.CertificateExpired;
    ErrSecCertificateRevoked:
      Result := TTlsAlertDescription.CertificateRevoked;
    ErrSecIncompleteCertRevocationCheck:
      // an indeterminate revocation under a Hard posture: report it as such
      Result := TTlsAlertDescription.BadCertificateStatusResponse;
    ErrSecInvalidExtendedKeyUsage:
      Result := TTlsAlertDescription.UnsupportedCertificate;
    ErrSecHostNameMismatch:
      Result := TTlsAlertDescription.BadCertificate;
  else
    // errSecNotTrusted (-67843), errSecTrustSettingDeny (-67654),
    // errSecCreateChainFailed (-25318) and any other status collapse to the safe
    // untrusted-root default - never soften a rejection into success.
    Result := TTlsAlertDescription.UnknownCa;
  end;
end;

{$IF DEFINED(TLSLIB_MACOS) OR DEFINED(TLSLIB_IOS)}

const
  KCFStringEncodingUTF8 = $08000100;

  ErrSecSuccess = 0;

  KSecTrustSettingsDomainUser = 0;
  KSecTrustSettingsDomainAdmin = 1;
  KSecTrustSettingsDomainSystem = 2;

  // SecTrustSettings.h SecTrustSettingsResult values
  KSecTrustSettingsResultInvalid = 0;
  KSecTrustSettingsResultTrustRoot = 1;
  KSecTrustSettingsResultTrustAsRoot = 2;
  KSecTrustSettingsResultDeny = 3;
  KSecTrustSettingsResultUnspecified = 4;
  KCFNumberSInt32Type = 3;

  // ClassifyEntry results: whether a trust-settings entry governs the SSL policy
  EntryScopeNot = 0;         // scoped to another app / hostname / non-SSL policy: ignore
  EntryScopeApplicable = 1;  // governs SSL (unscoped, or the Apple SSL policy)
  EntryScopeUnknown = 2;     // policy set but SSL scoping unresolved: honour a Deny, not a Trust

  // DomainVerdict results for one domain's settings
  DomainVerdictNoOpinion = 0;
  DomainVerdictTrust = 1;
  DomainVerdictDeny = 2;

  // SecPolicyCreateRevocation flags (SecPolicy.h): keep the check off the network, and under a
  // Hard posture demand a positive response rather than soft-failing on a missing one
  KSecRevocationOCSPMethod = 1;
  KSecRevocationCRLMethod = 2;
  KSecRevocationUseAnyAvailableMethod =
    KSecRevocationOCSPMethod or KSecRevocationCRLMethod;
  KSecRevocationRequirePositiveResponse = 8;
  KSecRevocationNetworkAccessDisabled = 16;

  // seconds between the Unix (1970) and CoreFoundation (2001) epochs: CFAbsoluteTime = unixSeconds - this
  CFAbsoluteTimeUnixEpochDelta = Double(978307200.0);

type
  CFIndex = NativeInt;
  CFArrayRef = Pointer;
  CFDataRef = Pointer;
  CFDateRef = Pointer;
  CFStringRef = Pointer;
  CFErrorRef = Pointer;
  SecCertificateRef = Pointer;
  SecPolicyRef = Pointer;
  SecTrustRef = Pointer;
  SecTrustSettingsDomain = Int32;
  OSStatus = Int32;

  // CoreFoundation
  TCFArrayGetCountFunc = function(AArray: CFArrayRef): CFIndex; cdecl;
  TCFArrayGetValueAtIndexFunc = function(AArray: CFArrayRef;
    AIndex: CFIndex): Pointer; cdecl;
  TCFArrayCreateFunc = function(AAllocator: Pointer; AValues: PPointer;
    ANumValues: CFIndex; ACallBacks: Pointer): CFArrayRef; cdecl;
  TCFReleaseProc = procedure(ACf: Pointer); cdecl;
  TCFDataGetLengthFunc = function(AData: CFDataRef): CFIndex; cdecl;
  TCFDataGetBytePtrFunc = function(AData: CFDataRef): PByte; cdecl;
  TCFDataCreateFunc = function(AAllocator: Pointer; ABytes: PByte;
    ALength: CFIndex): CFDataRef; cdecl;
  TCFStringCreateWithCStringFunc = function(AAlloc: Pointer; ACStr: PAnsiChar;
    AEncoding: LongWord): CFStringRef; cdecl;
  TCFDictionaryGetValueFunc = function(ADict: Pointer;
    AKey: Pointer): Pointer; cdecl;
  TCFNumberGetValueFunc = function(ANumber: Pointer; AType: CFIndex;
    AValuePtr: Pointer): Boolean; cdecl;
  TCFErrorGetCodeFunc = function(AError: CFErrorRef): CFIndex; cdecl;
  TCFErrorGetDomainFunc = function(AError: CFErrorRef): CFStringRef; cdecl;
  TCFEqualFunc = function(ACf1, ACf2: Pointer): Boolean; cdecl;

  // Security
  TSecCertificateCreateWithDataFunc = function(AAllocator: Pointer;
    AData: CFDataRef): SecCertificateRef; cdecl;
  TSecCertificateCopyDataFunc = function(ACertificate: SecCertificateRef)
    : CFDataRef; cdecl;
  TSecPolicyCreateSSLFunc = function(AServer: Boolean; AHostName: CFStringRef)
    : SecPolicyRef; cdecl;
  TSecTrustCreateWithCertificatesFunc = function(ACertificates: Pointer;
    APolicies: Pointer; var ATrust: SecTrustRef): OSStatus; cdecl;
  TSecTrustSetNetworkFetchAllowedFunc = function(ATrust: SecTrustRef;
    AAllowFetch: Boolean): OSStatus; cdecl;
  TSecTrustEvaluateWithErrorFunc = function(ATrust: SecTrustRef; AError: Pointer)
    : Boolean; cdecl;
  // CFOptionFlags is a 64-bit unsigned long here, so NativeUInt keeps the flags from truncating
  TSecPolicyCreateRevocationFunc = function(ARevocationFlags: NativeUInt)
    : SecPolicyRef; cdecl;
  TSecTrustSetVerifyDateFunc = function(ATrust: SecTrustRef;
    AVerifyDate: CFDateRef): OSStatus; cdecl;
  TSecTrustSetOCSPResponseFunc = function(ATrust: SecTrustRef;
    AResponseData: Pointer): OSStatus; cdecl;
  TSecTrustSetAnchorCertificatesFunc = function(ATrust: SecTrustRef;
    AAnchorCertificates: CFArrayRef): OSStatus; cdecl;
  TSecTrustSetAnchorCertificatesOnlyFunc = function(ATrust: SecTrustRef;
    AAnchorCertificatesOnly: Boolean): OSStatus; cdecl;
  TSecTrustCopyCertificateChainFunc = function(ATrust: SecTrustRef): CFArrayRef; cdecl;
  TSecTrustGetCertificateCountFunc = function(ATrust: SecTrustRef): CFIndex; cdecl;
  TSecTrustGetCertificateAtIndexFunc = function(ATrust: SecTrustRef;
    AIndex: CFIndex): SecCertificateRef; cdecl;
  // CFDateCreate takes a CFAbsoluteTime, which is a double
  TCFDateCreateFunc = function(AAllocator: Pointer; AAt: Double): CFDateRef; cdecl;
{$IFDEF TLSLIB_MACOS}
  TSecTrustSettingsCopyCertificatesFunc = function(ADomain: SecTrustSettingsDomain;
    var ACertArray: CFArrayRef): OSStatus; cdecl;
  TSecTrustSettingsCopyTrustSettingsFunc = function(ACertRef: SecCertificateRef;
    ADomain: SecTrustSettingsDomain; var ATrustSettings: CFArrayRef)
    : OSStatus; cdecl;
  // returns a CFDictionaryRef of a policy's properties (kSecPolicyOid identifies the policy)
  TSecPolicyCopyPropertiesFunc = function(APolicyRef: SecPolicyRef): Pointer; cdecl;
{$ENDIF}

  /// <summary>
  /// Resolves the CoreFoundation / Security entry points once via dlopen + dlsym.
  /// A missing (version-gated) symbol leaves the reader not ready, so callers fail
  /// closed instead of the process failing to link.
  /// </summary>
  TAppleTrustApi = class sealed
  strict private
  class var
    FReady: Boolean;
    FCFArrayGetCount: TCFArrayGetCountFunc;
    FCFArrayGetValueAtIndex: TCFArrayGetValueAtIndexFunc;
    FCFArrayCreate: TCFArrayCreateFunc;
    FCFRelease: TCFReleaseProc;
    FCFDataGetLength: TCFDataGetLengthFunc;
    FCFDataGetBytePtr: TCFDataGetBytePtrFunc;
    FCFDataCreate: TCFDataCreateFunc;
    FCFStringCreateWithCString: TCFStringCreateWithCStringFunc;
    FCFDictionaryGetValue: TCFDictionaryGetValueFunc;
    FCFNumberGetValue: TCFNumberGetValueFunc;
    FSecCertificateCreateWithData: TSecCertificateCreateWithDataFunc;
    FSecCertificateCopyData: TSecCertificateCopyDataFunc;
    FSecPolicyCreateSSL: TSecPolicyCreateSSLFunc;
    FSecTrustCreateWithCertificates: TSecTrustCreateWithCertificatesFunc;
    FSecTrustSetNetworkFetchAllowed: TSecTrustSetNetworkFetchAllowedFunc;
    FSecTrustEvaluateWithError: TSecTrustEvaluateWithErrorFunc;
    // hardening entry points: a missing one is handled per posture/path at the call site
    // (fail-closed where it would otherwise change the verdict), NOT by regressing FReady.
    FSecPolicyCreateRevocation: TSecPolicyCreateRevocationFunc;
    FSecTrustSetVerifyDate: TSecTrustSetVerifyDateFunc;
    FSecTrustSetOCSPResponse: TSecTrustSetOCSPResponseFunc;
    FSecTrustSetAnchorCertificates: TSecTrustSetAnchorCertificatesFunc;
    FSecTrustSetAnchorCertificatesOnly: TSecTrustSetAnchorCertificatesOnlyFunc;
    FSecTrustCopyCertificateChain: TSecTrustCopyCertificateChainFunc;
    FSecTrustGetCertificateCount: TSecTrustGetCertificateCountFunc;
    FSecTrustGetCertificateAtIndex: TSecTrustGetCertificateAtIndexFunc;
    FCFDateCreate: TCFDateCreateFunc;
    // the retaining-array callbacks: an array built with these owns its elements. Always
    // present, so unlike the hardening entry points above it gates FReady.
    FkCFTypeArrayCallBacks: Pointer;
    // best-effort CFError decode (shared macOS/iOS); their absence must NOT regress
    // FReady - the verifier still works, it just falls back to unknown_ca.
    FCFErrorGetCode: TCFErrorGetCodeFunc;
    FCFErrorGetDomain: TCFErrorGetDomainFunc;
    FCFEqual: TCFEqualFunc;
    FkCFErrorDomainOSStatus: CFStringRef;
    FCanDecodeError: Boolean;
{$IFDEF TLSLIB_MACOS}
    FSecTrustSettingsCopyCertificates: TSecTrustSettingsCopyCertificatesFunc;
    FSecTrustSettingsCopyTrustSettings: TSecTrustSettingsCopyTrustSettingsFunc;
    FSecPolicyCopyProperties: TSecPolicyCopyPropertiesFunc;
    // the trust-settings dictionary keys are CFSTR() macros in SecTrustSettings.h, NOT exported
    // symbols, so they are CREATED at load with CFStringCreateWithCString - a dlsym would return
    // nil. Trust-settings dictionaries use content (CFEqual) key comparison, so a created string
    // with the same characters matches the framework's literal.
    FkSecTrustSettingsResult: CFStringRef;
    FkSecTrustSettingsPolicy: CFStringRef;
    FkSecTrustSettingsApplication: CFStringRef;
    FkSecTrustSettingsPolicyString: CFStringRef;
    // kSecPolicyOid / kSecPolicyAppleSSL ARE exported data symbols (SecPolicy.h), resolved by dlsym
    FkSecPolicyOid: CFStringRef;
    FkSecPolicyAppleSSL: CFStringRef;
    // tiered readiness: tier 0 (enumerate) gates the harvest; tier 1 (read settings) falls back to
    // System-origin-only harvesting; tier 2 (SSL policy scoping) is best-effort and never gates
    FHarvestReady: Boolean;
    FSettingsReady: Boolean;
    FSslScopeReady: Boolean;
{$ENDIF}
    /// <summary>The DER of one certificate via SecCertificateCopyData. Empty on any failure.
    /// Shared macOS/iOS (harvest on macOS, the validated-path read on both).</summary>
    class function CopyCertificateDer(ACertificate: SecCertificateRef)
      : TBytes; static;
{$IFDEF TLSLIB_MACOS}
    /// <summary>Classifies a trust-settings dict's scope for TLS server auth: EntryScopeApplicable
    /// (the entry governs the SSL policy - no policy key, or the Apple SSL policy), EntryScopeNot
    /// (scoped to another application, a hostname policy string, or a non-SSL policy - ignore),
    /// or EntryScopeUnknown (a policy is set but SSL scoping cannot be resolved - a Deny is still
    /// honoured, a Trust is not).</summary>
    class function ClassifyEntry(ADict: Pointer): Int32; static;
    /// <summary>The verdict a single domain's trust settings yield for a certificate:
    /// DomainVerdictDeny, DomainVerdictTrust, or DomainVerdictNoOpinion (no record, or no entry
    /// that matches the SSL policy). Within a domain a Deny overrides a Trust.</summary>
    class function DomainVerdict(ACertificate: SecCertificateRef;
      ADomain: SecTrustSettingsDomain): Int32; static;
    /// <summary>Whether the OS trusts the certificate as a TLS server-auth anchor, honouring
    /// settings across domains (User -> Admin -> System, the first domain with a matching entry
    /// decides). A certificate enumerated from the System domain with no explicit decision is a
    /// built-in root and stays trusted; a User/Admin certificate needs an explicit SSL grant.</summary>
    class function AdmitsServerAuth(ACertificate: SecCertificateRef;
      AOriginDomain: SecTrustSettingsDomain): Boolean; static;
    class procedure HarvestDomain(ADomain: SecTrustSettingsDomain;
      const ADest: TList<TBytes>); static;
{$ENDIF}
    /// <summary>Builds a retaining CFArray of SecCertificateRef from the DERs (element refs
    /// released once the array owns them). False when a DER is unparseable or none are usable;
    /// the caller decides the alert. Never inserts a nil into the array.</summary>
    class function MakeCertArray(const ADers: TArray<TBytes>;
      out AArray: CFArrayRef): Boolean; static;
    /// <summary>Reads the DER of the path SecTrust built: element 0 the leaf, the last element
    /// the anchor. Prefers the owned-array API (released here); falls back to the indexed
    /// accessors (unretained, not released). False on any unreadable element.</summary>
    class function ReadTrustPath(ATrust: SecTrustRef;
      out APath: TArray<TBytes>): Boolean; static;
    /// <summary>Runs the chain-algorithm/key-strength policy over the OS-built path with the OS
    /// anchor (the last element) exempt. A nil provider, missing read entry points, or an
    /// unreadable path is internal_error.</summary>
    class function ApplyStrengthPolicy(ATrust: SecTrustRef;
      const AProvider: ICryptoProvider;
      const APolicy: TCertificateStrengthPolicy; const AAdvertised: TArray<UInt16>;
      out AValidatedChain: TArray<TBytes>;
      out AAlert: TTlsAlertDescription): Boolean; static;
    /// <summary>Unix epoch milliseconds to a CFAbsoluteTime (seconds since the 2001 CF epoch). The
    /// explicit Double casts are load-bearing: single precision loses whole seconds off a current
    /// timestamp.</summary>
    class function UnixMillisToCFAbsoluteTime(AMillisUtc: UInt64): Double; static;
  private
    class procedure ResolveDynamicImports; static;
    /// <summary>Runs the OS SSL-server trust evaluation with network fetch off, at the validation
    /// time AClock supplies, consuming the stapled OCSP response as the cached response. APosture
    /// adds the revocation policy (Soft best-effort, Hard require-positive, Off none). Returns True
    /// when trusted; on rejection returns False with AAlert set to the matching fatal alert.</summary>
    /// <summary>The shared SecTrust evaluation: builds the SSL trust (with a revocation policy
    /// when AAddRevocation, network per ANetworkAllowed, RequirePositiveResponse per ARequirePositive),
    /// pins the verify date, consumes the staple, and classifies the result as a tri-state. Returns
    /// True with AOutcome in {Good, Revoked, Indeterminate}; False with AAlert on a definitive
    /// non-revocation trust (or strength) failure. Good means trust + strength passed.</summary>
    class function EvaluateTrust(const AChain: TArray<TBytes>;
      const AHostName: string; const AOcspStaple: TBytes; ANetworkAllowed: Boolean;
      AAddRevocation, ARequirePositive: Boolean; const AClock: ITlsClock;
      const AProvider: ICryptoProvider;
      const AStrengthPolicy: TCertificateStrengthPolicy;
      const AAdvertised: TArray<UInt16>; out AOutcome: TLiveRevocationOutcome;
      out AValidatedChain: TArray<TBytes>;
      out AAlert: TTlsAlertDescription): Boolean; static;
    /// <summary>The inline cache-only server evaluation (no socket). Live downgrades a configured
    /// Hard to effective-Soft so an indeterminate revocation defers to the async park.</summary>
    class function EvaluateSslChain(const AChain: TArray<TBytes>;
      const AHostName: string; APosture: TRevocationPosture; AFetch: TSystemTrustFetch;
      const AClock: ITlsClock;
      const AOcspStaple: TBytes; const AProvider: ICryptoProvider;
      const AStrengthPolicy: TCertificateStrengthPolicy;
      const AAdvertised: TArray<UInt16>;
      out AValidatedChain: TArray<TBytes>;
      out AAlert: TTlsAlertDescription): Boolean; static;
    /// <summary>Runs the SERVER evaluation LIVE (network on, network-disabled flag dropped,
    /// RequirePositiveResponse always on so an indeterminate surfaces), returning the tri-state for
    /// the park resolver. For the off-engine-thread resolver only. Apple has no per-evaluation
    /// revocation timeout, so the fetch is bounded by the OS default.</summary>
    class function EvaluateServerLive(const AChain: TArray<TBytes>;
      const AHostName: string; const AStaple: TBytes; const AClock: ITlsClock;
      const AProvider: ICryptoProvider;
      const AStrengthPolicy: TCertificateStrengthPolicy;
      const AAdvertised: TArray<UInt16>; out AOutcome: TLiveRevocationOutcome;
      out AAlert: TTlsAlertDescription): Boolean; static;
    /// <summary>The shared CLIENT-certificate trust evaluation: an anchors-only SecTrust built over
    /// AAnchors alone (never the OS/public roots) with the client SSL policy, the revocation policy
    /// (network per ANetworkAllowed, RequirePositiveResponse per ARequirePositive), and the injected
    /// clock (a client certificate is never stapled). Zero usable anchors reject before the trust.
    /// Classifies the result as a tri-state, exactly like EvaluateTrust. For the wrappers below.</summary>
    class function EvaluateClientTrust(const AChain, AAnchors: TArray<TBytes>;
      ANetworkAllowed, AAddRevocation, ARequirePositive: Boolean; const AClock: ITlsClock;
      const AProvider: ICryptoProvider;
      const AStrengthPolicy: TCertificateStrengthPolicy;
      const AAdvertised: TArray<UInt16>; out AOutcome: TLiveRevocationOutcome;
      out AValidatedChain: TArray<TBytes>;
      out AAlert: TTlsAlertDescription): Boolean; static;
    /// <summary>The inline cache-only CLIENT evaluation (no socket). Live downgrades a configured
    /// Hard to effective-Soft so an indeterminate revocation defers to the async park.</summary>
    class function EvaluateClientChain(const AChain, AAnchors: TArray<TBytes>;
      APosture: TRevocationPosture; AFetch: TSystemTrustFetch; const AClock: ITlsClock;
      const AProvider: ICryptoProvider;
      const AStrengthPolicy: TCertificateStrengthPolicy;
      const AAdvertised: TArray<UInt16>;
      out AValidatedChain: TArray<TBytes>;
      out AAlert: TTlsAlertDescription): Boolean; static;
    /// <summary>Runs the CLIENT evaluation LIVE (network on, network-disabled flag dropped,
    /// RequirePositiveResponse always on so an indeterminate surfaces), returning the tri-state for
    /// the park resolver. For the off-engine-thread resolver only. Apple has no per-evaluation
    /// revocation timeout, so the fetch is bounded by the OS default.</summary>
    class function EvaluateClientLive(const AChain, AAnchors: TArray<TBytes>;
      const AClock: ITlsClock; const AProvider: ICryptoProvider;
      const AStrengthPolicy: TCertificateStrengthPolicy;
      const AAdvertised: TArray<UInt16>; out AOutcome: TLiveRevocationOutcome;
      out AAlert: TTlsAlertDescription): Boolean; static;
{$IFDEF TLSLIB_MACOS}
    /// <summary>The raw DER of every keychain-trusted certificate across the
    /// System, Admin and User domains, honouring per-domain trust settings. Validation and
    /// de-duplication are the caller's responsibility.</summary>
    class function CopyTrustSettingsCertificates: TArray<TBytes>; static;
{$ENDIF}
  end;

{ TAppleTrustApi }

class procedure TAppleTrustApi.ResolveDynamicImports;
var
  LHandle: NativeUInt;
  LSym: Pointer;
begin
  FReady := False;

  // the CoreFoundation / Security frameworks are already linked, so the global namespace
  // (an empty soname) resolves their exports
  LHandle := TPosixDynLib.Open('');
  if LHandle = 0 then
    Exit;
  try
    FCFArrayGetCount := TCFArrayGetCountFunc(TPosixDynLib.Resolve(LHandle, 'CFArrayGetCount'));
    FCFArrayGetValueAtIndex := TCFArrayGetValueAtIndexFunc(TPosixDynLib.Resolve(LHandle,
      'CFArrayGetValueAtIndex'));
    FCFArrayCreate := TCFArrayCreateFunc(TPosixDynLib.Resolve(LHandle, 'CFArrayCreate'));
    FCFRelease := TCFReleaseProc(TPosixDynLib.Resolve(LHandle, 'CFRelease'));
    FCFDataGetLength := TCFDataGetLengthFunc(TPosixDynLib.Resolve(LHandle, 'CFDataGetLength'));
    FCFDataGetBytePtr := TCFDataGetBytePtrFunc(TPosixDynLib.Resolve(LHandle,
      'CFDataGetBytePtr'));
    FCFDataCreate := TCFDataCreateFunc(TPosixDynLib.Resolve(LHandle, 'CFDataCreate'));
    FCFStringCreateWithCString := TCFStringCreateWithCStringFunc(TPosixDynLib.Resolve(LHandle,
      'CFStringCreateWithCString'));
    FCFDictionaryGetValue := TCFDictionaryGetValueFunc(TPosixDynLib.Resolve(LHandle,
      'CFDictionaryGetValue'));
    FCFNumberGetValue := TCFNumberGetValueFunc(TPosixDynLib.Resolve(LHandle,
      'CFNumberGetValue'));

    FSecCertificateCreateWithData := TSecCertificateCreateWithDataFunc(TPosixDynLib.Resolve(
      LHandle, 'SecCertificateCreateWithData'));
    FSecCertificateCopyData := TSecCertificateCopyDataFunc(TPosixDynLib.Resolve(LHandle,
      'SecCertificateCopyData'));
    FSecPolicyCreateSSL := TSecPolicyCreateSSLFunc(TPosixDynLib.Resolve(LHandle,
      'SecPolicyCreateSSL'));
    FSecTrustCreateWithCertificates := TSecTrustCreateWithCertificatesFunc(TPosixDynLib.Resolve(
      LHandle, 'SecTrustCreateWithCertificates'));
    FSecTrustSetNetworkFetchAllowed := TSecTrustSetNetworkFetchAllowedFunc(TPosixDynLib.Resolve(
      LHandle, 'SecTrustSetNetworkFetchAllowed'));
    FSecTrustEvaluateWithError := TSecTrustEvaluateWithErrorFunc(TPosixDynLib.Resolve(LHandle,
      'SecTrustEvaluateWithError'));

    FSecPolicyCreateRevocation := TSecPolicyCreateRevocationFunc(TPosixDynLib.Resolve(LHandle,
      'SecPolicyCreateRevocation'));
    FSecTrustSetVerifyDate := TSecTrustSetVerifyDateFunc(TPosixDynLib.Resolve(LHandle,
      'SecTrustSetVerifyDate'));
    FSecTrustSetOCSPResponse := TSecTrustSetOCSPResponseFunc(TPosixDynLib.Resolve(LHandle,
      'SecTrustSetOCSPResponse'));
    FSecTrustSetAnchorCertificates := TSecTrustSetAnchorCertificatesFunc(TPosixDynLib.Resolve(
      LHandle, 'SecTrustSetAnchorCertificates'));
    FSecTrustSetAnchorCertificatesOnly := TSecTrustSetAnchorCertificatesOnlyFunc(
      TPosixDynLib.Resolve(LHandle, 'SecTrustSetAnchorCertificatesOnly'));
    FSecTrustCopyCertificateChain := TSecTrustCopyCertificateChainFunc(
      TPosixDynLib.Resolve(LHandle, 'SecTrustCopyCertificateChain'));
    FSecTrustGetCertificateCount := TSecTrustGetCertificateCountFunc(
      TPosixDynLib.Resolve(LHandle, 'SecTrustGetCertificateCount'));
    FSecTrustGetCertificateAtIndex := TSecTrustGetCertificateAtIndexFunc(
      TPosixDynLib.Resolve(LHandle, 'SecTrustGetCertificateAtIndex'));
    FCFDateCreate := TCFDateCreateFunc(TPosixDynLib.Resolve(LHandle, 'CFDateCreate'));
    // a data export whose address IS the callbacks struct CFArrayCreate wants: pass it as
    // resolved, do not dereference
    FkCFTypeArrayCallBacks := TPosixDynLib.Resolve(LHandle, 'kCFTypeArrayCallBacks');

    // best-effort CFError decode symbols (may be absent); resolving them never
    // gates FReady - if any is missing the rejected-chain path just reports unknown_ca.
    FCFErrorGetCode := TCFErrorGetCodeFunc(TPosixDynLib.Resolve(LHandle, 'CFErrorGetCode'));
    FCFErrorGetDomain := TCFErrorGetDomainFunc(TPosixDynLib.Resolve(LHandle, 'CFErrorGetDomain'));
    FCFEqual := TCFEqualFunc(TPosixDynLib.Resolve(LHandle, 'CFEqual'));
    LSym := TPosixDynLib.Resolve(LHandle, 'kCFErrorDomainOSStatus');
    if LSym <> nil then
      FkCFErrorDomainOSStatus := CFStringRef(PPointer(LSym)^);

{$IFDEF TLSLIB_MACOS}
    FSecTrustSettingsCopyCertificates := TSecTrustSettingsCopyCertificatesFunc(
      TPosixDynLib.Resolve(LHandle, 'SecTrustSettingsCopyCertificates'));
    FSecTrustSettingsCopyTrustSettings := TSecTrustSettingsCopyTrustSettingsFunc(
      TPosixDynLib.Resolve(LHandle, 'SecTrustSettingsCopyTrustSettings'));
    FSecPolicyCopyProperties := TSecPolicyCopyPropertiesFunc(
      TPosixDynLib.Resolve(LHandle, 'SecPolicyCopyProperties'));
    // create (do not dlsym) the trust-settings keys - see the field declarations for why
    if System.Assigned(FCFStringCreateWithCString) then
    begin
      FkSecTrustSettingsResult := FCFStringCreateWithCString(nil,
        'kSecTrustSettingsResult', KCFStringEncodingUTF8);
      FkSecTrustSettingsPolicy := FCFStringCreateWithCString(nil,
        'kSecTrustSettingsPolicy', KCFStringEncodingUTF8);
      FkSecTrustSettingsApplication := FCFStringCreateWithCString(nil,
        'kSecTrustSettingsApplication', KCFStringEncodingUTF8);
      FkSecTrustSettingsPolicyString := FCFStringCreateWithCString(nil,
        'kSecTrustSettingsPolicyString', KCFStringEncodingUTF8);
    end;
    // kSecPolicyOid / kSecPolicyAppleSSL are genuine exported data symbols (SecPolicy.h)
    LSym := TPosixDynLib.Resolve(LHandle, 'kSecPolicyOid');
    if LSym <> nil then
      FkSecPolicyOid := CFStringRef(PPointer(LSym)^);
    LSym := TPosixDynLib.Resolve(LHandle, 'kSecPolicyAppleSSL');
    if LSym <> nil then
      FkSecPolicyAppleSSL := CFStringRef(PPointer(LSym)^);
{$ENDIF}
  finally
    TPosixDynLib.Close(LHandle);
  end;

  FReady := System.Assigned(FCFRelease) and System.Assigned(FCFDataCreate) and
    System.Assigned(FCFArrayCreate) and (FkCFTypeArrayCallBacks <> nil) and
    System.Assigned(FSecCertificateCreateWithData) and
    System.Assigned(FSecPolicyCreateSSL) and
    System.Assigned(FSecTrustCreateWithCertificates) and
    System.Assigned(FSecTrustSetNetworkFetchAllowed) and
    System.Assigned(FSecTrustEvaluateWithError);

  // Independent of FReady: only when every CFError accessor resolved may we decode
  // a granular reason; otherwise the rejected-chain path stays at unknown_ca.
  FCanDecodeError := System.Assigned(FCFErrorGetCode) and
    System.Assigned(FCFErrorGetDomain) and System.Assigned(FCFEqual) and
    (FkCFErrorDomainOSStatus <> nil);

{$IFDEF TLSLIB_MACOS}
  // tier 0: enumerating the store. A miss means the harvest cannot run at all (fail closed).
  // These are CoreFoundation/Security fundamentals present on every supported macOS.
  FHarvestReady := System.Assigned(FSecTrustSettingsCopyCertificates) and
    System.Assigned(FCFArrayGetCount) and
    System.Assigned(FCFArrayGetValueAtIndex) and System.Assigned(FCFRelease) and
    System.Assigned(FSecCertificateCopyData) and System.Assigned(FCFDataGetLength) and
    System.Assigned(FCFDataGetBytePtr);
  // tier 1: reading and interpreting per-domain settings. A miss falls back to harvesting the
  // System domain only (a custom CA whose record cannot be read must not become an anchor, while
  // the built-in roots stay populated) rather than zeroing the harvest.
  FSettingsReady := FHarvestReady and
    System.Assigned(FSecTrustSettingsCopyTrustSettings) and
    System.Assigned(FCFDictionaryGetValue) and System.Assigned(FCFNumberGetValue) and
    (FkSecTrustSettingsResult <> nil) and (FkSecTrustSettingsPolicy <> nil) and
    (FkSecTrustSettingsApplication <> nil) and (FkSecTrustSettingsPolicyString <> nil);
  // tier 2: SSL policy scoping. Best-effort - a miss treats a policy-scoped entry as unscoped
  // (the prior behaviour), never gating the harvest.
  FSslScopeReady := System.Assigned(FSecPolicyCopyProperties) and
    System.Assigned(FCFEqual) and (FkSecPolicyOid <> nil) and (FkSecPolicyAppleSSL <> nil);
{$ENDIF}
end;

class function TAppleTrustApi.CopyCertificateDer(
  ACertificate: SecCertificateRef): TBytes;
var
  LData: CFDataRef;
  LLen: CFIndex;
  LPtr: PByte;
begin
  Result := nil;
  if (ACertificate = nil) or (not System.Assigned(FSecCertificateCopyData)) then
    Exit;
  LData := FSecCertificateCopyData(ACertificate);
  if LData = nil then
    Exit;
  try
    LLen := FCFDataGetLength(LData);
    LPtr := FCFDataGetBytePtr(LData);
    if (LLen > 0) and (LPtr <> nil) then
    begin
      SetLength(Result, LLen);
      Move(LPtr^, Result[0], LLen);
    end;
  finally
    FCFRelease(LData);
  end;
end;

class function TAppleTrustApi.ReadTrustPath(ATrust: SecTrustRef;
  out APath: TArray<TBytes>): Boolean;
var
  LArr: CFArrayRef;
  LOwned: Boolean;
  LCount, LI: CFIndex;
  LDer: TBytes;
begin
  Result := False;
  APath := nil;
  LArr := nil;
  LOwned := False;
  // prefer the owned-array API; else the indexed fallback
  if System.Assigned(FSecTrustCopyCertificateChain) then
  begin
    LArr := FSecTrustCopyCertificateChain(ATrust);
    if LArr = nil then
      Exit;
    LOwned := True;
  end;
  try
    if LArr <> nil then
    begin
      if (not System.Assigned(FCFArrayGetCount)) or
        (not System.Assigned(FCFArrayGetValueAtIndex)) then
        Exit;
      LCount := FCFArrayGetCount(LArr);
      if LCount <= 0 then
        Exit;
      SetLength(APath, LCount);
      for LI := 0 to LCount - 1 do
      begin
        // unretained; do not release
        LDer := CopyCertificateDer(FCFArrayGetValueAtIndex(LArr, LI));
        if Length(LDer) = 0 then
          Exit;
        APath[LI] := LDer;
      end;
    end
    else
    begin
      if (not System.Assigned(FSecTrustGetCertificateCount)) or
        (not System.Assigned(FSecTrustGetCertificateAtIndex)) then
        Exit;
      LCount := FSecTrustGetCertificateCount(ATrust);
      if LCount <= 0 then
        Exit;
      SetLength(APath, LCount);
      for LI := 0 to LCount - 1 do
      begin
        // unretained; do not release
        LDer := CopyCertificateDer(FSecTrustGetCertificateAtIndex(ATrust, LI));
        if Length(LDer) = 0 then
          Exit;
        APath[LI] := LDer;
      end;
    end;
    Result := True;
  finally
    if LOwned and (LArr <> nil) then
      FCFRelease(LArr);
  end;
end;

class function TAppleTrustApi.ApplyStrengthPolicy(ATrust: SecTrustRef;
  const AProvider: ICryptoProvider; const APolicy: TCertificateStrengthPolicy;
  const AAdvertised: TArray<UInt16>; out AValidatedChain: TArray<TBytes>;
  out AAlert: TTlsAlertDescription): Boolean;
var
  LPath: TArray<TBytes>;
begin
  Result := False;
  AValidatedChain := nil;
  if AProvider = nil then
  begin
    AAlert := TTlsAlertDescription.InternalError;
    Exit;
  end;
  if not ReadTrustPath(ATrust, LPath) then
  begin
    AAlert := TTlsAlertDescription.InternalError;
    Exit;
  end;
  // exempt the OS anchor (last path element); leaf and intermediates are checked
  Result := TChainAlgorithmPolicy.Check(AProvider.Certificates, LPath,
    TArray<TBytes>.Create(LPath[High(LPath)]), APolicy, AAdvertised, AAlert);
  // the OS-built path (leaf-first, ending at the anchor) is the validated chain; ReadTrustPath
  // copied each certificate's DER, so it outlives the SecTrustRef the caller releases
  if Result then
    AValidatedChain := LPath;
end;

class function TAppleTrustApi.MakeCertArray(const ADers: TArray<TBytes>;
  out AArray: CFArrayRef): Boolean;
var
  LRefs: array of Pointer;
  LData: CFDataRef;
  LI, LMade: Integer;
begin
  Result := False;
  AArray := nil;
  if Length(ADers) = 0 then
    Exit;
  SetLength(LRefs, Length(ADers));
  LMade := 0;
  try
    for LI := 0 to Length(ADers) - 1 do
    begin
      if Length(ADers[LI]) = 0 then
        Continue;
      LData := FCFDataCreate(nil, PByte(ADers[LI]), Length(ADers[LI]));
      if LData = nil then
        Exit;
      try
        LRefs[LMade] := FSecCertificateCreateWithData(nil, LData);
      finally
        FCFRelease(LData);
      end;
      // never insert a nil into the array
      if LRefs[LMade] = nil then
        Exit;
      Inc(LMade);
    end;
    if LMade = 0 then
      Exit;
    AArray := FCFArrayCreate(nil, @LRefs[0], LMade, FkCFTypeArrayCallBacks);
    Result := AArray <> nil;
  finally
    // the array retains its elements, so drop our creation refs now; this also runs on a
    // failed build so the created certificates are never leaked
    for LI := 0 to LMade - 1 do
      if LRefs[LI] <> nil then
        FCFRelease(LRefs[LI]);
  end;
end;

class function TAppleTrustApi.UnixMillisToCFAbsoluteTime(AMillisUtc: UInt64): Double;
begin
  Result := (Double(Int64(AMillisUtc)) / Double(1000)) - CFAbsoluteTimeUnixEpochDelta;
end;

class function TAppleTrustApi.EvaluateTrust(const AChain: TArray<TBytes>;
  const AHostName: string; const AOcspStaple: TBytes; ANetworkAllowed: Boolean;
  AAddRevocation, ARequirePositive: Boolean; const AClock: ITlsClock;
  const AProvider: ICryptoProvider;
  const AStrengthPolicy: TCertificateStrengthPolicy;
  const AAdvertised: TArray<UInt16>; out AOutcome: TLiveRevocationOutcome;
  out AValidatedChain: TArray<TBytes>;
  out AAlert: TTlsAlertDescription): Boolean;
var
  LStatusCode: Int32;
  LCertArray, LPolicyArray: CFArrayRef;
  LSslPolicy, LRevPolicy: SecPolicyRef;
  LTrust: SecTrustRef;
  LHostRef: CFStringRef;
  LDate: CFDateRef;
  LStaple: CFDataRef;
  LHostUtf8: UTF8String;
  LPolicyRefs: array [0 .. 1] of Pointer;
  LPolicyCount: Integer;
  LFlags: NativeUInt;
  LStatus: OSStatus;
  LError: CFErrorRef;
begin
  Result := False;
  AOutcome := TLiveRevocationOutcome.Indeterminate;
  AValidatedChain := nil;
  AAlert := TTlsAlertDescription.BadCertificate;

  if Length(AChain) = 0 then
    Exit;

  if not FReady then
  begin
    AAlert := TTlsAlertDescription.InternalError;
    Exit;
  end;

  LCertArray := nil;
  LPolicyArray := nil;
  LSslPolicy := nil;
  LRevPolicy := nil;
  LTrust := nil;
  LHostRef := nil;
  LDate := nil;
  LStaple := nil;
  LError := nil;
  try
    // an unparseable leaf or chain certificate is a bad certificate, not a broken runtime
    if not MakeCertArray(AChain, LCertArray) then
      Exit;

    if AHostName <> '' then
    begin
      LHostUtf8 := UTF8String(AHostName);
      LHostRef := FCFStringCreateWithCString(nil, PAnsiChar(LHostUtf8),
        KCFStringEncodingUTF8);
    end;
    LSslPolicy := FSecPolicyCreateSSL(True, LHostRef);
    if LSslPolicy = nil then
    begin
      AAlert := TTlsAlertDescription.InternalError;
      Exit;
    end;

    // the SSL policy, plus a revocation policy when revocation is in play
    LPolicyRefs[0] := LSslPolicy;
    LPolicyCount := 1;
    if AAddRevocation then
    begin
      if not System.Assigned(FSecPolicyCreateRevocation) then
      begin
        // a required positive response cannot be honored without the revocation policy - fail
        // closed; a best-effort check proceeds under the default behavior
        if ARequirePositive then
        begin
          AAlert := TTlsAlertDescription.InternalError;
          Exit;
        end;
      end
      else
      begin
        LFlags := KSecRevocationUseAnyAvailableMethod;
        // cache-only inline keeps the check off the network; the live re-check drops this
        if not ANetworkAllowed then
          LFlags := LFlags or KSecRevocationNetworkAccessDisabled;
        if ARequirePositive then
          LFlags := LFlags or KSecRevocationRequirePositiveResponse;
        LRevPolicy := FSecPolicyCreateRevocation(LFlags);
        if LRevPolicy = nil then
        begin
          AAlert := TTlsAlertDescription.InternalError;
          Exit;
        end;
        LPolicyRefs[1] := LRevPolicy;
        LPolicyCount := 2;
      end;
    end;
    LPolicyArray := FCFArrayCreate(nil, @LPolicyRefs[0], LPolicyCount,
      FkCFTypeArrayCallBacks);
    if LPolicyArray = nil then
    begin
      AAlert := TTlsAlertDescription.InternalError;
      Exit;
    end;

    LStatus := FSecTrustCreateWithCertificates(LCertArray, LPolicyArray, LTrust);
    if (LStatus <> ErrSecSuccess) or (LTrust = nil) then
    begin
      AAlert := TTlsAlertDescription.BadCertificate;
      Exit;
    end;

    // network per the caller: cache-only inline (no socket), enabled for the live re-check
    if FSecTrustSetNetworkFetchAllowed(LTrust, ANetworkAllowed) <> ErrSecSuccess then
    begin
      AAlert := TTlsAlertDescription.InternalError;
      Exit;
    end;

    // the injected clock pins the validation time (chain validity and OCSP freshness)
    if AClock <> nil then
    begin
      if (not System.Assigned(FSecTrustSetVerifyDate)) or
        (not System.Assigned(FCFDateCreate)) then
      begin
        AAlert := TTlsAlertDescription.InternalError;
        Exit;
      end;
      LDate := FCFDateCreate(nil, UnixMillisToCFAbsoluteTime(AClock.NowUnixMillis));
      if LDate = nil then
      begin
        AAlert := TTlsAlertDescription.InternalError;
        Exit;
      end;
      if FSecTrustSetVerifyDate(LTrust, LDate) <> ErrSecSuccess then
      begin
        AAlert := TTlsAlertDescription.InternalError;
        Exit;
      end;
    end;

    // the handshake staple is consumed as the cached OCSP response (no responder fetch)
    if Length(AOcspStaple) > 0 then
    begin
      if not System.Assigned(FSecTrustSetOCSPResponse) then
      begin
        AAlert := TTlsAlertDescription.InternalError;
        Exit;
      end;
      LStaple := FCFDataCreate(nil, PByte(AOcspStaple), Length(AOcspStaple));
      if LStaple = nil then
      begin
        AAlert := TTlsAlertDescription.InternalError;
        Exit;
      end;
      if FSecTrustSetOCSPResponse(LTrust, LStaple) <> ErrSecSuccess then
      begin
        AAlert := TTlsAlertDescription.InternalError;
        Exit;
      end;
    end;

    if FSecTrustEvaluateWithError(LTrust, @LError) then
    begin
      // trusted: strength policy over the OS-built path; a pass is a definitive Good. The path
      // is read here (before the finally releases LTrust) and handed back as the validated chain.
      if not ApplyStrengthPolicy(LTrust, AProvider, AStrengthPolicy, AAdvertised,
        AValidatedChain, AAlert) then
        Exit;
      AOutcome := TLiveRevocationOutcome.Good;
      Result := True;
      Exit;
    end;

    // Rejected: default to unknown_ca, then refine ONLY from an OSStatus-domain CFError
    // (best-effort). A revoked or an incomplete-revocation status is a tri-state outcome the
    // resolver acts on; every other reason is a definitive trust failure (Result stays False).
    AAlert := TTlsAlertDescription.UnknownCa;
    if (LError <> nil) and FCanDecodeError and
      FCFEqual(FCFErrorGetDomain(LError), FkCFErrorDomainOSStatus) then
    begin
      LStatusCode := Int32(FCFErrorGetCode(LError));
      if LStatusCode = ErrSecCertificateRevoked then
      begin
        AOutcome := TLiveRevocationOutcome.Revoked;
        Result := True;
        Exit;
      end;
      if LStatusCode = ErrSecIncompleteCertRevocationCheck then
      begin
        AOutcome := TLiveRevocationOutcome.Indeterminate;
        Result := True;
        Exit;
      end;
      AAlert := TAppleAlertMap.OsStatusToAlert(LStatusCode);
    end;
  finally
    if LError <> nil then
      FCFRelease(LError);
    if LStaple <> nil then
      FCFRelease(LStaple);
    if LDate <> nil then
      FCFRelease(LDate);
    if LTrust <> nil then
      FCFRelease(LTrust);
    if LRevPolicy <> nil then
      FCFRelease(LRevPolicy);
    if LSslPolicy <> nil then
      FCFRelease(LSslPolicy);
    if LPolicyArray <> nil then
      FCFRelease(LPolicyArray);
    if LHostRef <> nil then
      FCFRelease(LHostRef);
    if LCertArray <> nil then
      FCFRelease(LCertArray);
  end;
end;

class function TAppleTrustApi.EvaluateSslChain(const AChain: TArray<TBytes>;
  const AHostName: string; APosture: TRevocationPosture; AFetch: TSystemTrustFetch;
  const AClock: ITlsClock; const AOcspStaple: TBytes; const AProvider: ICryptoProvider;
  const AStrengthPolicy: TCertificateStrengthPolicy;
  const AAdvertised: TArray<UInt16>;
  out AValidatedChain: TArray<TBytes>;
  out AAlert: TTlsAlertDescription): Boolean;
var
  LOutcome: TLiveRevocationOutcome;
  LRequirePositive: Boolean;
begin
  AValidatedChain := nil;
  // live defers a configured Hard to the async park: run effective-Soft inline (no positive-
  // response requirement) so an indeterminate revocation accepts here and the handshake parks;
  // configured Hard cache-only keeps requiring a positive response inline
  LRequirePositive := (APosture = TRevocationPosture.Hard) and
    (AFetch = TSystemTrustFetch.CacheOnly);
  if not EvaluateTrust(AChain, AHostName, AOcspStaple, False,
    APosture <> TRevocationPosture.Off, LRequirePositive, AClock, AProvider,
    AStrengthPolicy, AAdvertised, LOutcome, AValidatedChain, AAlert) then
    Exit(False);
  case LOutcome of
    TLiveRevocationOutcome.Revoked:
      begin
        AAlert := TTlsAlertDescription.CertificateRevoked;
        Result := False;
      end;
    TLiveRevocationOutcome.Good:
      Result := True;
  else
    // indeterminate surfaces only under effective-Hard (RequirePositiveResponse): reject
    AAlert := TTlsAlertDescription.BadCertificateStatusResponse;
    Result := False;
  end;
end;

class function TAppleTrustApi.EvaluateServerLive(const AChain: TArray<TBytes>;
  const AHostName: string; const AStaple: TBytes; const AClock: ITlsClock;
  const AProvider: ICryptoProvider;
  const AStrengthPolicy: TCertificateStrengthPolicy;
  const AAdvertised: TArray<UInt16>; out AOutcome: TLiveRevocationOutcome;
  out AAlert: TTlsAlertDescription): Boolean;
var
  LValidated: TArray<TBytes>;
begin
  // network on, revocation network-disabled flag dropped, and always RequirePositiveResponse so an
  // indeterminate surfaces distinctly; the resolver applies the configured posture and any fallback.
  // The validated path is not surfaced from the live resolver (it renders a verdict, not a chain).
  Result := EvaluateTrust(AChain, AHostName, AStaple, True, True, True, AClock, AProvider,
    AStrengthPolicy, AAdvertised, AOutcome, LValidated, AAlert);
end;

class function TAppleTrustApi.EvaluateClientTrust(const AChain, AAnchors: TArray<TBytes>;
  ANetworkAllowed, AAddRevocation, ARequirePositive: Boolean; const AClock: ITlsClock;
  const AProvider: ICryptoProvider;
  const AStrengthPolicy: TCertificateStrengthPolicy;
  const AAdvertised: TArray<UInt16>; out AOutcome: TLiveRevocationOutcome;
  out AValidatedChain: TArray<TBytes>;
  out AAlert: TTlsAlertDescription): Boolean;
var
  LStatusCode: Int32;
  LCertArray, LAnchorArray, LPolicyArray: CFArrayRef;
  LSslPolicy, LRevPolicy: SecPolicyRef;
  LTrust: SecTrustRef;
  LDate: CFDateRef;
  LPolicyRefs: array [0 .. 1] of Pointer;
  LPolicyCount: Integer;
  LFlags: NativeUInt;
  LStatus: OSStatus;
  LError: CFErrorRef;
begin
  Result := False;
  AOutcome := TLiveRevocationOutcome.Indeterminate;
  AValidatedChain := nil;
  AAlert := TTlsAlertDescription.BadCertificate;

  if Length(AChain) = 0 then
    Exit;

  if not FReady then
  begin
    AAlert := TTlsAlertDescription.InternalError;
    Exit;
  end;

  // the anchors-only entry points are required for client-auth: without them a client could
  // validate against the OS/public roots, so fail closed rather than fall back to a weaker check
  if (not System.Assigned(FSecTrustSetAnchorCertificates)) or
    (not System.Assigned(FSecTrustSetAnchorCertificatesOnly)) then
  begin
    AAlert := TTlsAlertDescription.InternalError;
    Exit;
  end;

  // zero configured client-CA anchors can trust nothing: reject before building any trust so an
  // empty anchor set can never fall through to the system roots
  if Length(AAnchors) = 0 then
  begin
    AAlert := TTlsAlertDescription.UnknownCa;
    Exit;
  end;

  LCertArray := nil;
  LAnchorArray := nil;
  LPolicyArray := nil;
  LSslPolicy := nil;
  LRevPolicy := nil;
  LTrust := nil;
  LDate := nil;
  LError := nil;
  try
    if not MakeCertArray(AChain, LCertArray) then
      Exit;
    // a configured anchor that will not parse is a broken trust configuration, not a bad peer
    if not MakeCertArray(AAnchors, LAnchorArray) then
    begin
      AAlert := TTlsAlertDescription.InternalError;
      Exit;
    end;

    // a client-authentication SSL policy (no host binding)
    LSslPolicy := FSecPolicyCreateSSL(False, nil);
    if LSslPolicy = nil then
    begin
      AAlert := TTlsAlertDescription.InternalError;
      Exit;
    end;

    LPolicyRefs[0] := LSslPolicy;
    LPolicyCount := 1;
    if AAddRevocation then
    begin
      if not System.Assigned(FSecPolicyCreateRevocation) then
      begin
        // a required positive response cannot be honored without the revocation policy - fail
        // closed; a best-effort check proceeds under the default behavior
        if ARequirePositive then
        begin
          AAlert := TTlsAlertDescription.InternalError;
          Exit;
        end;
      end
      else
      begin
        LFlags := KSecRevocationUseAnyAvailableMethod;
        // cache-only inline keeps the check off the network; the live re-check drops this
        if not ANetworkAllowed then
          LFlags := LFlags or KSecRevocationNetworkAccessDisabled;
        if ARequirePositive then
          LFlags := LFlags or KSecRevocationRequirePositiveResponse;
        LRevPolicy := FSecPolicyCreateRevocation(LFlags);
        if LRevPolicy = nil then
        begin
          AAlert := TTlsAlertDescription.InternalError;
          Exit;
        end;
        LPolicyRefs[1] := LRevPolicy;
        LPolicyCount := 2;
      end;
    end;
    LPolicyArray := FCFArrayCreate(nil, @LPolicyRefs[0], LPolicyCount,
      FkCFTypeArrayCallBacks);
    if LPolicyArray = nil then
    begin
      AAlert := TTlsAlertDescription.InternalError;
      Exit;
    end;

    LStatus := FSecTrustCreateWithCertificates(LCertArray, LPolicyArray, LTrust);
    if (LStatus <> ErrSecSuccess) or (LTrust = nil) then
    begin
      AAlert := TTlsAlertDescription.BadCertificate;
      Exit;
    end;

    // the configured client-CA anchors are the ONLY trusted roots
    if FSecTrustSetAnchorCertificates(LTrust, LAnchorArray) <> ErrSecSuccess then
    begin
      AAlert := TTlsAlertDescription.InternalError;
      Exit;
    end;
    if FSecTrustSetAnchorCertificatesOnly(LTrust, True) <> ErrSecSuccess then
    begin
      AAlert := TTlsAlertDescription.InternalError;
      Exit;
    end;

    // network per the caller: cache-only inline (no socket), enabled for the live re-check
    if FSecTrustSetNetworkFetchAllowed(LTrust, ANetworkAllowed) <> ErrSecSuccess then
    begin
      AAlert := TTlsAlertDescription.InternalError;
      Exit;
    end;

    if AClock <> nil then
    begin
      if (not System.Assigned(FSecTrustSetVerifyDate)) or
        (not System.Assigned(FCFDateCreate)) then
      begin
        AAlert := TTlsAlertDescription.InternalError;
        Exit;
      end;
      LDate := FCFDateCreate(nil, UnixMillisToCFAbsoluteTime(AClock.NowUnixMillis));
      if LDate = nil then
      begin
        AAlert := TTlsAlertDescription.InternalError;
        Exit;
      end;
      if FSecTrustSetVerifyDate(LTrust, LDate) <> ErrSecSuccess then
      begin
        AAlert := TTlsAlertDescription.InternalError;
        Exit;
      end;
    end;

    if FSecTrustEvaluateWithError(LTrust, @LError) then
    begin
      // trusted: strength policy over the OS-built path; a pass is a definitive Good. The path
      // is read here (before the finally releases LTrust) and handed back as the validated chain.
      if not ApplyStrengthPolicy(LTrust, AProvider, AStrengthPolicy, AAdvertised,
        AValidatedChain, AAlert) then
        Exit;
      AOutcome := TLiveRevocationOutcome.Good;
      Result := True;
      Exit;
    end;

    // Rejected: default to unknown_ca, then refine ONLY from an OSStatus-domain CFError. A revoked
    // or an incomplete-revocation status is a tri-state outcome the resolver acts on; every other
    // reason is a definitive trust failure (Result stays False).
    AAlert := TTlsAlertDescription.UnknownCa;
    if (LError <> nil) and FCanDecodeError and
      FCFEqual(FCFErrorGetDomain(LError), FkCFErrorDomainOSStatus) then
    begin
      LStatusCode := Int32(FCFErrorGetCode(LError));
      if LStatusCode = ErrSecCertificateRevoked then
      begin
        AOutcome := TLiveRevocationOutcome.Revoked;
        Result := True;
        Exit;
      end;
      if LStatusCode = ErrSecIncompleteCertRevocationCheck then
      begin
        AOutcome := TLiveRevocationOutcome.Indeterminate;
        Result := True;
        Exit;
      end;
      AAlert := TAppleAlertMap.OsStatusToAlert(LStatusCode);
    end;
  finally
    if LError <> nil then
      FCFRelease(LError);
    if LDate <> nil then
      FCFRelease(LDate);
    if LTrust <> nil then
      FCFRelease(LTrust);
    if LRevPolicy <> nil then
      FCFRelease(LRevPolicy);
    if LSslPolicy <> nil then
      FCFRelease(LSslPolicy);
    if LPolicyArray <> nil then
      FCFRelease(LPolicyArray);
    if LAnchorArray <> nil then
      FCFRelease(LAnchorArray);
    if LCertArray <> nil then
      FCFRelease(LCertArray);
  end;
end;

class function TAppleTrustApi.EvaluateClientChain(const AChain, AAnchors: TArray<TBytes>;
  APosture: TRevocationPosture; AFetch: TSystemTrustFetch; const AClock: ITlsClock;
  const AProvider: ICryptoProvider;
  const AStrengthPolicy: TCertificateStrengthPolicy;
  const AAdvertised: TArray<UInt16>;
  out AValidatedChain: TArray<TBytes>;
  out AAlert: TTlsAlertDescription): Boolean;
var
  LOutcome: TLiveRevocationOutcome;
  LRequirePositive: Boolean;
begin
  AValidatedChain := nil;
  // live defers a configured Hard to the async park: run effective-Soft inline (no positive-
  // response requirement) so an indeterminate revocation accepts here and the handshake parks;
  // configured Hard cache-only keeps requiring a positive response inline
  LRequirePositive := (APosture = TRevocationPosture.Hard) and
    (AFetch = TSystemTrustFetch.CacheOnly);
  if not EvaluateClientTrust(AChain, AAnchors, False, APosture <> TRevocationPosture.Off,
    LRequirePositive, AClock, AProvider, AStrengthPolicy, AAdvertised, LOutcome,
    AValidatedChain, AAlert) then
    Exit(False);
  case LOutcome of
    TLiveRevocationOutcome.Revoked:
      begin
        AAlert := TTlsAlertDescription.CertificateRevoked;
        Result := False;
      end;
    TLiveRevocationOutcome.Good:
      Result := True;
  else
    // indeterminate surfaces only under effective-Hard (RequirePositiveResponse): reject
    AAlert := TTlsAlertDescription.BadCertificateStatusResponse;
    Result := False;
  end;
end;

class function TAppleTrustApi.EvaluateClientLive(const AChain, AAnchors: TArray<TBytes>;
  const AClock: ITlsClock; const AProvider: ICryptoProvider;
  const AStrengthPolicy: TCertificateStrengthPolicy;
  const AAdvertised: TArray<UInt16>; out AOutcome: TLiveRevocationOutcome;
  out AAlert: TTlsAlertDescription): Boolean;
var
  LValidated: TArray<TBytes>;
begin
  // network on, revocation network-disabled flag dropped, and always RequirePositiveResponse so an
  // indeterminate surfaces distinctly; the resolver applies the configured posture and any fallback.
  // The validated path is not surfaced from the live resolver (it renders a verdict, not a chain).
  Result := EvaluateClientTrust(AChain, AAnchors, True, True, True, AClock, AProvider,
    AStrengthPolicy, AAdvertised, AOutcome, LValidated, AAlert);
end;

{$IFDEF TLSLIB_MACOS}

class function TAppleTrustApi.ClassifyEntry(ADict: Pointer): Int32;
var
  LPolicy: SecPolicyRef;
  LProps: Pointer;
  LOid: Pointer;
begin
  if ADict = nil then
    Exit(EntryScopeNot);
  // an entry scoped to a specific application, or to a hostname (policy string), is not a general
  // server-auth grant or deny for a root (SecTrustSettings.h)
  if FCFDictionaryGetValue(ADict, FkSecTrustSettingsApplication) <> nil then
    Exit(EntryScopeNot);
  if FCFDictionaryGetValue(ADict, FkSecTrustSettingsPolicyString) <> nil then
    Exit(EntryScopeNot);
  // no policy key means the entry applies to every policy, SSL included
  LPolicy := FCFDictionaryGetValue(ADict, FkSecTrustSettingsPolicy);
  if LPolicy = nil then
    Exit(EntryScopeApplicable);
  // a policy is set; without the SSL-scoping symbols the scope is unknown (honour a Deny, not a
  // Trust) rather than failing the harvest
  if not FSslScopeReady then
    Exit(EntryScopeUnknown);
  LProps := FSecPolicyCopyProperties(LPolicy);
  if LProps = nil then
    Exit(EntryScopeUnknown);
  try
    LOid := FCFDictionaryGetValue(LProps, FkSecPolicyOid);
    if LOid = nil then
      Exit(EntryScopeUnknown);
    if FCFEqual(LOid, FkSecPolicyAppleSSL) then
      Result := EntryScopeApplicable
    else
      Result := EntryScopeNot; // a non-SSL policy (S/MIME, code signing, ...) does not govern TLS
  finally
    FCFRelease(LProps);
  end;
end;

class function TAppleTrustApi.DomainVerdict(ACertificate: SecCertificateRef;
  ADomain: SecTrustSettingsDomain): Int32;
var
  LSettings: CFArrayRef;
  LStatus: OSStatus;
  LI, LCount: CFIndex;
  LDict, LNum: Pointer;
  LScope, LResult: Int32;
  LSawTrust: Boolean;
begin
  Result := DomainVerdictNoOpinion;
  LSettings := nil;
  LStatus := FSecTrustSettingsCopyTrustSettings(ACertificate, ADomain, LSettings);
  // errSecItemNotFound (or any non-success) means no record in this domain: no opinion
  if (LStatus <> ErrSecSuccess) or (LSettings = nil) then
    Exit;
  try
    LCount := FCFArrayGetCount(LSettings);
    // an empty settings array is an unconditional trust-root grant (SecTrustSettings.h)
    if LCount = 0 then
      Exit(DomainVerdictTrust);
    LSawTrust := False;
    for LI := 0 to LCount - 1 do
    begin
      LDict := FCFArrayGetValueAtIndex(LSettings, LI);
      LScope := ClassifyEntry(LDict);
      if LScope = EntryScopeNot then
        Continue;
      LNum := FCFDictionaryGetValue(LDict, FkSecTrustSettingsResult);
      if LNum = nil then
        LResult := KSecTrustSettingsResultTrustRoot // an absent result defaults to TrustRoot
      else if not FCFNumberGetValue(LNum, KCFNumberSInt32Type, @LResult) then
        LResult := KSecTrustSettingsResultInvalid;
      // a Deny is honoured whether the scope is applicable OR unknown (unresolved scope resolves
      // toward less trust); a Trust is granted only when the scope is positively applicable
      if LResult = KSecTrustSettingsResultDeny then
        Exit(DomainVerdictDeny);
      if (LScope = EntryScopeApplicable) and
        ((LResult = KSecTrustSettingsResultTrustRoot) or
        (LResult = KSecTrustSettingsResultTrustAsRoot)) then
        LSawTrust := True;
      // Unspecified / Invalid: no opinion, keep scanning (a later Deny still wins)
    end;
    if LSawTrust then
      Result := DomainVerdictTrust;
  finally
    FCFRelease(LSettings);
  end;
end;

class function TAppleTrustApi.AdmitsServerAuth(ACertificate: SecCertificateRef;
  AOriginDomain: SecTrustSettingsDomain): Boolean;
var
  LVerdict: Int32;
begin
  // without the settings-reading symbols, admit only a built-in System root (an unreadable
  // User/Admin record must not become an anchor)
  if not FSettingsReady then
    Exit(AOriginDomain = KSecTrustSettingsDomainSystem);
  // User -> Admin -> System: the first domain with a matching entry decides, so a user
  // "Never Trust" (a User-domain Deny) overrides a built-in System root
  LVerdict := DomainVerdict(ACertificate, KSecTrustSettingsDomainUser);
  if LVerdict <> DomainVerdictNoOpinion then
    Exit(LVerdict = DomainVerdictTrust);
  LVerdict := DomainVerdict(ACertificate, KSecTrustSettingsDomainAdmin);
  if LVerdict <> DomainVerdictNoOpinion then
    Exit(LVerdict = DomainVerdictTrust);
  LVerdict := DomainVerdict(ACertificate, KSecTrustSettingsDomainSystem);
  if LVerdict <> DomainVerdictNoOpinion then
    Exit(LVerdict = DomainVerdictTrust);
  // no matching entry anywhere: a built-in System root is trusted by default (the safety net that
  // keeps the OS system roots harvested regardless of their settings shape); a User/Admin cert is not
  Result := AOriginDomain = KSecTrustSettingsDomainSystem;
end;

class procedure TAppleTrustApi.HarvestDomain(ADomain: SecTrustSettingsDomain;
  const ADest: TList<TBytes>);
var
  LCerts: CFArrayRef;
  LStatus: OSStatus;
  LI, LCount: CFIndex;
  LCert: SecCertificateRef;
  LDer: TBytes;
begin
  LCerts := nil;
  LStatus := FSecTrustSettingsCopyCertificates(ADomain, LCerts);
  if (LStatus <> ErrSecSuccess) or (LCerts = nil) then
    Exit;
  try
    LCount := FCFArrayGetCount(LCerts);
    ADest.Capacity := ADest.Count + LCount;
    for LI := 0 to LCount - 1 do
    begin
      LCert := FCFArrayGetValueAtIndex(LCerts, LI);
      if LCert = nil then
        Continue;
      if not AdmitsServerAuth(LCert, ADomain) then
        Continue;
      LDer := CopyCertificateDer(LCert);
      if Length(LDer) > 0 then
        ADest.Add(LDer);
    end;
  finally
    FCFRelease(LCerts);
  end;
end;

class function TAppleTrustApi.CopyTrustSettingsCertificates: TArray<TBytes>;
var
  LList: TList<TBytes>;
begin
  Result := nil;
  // tier 0: without the enumeration symbols the harvest cannot run; TSystemRootSource.Harvest
  // then raises on the empty result (fail closed)
  if (not FReady) or (not FHarvestReady) then
    Exit;
  LList := TList<TBytes>.Create;
  try
    // System first so a built-in root is harvested with its origin; a User/Admin "Never Trust"
    // still excludes it because AdmitsServerAuth consults every domain regardless of origin.
    HarvestDomain(KSecTrustSettingsDomainSystem, LList);
    // Admin/User records contribute (and can override) only when settings are readable; without
    // that the System roots alone are harvested rather than admitting unreadable custom records.
    if FSettingsReady then
    begin
      HarvestDomain(KSecTrustSettingsDomainAdmin, LList);
      HarvestDomain(KSecTrustSettingsDomainUser, LList);
    end;
    Result := LList.ToArray;
  finally
    LList.Free;
  end;
end;

{ TAppleRootSource }

function TAppleRootSource.HarvestRoots: TArray<TBytes>;
var
  LRaw: TArray<TBytes>;
  LI: Integer;
  LAcc: TSystemRootAccumulator;
begin
  Result := nil;
  LRaw := TAppleTrustApi.CopyTrustSettingsCertificates;
  LAcc := TSystemRootAccumulator.Create;
  try
    for LI := 0 to Length(LRaw) - 1 do
      AddUnique(LAcc, LRaw[LI]);
    Result := LAcc.ToArray;
  finally
    LAcc.Free;
  end;
end;

function TAppleRootSource.SourceName: string;
begin
  Result := 'macOS';
end;
{$ENDIF}

{ TAppleDelegateVerifier }

constructor TAppleDelegateVerifier.Create(const AProvider: ICryptoProvider;
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

function TAppleDelegateVerifier.VerifyServerCertificate(const AChain: TArray<TBytes>;
  const AServerName: TServerName; const AOcspStaple: TBytes;
  out AValidatedChain: TArray<TBytes>;
  out AAlert: TTlsAlertDescription): Boolean;
begin
  Result := TAppleTrustApi.EvaluateSslChain(AChain, AServerName.ToString, FPosture,
    FFetch, FClock, AOcspStaple, FProvider, FStrengthPolicy, FAdvertised,
    AValidatedChain, AAlert);
end;

{ TAppleLiveRevocationResolver }

constructor TAppleLiveRevocationResolver.Create(const AProvider: ICryptoProvider;
  APosture: TRevocationPosture; const AClock: ITlsClock;
  const AStrengthPolicy: TCertificateStrengthPolicy;
  const AAdvertised: TArray<UInt16>; const AFallback: TCertificateVerdictResolver);
begin
  inherited Create(APosture, AFallback);
  FProvider := AProvider;
  FClock := AClock;
  FStrengthPolicy := AStrengthPolicy;
  FAdvertised := AAdvertised;
end;

function TAppleLiveRevocationResolver.EvaluateLive(const AChain: TArray<TBytes>;
  const AHostName: string; const AStaple: TBytes;
  out AOutcome: TLiveRevocationOutcome;
  out ARejectAlert: TTlsAlertDescription): Boolean;
begin
  Result := TAppleTrustApi.EvaluateServerLive(AChain, AHostName, AStaple, FClock,
    FProvider, FStrengthPolicy, FAdvertised, AOutcome, ARejectAlert);
end;

{ TAppleClientLiveRevocationResolver }

constructor TAppleClientLiveRevocationResolver.Create(const AProvider: ICryptoProvider;
  const AAnchors: TArray<TBytes>; APosture: TRevocationPosture; const AClock: ITlsClock;
  const AStrengthPolicy: TCertificateStrengthPolicy;
  const AAdvertised: TArray<UInt16>; const AFallback: TCertificateVerdictResolver);
begin
  inherited Create(APosture, AFallback);
  FProvider := AProvider;
  FAnchors := AAnchors;
  FClock := AClock;
  FStrengthPolicy := AStrengthPolicy;
  FAdvertised := AAdvertised;
end;

function TAppleClientLiveRevocationResolver.EvaluateLive(const AChain: TArray<TBytes>;
  const AHostName: string; const AStaple: TBytes;
  out AOutcome: TLiveRevocationOutcome;
  out ARejectAlert: TTlsAlertDescription): Boolean;
begin
  // a client certificate carries no host identity and is never stapled: AHostName/AStaple unused
  Result := TAppleTrustApi.EvaluateClientLive(AChain, FAnchors, FClock, FProvider,
    FStrengthPolicy, FAdvertised, AOutcome, ARejectAlert);
end;

{ TAppleServerVerifierSource }

constructor TAppleServerVerifierSource.Create(AFetch: TSystemTrustFetch);
begin
  inherited Create;
  FFetch := AFetch;
end;

function TAppleServerVerifierSource.CreateServerVerifier(
  const AContext: TServerTrustContext): IServerCertificateVerifier;
begin
  // live inline defers an indeterminate revocation to the async park, so a park must be guaranteed;
  // without it the delegate would silently run cache-only Soft. Fail at engine creation (before IO).
  if (FFetch = TSystemTrustFetch.Live) and (not AContext.AsyncVerdictEnabled) then
    raise ESystemTrustUnsupportedTlsLibException.CreateRes(@SLiveNeedsAsyncVerdict);
  Result := TAppleDelegateVerifier.Create(AContext.Provider,
    AContext.RevocationPosture, FFetch, AContext.Clock, AContext.StrengthPolicy,
    AContext.AdvertisedSignatureSchemes) as IServerCertificateVerifier;
end;

{ TAppleClientDelegateVerifier }

constructor TAppleClientDelegateVerifier.Create(const AProvider: ICryptoProvider;
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

function TAppleClientDelegateVerifier.VerifyClientCertificate(
  const AChain: TArray<TBytes>; out AValidatedChain: TArray<TBytes>;
  out AAlert: TTlsAlertDescription): Boolean;
begin
  Result := TAppleTrustApi.EvaluateClientChain(AChain, FAnchors, FPosture, FFetch,
    FClock, FProvider, FStrengthPolicy, FAdvertised, AValidatedChain, AAlert);
end;

{ TAppleClientVerifierSource }

constructor TAppleClientVerifierSource.Create(AFetch: TSystemTrustFetch);
begin
  inherited Create;
  FFetch := AFetch;
end;

function TAppleClientVerifierSource.CreateClientVerifier(
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
  Result := TAppleClientDelegateVerifier.Create(AContext.Provider, LAnchors,
    AContext.RevocationPosture, FFetch, AContext.Clock, AContext.StrengthPolicy,
    AContext.AdvertisedSignatureSchemes) as IClientCertificateVerifier;
end;

initialization
  TAppleTrustApi.ResolveDynamicImports;

{$IFEND}

end.
