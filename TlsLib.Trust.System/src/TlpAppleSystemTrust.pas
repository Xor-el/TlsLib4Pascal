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
  TlpTrustPolicy,
  TlpIClock,
  TlpSystemTrustBase,
  TlpIPlatformChainEngine,
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
  /// The Apple platform chain engine behind the OS trust delegate: builds and trusts a
  /// certificate path with Security.framework (the OS roots for a server certificate, an
  /// exclusive SecTrust over the configured client-CA anchors for a client certificate),
  /// consuming the handshake OCSP staple and the OS revocation cache, and reports the tri-state
  /// revocation outcome. Cache-only inline (network fetch disabled) or, from the async park,
  /// network-enabled for revocation only. Posture, the strength policy, the staple decision and
  /// the identity post-checks belong to the delegate that owns it. Shared by macOS and iOS.
  /// Stateless and thread-reusable.
  /// </summary>
  TAppleChainEngine = class sealed(TInterfacedObject, IPlatformChainEngine)
  public
    function Capabilities: TPlatformChainCapabilities;
    function EvaluateServer(const ARequest: TPlatformChainRequest;
      out AResult: TPlatformChainResult; out AAlert: TTlsAlertDescription): Boolean;
    function EvaluateClient(const ARequest: TPlatformChainRequest;
      out AResult: TPlatformChainResult; out AAlert: TTlsAlertDescription): Boolean;
  end;

{$IFEND}

implementation

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
    /// <summary>Unix epoch milliseconds to a CFAbsoluteTime (seconds since the 2001 CF epoch). The
    /// explicit Double casts are load-bearing: single precision loses whole seconds off a current
    /// timestamp.</summary>
    class function UnixMillisToCFAbsoluteTime(AMillisUtc: UInt64): Double; static;
  private
    class procedure ResolveDynamicImports; static;
    /// <summary>The shared SecTrust SERVER evaluation: builds the SSL trust (adding a revocation
    /// policy unless ARevocation is None, network per ANetworkAllowed, RequirePositiveResponse when
    /// ARevocation is RequirePositive), pins the verify date, consumes the staple, and reports the
    /// result as a tri-state in AResult (Outcome plus, on Good, the OS-built path and the OS anchor
    /// as the policy-exempt certificate). Returns True with a tri-state outcome; False with AAlert
    /// on a definitive non-revocation trust failure. The posture, the strength policy and the
    /// identity post-checks are the owning delegate's.</summary>
    class function EvaluateTrust(const AChain: TArray<TBytes>;
      const AHostName: string; const AOcspStaple: TBytes; ANetworkAllowed: Boolean;
      ARevocation: TPlatformRevocationCheck; const AClock: ITlsClock;
      out AResult: TPlatformChainResult;
      out AAlert: TTlsAlertDescription): Boolean; static;
    /// <summary>The shared SecTrust CLIENT-certificate evaluation: an anchors-only SecTrust built
    /// over AAnchors alone (never the OS/public roots) with the client SSL policy, the revocation
    /// policy (added unless ARevocation is None, network per ANetworkAllowed, RequirePositiveResponse
    /// when ARevocation is RequirePositive), and the injected clock (a client certificate is never
    /// stapled). Zero usable anchors reject before the trust. Reports the tri-state in AResult
    /// exactly like EvaluateTrust.</summary>
    class function EvaluateClientTrust(const AChain, AAnchors: TArray<TBytes>;
      ANetworkAllowed: Boolean; ARevocation: TPlatformRevocationCheck; const AClock: ITlsClock;
      out AResult: TPlatformChainResult;
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
  ARevocation: TPlatformRevocationCheck; const AClock: ITlsClock;
  out AResult: TPlatformChainResult;
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
  LPath: TArray<TBytes>;
  LAddRevocation, LRequirePositive: Boolean;
begin
  // None asks for no revocation policy; BestEffort adds the any-method policy; RequirePositive
  // additionally demands a positive response
  LAddRevocation := ARevocation <> TPlatformRevocationCheck.None;
  LRequirePositive := ARevocation = TPlatformRevocationCheck.RequirePositive;
  Result := False;
  AResult := Default(TPlatformChainResult);
  AResult.Outcome := TLiveRevocationOutcome.Indeterminate;
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
    if LAddRevocation then
    begin
      if not System.Assigned(FSecPolicyCreateRevocation) then
      begin
        // a required positive response cannot be honored without the revocation policy - fail
        // closed; a best-effort check proceeds under the default behavior
        if LRequirePositive then
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
        if LRequirePositive then
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
      // trusted: read the OS-built path (before the finally releases LTrust) and report it with
      // the OS anchor (the last element) exempt from the strength policy the delegate runs over it
      if not ReadTrustPath(LTrust, LPath) then
      begin
        AAlert := TTlsAlertDescription.InternalError;
        Exit;
      end;
      AResult.Path := LPath;
      AResult.PolicyExempt := TArray<TBytes>.Create(LPath[High(LPath)]);
      AResult.Outcome := TLiveRevocationOutcome.Good;
      Result := True;
      Exit;
    end;

    // Rejected: default to unknown_ca, then refine ONLY from an OSStatus-domain CFError
    // (best-effort). A revoked or an incomplete-revocation status is a tri-state outcome the
    // delegate acts on; every other reason is a definitive trust failure (Result stays False).
    AAlert := TTlsAlertDescription.UnknownCa;
    if (LError <> nil) and FCanDecodeError and
      FCFEqual(FCFErrorGetDomain(LError), FkCFErrorDomainOSStatus) then
    begin
      LStatusCode := Int32(FCFErrorGetCode(LError));
      if (LStatusCode = ErrSecCertificateRevoked) or
        (LStatusCode = ErrSecIncompleteCertRevocationCheck) then
      begin
        // a revocation outcome the delegate decides: report the OS-built path (readable even on a
        // rejected evaluation) so the shared pipeline renders the precise revocation alert
        if not ReadTrustPath(LTrust, LPath) then
        begin
          AAlert := TTlsAlertDescription.InternalError;
          Exit;
        end;
        AResult.Path := LPath;
        AResult.PolicyExempt := TArray<TBytes>.Create(LPath[High(LPath)]);
        if LStatusCode = ErrSecCertificateRevoked then
          AResult.Outcome := TLiveRevocationOutcome.Revoked
        else
          AResult.Outcome := TLiveRevocationOutcome.Indeterminate;
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

class function TAppleTrustApi.EvaluateClientTrust(const AChain, AAnchors: TArray<TBytes>;
  ANetworkAllowed: Boolean; ARevocation: TPlatformRevocationCheck; const AClock: ITlsClock;
  out AResult: TPlatformChainResult;
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
  LPath: TArray<TBytes>;
  LAddRevocation, LRequirePositive: Boolean;
begin
  // None asks for no revocation policy; BestEffort adds the any-method policy; RequirePositive
  // additionally demands a positive response
  LAddRevocation := ARevocation <> TPlatformRevocationCheck.None;
  LRequirePositive := ARevocation = TPlatformRevocationCheck.RequirePositive;
  Result := False;
  AResult := Default(TPlatformChainResult);
  AResult.Outcome := TLiveRevocationOutcome.Indeterminate;
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
    if LAddRevocation then
    begin
      if not System.Assigned(FSecPolicyCreateRevocation) then
      begin
        // a required positive response cannot be honored without the revocation policy - fail
        // closed; a best-effort check proceeds under the default behavior
        if LRequirePositive then
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
        if LRequirePositive then
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
      // trusted: read the OS-built path (before the finally releases LTrust) and report it with
      // the configured client-CA anchor (the last element) exempt from the delegate's strength policy
      if not ReadTrustPath(LTrust, LPath) then
      begin
        AAlert := TTlsAlertDescription.InternalError;
        Exit;
      end;
      AResult.Path := LPath;
      AResult.PolicyExempt := TArray<TBytes>.Create(LPath[High(LPath)]);
      AResult.Outcome := TLiveRevocationOutcome.Good;
      Result := True;
      Exit;
    end;

    // Rejected: default to unknown_ca, then refine ONLY from an OSStatus-domain CFError. A revoked
    // or an incomplete-revocation status is a tri-state outcome the delegate acts on; every other
    // reason is a definitive trust failure (Result stays False).
    AAlert := TTlsAlertDescription.UnknownCa;
    if (LError <> nil) and FCanDecodeError and
      FCFEqual(FCFErrorGetDomain(LError), FkCFErrorDomainOSStatus) then
    begin
      LStatusCode := Int32(FCFErrorGetCode(LError));
      if (LStatusCode = ErrSecCertificateRevoked) or
        (LStatusCode = ErrSecIncompleteCertRevocationCheck) then
      begin
        // a revocation outcome the delegate decides: report the OS-built path (readable even on a
        // rejected evaluation) so the shared pipeline renders the precise revocation alert
        if not ReadTrustPath(LTrust, LPath) then
        begin
          AAlert := TTlsAlertDescription.InternalError;
          Exit;
        end;
        AResult.Path := LPath;
        AResult.PolicyExempt := TArray<TBytes>.Create(LPath[High(LPath)]);
        if LStatusCode = ErrSecCertificateRevoked then
          AResult.Outcome := TLiveRevocationOutcome.Revoked
        else
          AResult.Outcome := TLiveRevocationOutcome.Indeterminate;
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

{ TAppleChainEngine }

function TAppleChainEngine.Capabilities: TPlatformChainCapabilities;
begin
  // Security.framework can fetch live revocation, render a cached revocation outcome, and match the
  // DNS host
  Result := [TPlatformChainCapability.LiveFetch, TPlatformChainCapability.CachedRevocation,
    TPlatformChainCapability.DnsIdentity];
end;

function TAppleChainEngine.EvaluateServer(const ARequest: TPlatformChainRequest;
  out AResult: TPlatformChainResult; out AAlert: TTlsAlertDescription): Boolean;
begin
  // the OS name check only ever sees a DNS host (empty for an IP literal); an IP is matched in the
  // library by the delegate
  Result := TAppleTrustApi.EvaluateTrust(ARequest.Chain, ARequest.ServerName.AsDns,
    ARequest.OcspStaple, ARequest.NetworkAllowed, ARequest.Revocation,
    ARequest.Clock, AResult, AAlert);
end;

function TAppleChainEngine.EvaluateClient(const ARequest: TPlatformChainRequest;
  out AResult: TPlatformChainResult; out AAlert: TTlsAlertDescription): Boolean;
begin
  // anchors-only over the configured client-CA anchors (never the OS/public roots); a client
  // certificate carries no host identity and is never stapled
  Result := TAppleTrustApi.EvaluateClientTrust(ARequest.Chain, ARequest.Anchors,
    ARequest.NetworkAllowed, ARequest.Revocation,
    ARequest.Clock, AResult, AAlert);
end;

initialization
  TAppleTrustApi.ResolveDynamicImports;

{$IFEND}

end.
