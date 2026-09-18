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
  TlpIClock,
  TlpServerName,
{$IFDEF TLSLIB_MACOS}
  TlpSystemTrustBase,
{$ENDIF}
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
    FClock: ITlsClock;
    FStrengthPolicy: TCertificateStrengthPolicy;
    FAdvertised: TArray<UInt16>;
  public
    constructor Create(const AProvider: ICryptoProvider;
      APosture: TRevocationPosture; const AClock: ITlsClock;
      const AStrengthPolicy: TCertificateStrengthPolicy;
      const AAdvertised: TArray<UInt16>);
    function VerifyServerCertificate(const AChain: TArray<TBytes>;
      const AServerName: TServerName; const AOcspStaple: TBytes;
      out AAlert: TTlsAlertDescription): Boolean;
  end;

  /// <summary>
  /// The Apple server-certificate verifier source: builds a delegate from the connection's
  /// trust context, so its revocation posture and clock are injected the same way the built-in
  /// verifier receives them.
  /// </summary>
  TAppleServerVerifierSource = class sealed(TInterfacedObject,
    IServerCertificateVerifierSource)
  public
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
    FClock: ITlsClock;
    FStrengthPolicy: TCertificateStrengthPolicy;
    FAdvertised: TArray<UInt16>;
  public
    constructor Create(const AProvider: ICryptoProvider;
      const AAnchors: TArray<TBytes>; APosture: TRevocationPosture;
      const AClock: ITlsClock; const AStrengthPolicy: TCertificateStrengthPolicy;
      const AAdvertised: TArray<UInt16>);
    function VerifyClientCertificate(const AChain: TArray<TBytes>;
      out AAlert: TTlsAlertDescription): Boolean;
  end;

  /// <summary>
  /// The Apple client-certificate verifier source: builds a client delegate over the client-CA
  /// anchors in the context (the exclusive trust root), with the connection's posture and clock.
  /// </summary>
  TAppleClientVerifierSource = class sealed(TInterfacedObject,
    IClientCertificateVerifierSource)
  public
    function CreateClientVerifier(const AContext: TClientTrustContext)
      : IClientCertificateVerifier;
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

  KSecTrustSettingsResultDeny = 3;
  KCFNumberSInt32Type = 3;

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
    FkSecTrustSettingsResult: CFStringRef;
{$ENDIF}
    /// <summary>The DER of one certificate via SecCertificateCopyData. Empty on any failure.
    /// Shared macOS/iOS (harvest on macOS, the validated-path read on both).</summary>
    class function CopyCertificateDer(ACertificate: SecCertificateRef)
      : TBytes; static;
{$IFDEF TLSLIB_MACOS}
    class function DomainDeniesCertificate(ACertificate: SecCertificateRef;
      ADomain: SecTrustSettingsDomain): Boolean; static;
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
      out AAlert: TTlsAlertDescription): Boolean; static;
  private
    class procedure ResolveDynamicImports; static;
    /// <summary>Runs the OS SSL-server trust evaluation with network fetch off, at the validation
    /// time AClock supplies, consuming the stapled OCSP response as the cached response. APosture
    /// adds the revocation policy (Soft best-effort, Hard require-positive, Off none). Returns True
    /// when trusted; on rejection returns False with AAlert set to the matching fatal alert.</summary>
    class function EvaluateSslChain(const AChain: TArray<TBytes>;
      const AHostName: string; APosture: TRevocationPosture; const AClock: ITlsClock;
      const AOcspStaple: TBytes; const AProvider: ICryptoProvider;
      const AStrengthPolicy: TCertificateStrengthPolicy;
      const AAdvertised: TArray<UInt16>;
      out AAlert: TTlsAlertDescription): Boolean; static;
    /// <summary>Runs the OS trust evaluation for a peer CLIENT certificate against an
    /// anchors-only trust built over AAnchors alone (never the OS/public roots), with the client
    /// SSL policy, the posture revocation policy and the injected clock (a client certificate is
    /// never stapled). Zero usable anchors reject before the engine. Returns False with
    /// internal_error when an anchors-only entry point is unavailable.</summary>
    class function EvaluateClientChain(const AChain, AAnchors: TArray<TBytes>;
      APosture: TRevocationPosture; const AClock: ITlsClock;
      const AProvider: ICryptoProvider;
      const AStrengthPolicy: TCertificateStrengthPolicy;
      const AAdvertised: TArray<UInt16>;
      out AAlert: TTlsAlertDescription): Boolean; static;
{$IFDEF TLSLIB_MACOS}
    /// <summary>The raw DER of every keychain-trusted certificate across the
    /// System, Admin and User domains, minus any marked Deny. Validation and
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
    LSym := TPosixDynLib.Resolve(LHandle, 'kSecTrustSettingsResult');
    if LSym <> nil then
      FkSecTrustSettingsResult := CFStringRef(PPointer(LSym)^);
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
  const AAdvertised: TArray<UInt16>; out AAlert: TTlsAlertDescription): Boolean;
var
  LPath: TArray<TBytes>;
begin
  Result := False;
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

class function TAppleTrustApi.EvaluateSslChain(const AChain: TArray<TBytes>;
  const AHostName: string; APosture: TRevocationPosture; const AClock: ITlsClock;
  const AOcspStaple: TBytes; const AProvider: ICryptoProvider;
  const AStrengthPolicy: TCertificateStrengthPolicy;
  const AAdvertised: TArray<UInt16>; out AAlert: TTlsAlertDescription): Boolean;
var
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

    // the SSL policy, plus a revocation policy under a non-Off posture
    LPolicyRefs[0] := LSslPolicy;
    LPolicyCount := 1;
    if APosture <> TRevocationPosture.Off then
    begin
      if not System.Assigned(FSecPolicyCreateRevocation) then
      begin
        // Hard cannot be honored without the revocation policy - fail closed; Soft proceeds
        // best-effort under the default cache-only behavior
        if APosture = TRevocationPosture.Hard then
        begin
          AAlert := TTlsAlertDescription.InternalError;
          Exit;
        end;
      end
      else
      begin
        LFlags := KSecRevocationUseAnyAvailableMethod or
          KSecRevocationNetworkAccessDisabled;
        if APosture = TRevocationPosture.Hard then
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

    // cache-only: never open a socket for AIA / revocation during evaluation
    if FSecTrustSetNetworkFetchAllowed(LTrust, False) <> ErrSecSuccess then
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
      LDate := FCFDateCreate(nil,
        (Int64(AClock.NowUnixMillis) / 1000.0) - CFAbsoluteTimeUnixEpochDelta);
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
      // trusted: policy over the OS-built path
      Result := ApplyStrengthPolicy(LTrust, AProvider, AStrengthPolicy,
        AAdvertised, AAlert);
      Exit;
    end;

    // Rejected: default to unknown_ca, then refine ONLY from an OSStatus-domain CFError
    // (best-effort) so the real reason reaches the peer. Any other domain or a missing
    // accessor stays unknown_ca - a rejection is never softened into success.
    AAlert := TTlsAlertDescription.UnknownCa;
    if (LError <> nil) and FCanDecodeError and
      FCFEqual(FCFErrorGetDomain(LError), FkCFErrorDomainOSStatus) then
      AAlert := TAppleAlertMap.OsStatusToAlert(Int32(FCFErrorGetCode(LError)));
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

class function TAppleTrustApi.EvaluateClientChain(const AChain, AAnchors: TArray<TBytes>;
  APosture: TRevocationPosture; const AClock: ITlsClock;
  const AProvider: ICryptoProvider;
  const AStrengthPolicy: TCertificateStrengthPolicy;
  const AAdvertised: TArray<UInt16>; out AAlert: TTlsAlertDescription): Boolean;
var
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
    if APosture <> TRevocationPosture.Off then
    begin
      if not System.Assigned(FSecPolicyCreateRevocation) then
      begin
        if APosture = TRevocationPosture.Hard then
        begin
          AAlert := TTlsAlertDescription.InternalError;
          Exit;
        end;
      end
      else
      begin
        LFlags := KSecRevocationUseAnyAvailableMethod or
          KSecRevocationNetworkAccessDisabled;
        if APosture = TRevocationPosture.Hard then
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

    if FSecTrustSetNetworkFetchAllowed(LTrust, False) <> ErrSecSuccess then
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
      LDate := FCFDateCreate(nil,
        (Int64(AClock.NowUnixMillis) / 1000.0) - CFAbsoluteTimeUnixEpochDelta);
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
      // trusted: policy over the OS-built path
      Result := ApplyStrengthPolicy(LTrust, AProvider, AStrengthPolicy,
        AAdvertised, AAlert);
      Exit;
    end;

    AAlert := TTlsAlertDescription.UnknownCa;
    if (LError <> nil) and FCanDecodeError and
      FCFEqual(FCFErrorGetDomain(LError), FkCFErrorDomainOSStatus) then
      AAlert := TAppleAlertMap.OsStatusToAlert(Int32(FCFErrorGetCode(LError)));
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

class function TAppleTrustApi.DomainDeniesCertificate(
  ACertificate: SecCertificateRef; ADomain: SecTrustSettingsDomain): Boolean;
var
  LSettings: CFArrayRef;
  LStatus: OSStatus;
  LI, LCount: CFIndex;
  LDict: Pointer;
  LNum: Pointer;
  LResult: Int32;
begin
  Result := False;
  LSettings := nil;
  LStatus := FSecTrustSettingsCopyTrustSettings(ACertificate, ADomain,
    LSettings);
  // No explicit settings in this domain means "no opinion", not deny.
  if (LStatus <> ErrSecSuccess) or (LSettings = nil) then
    Exit;
  try
    LCount := FCFArrayGetCount(LSettings);
    for LI := 0 to LCount - 1 do
    begin
      LDict := FCFArrayGetValueAtIndex(LSettings, LI);
      if LDict = nil then
        Continue;
      LNum := FCFDictionaryGetValue(LDict, FkSecTrustSettingsResult);
      if LNum = nil then
        Continue;
      LResult := 0;
      if FCFNumberGetValue(LNum, KCFNumberSInt32Type, @LResult) then
      begin
        if LResult = KSecTrustSettingsResultDeny then
          Exit(True);
      end;
    end;
  finally
    FCFRelease(LSettings);
  end;
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
      if DomainDeniesCertificate(LCert, ADomain) then
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
  if not FReady then
    Exit;
  LList := TList<TBytes>.Create;
  try
    HarvestDomain(KSecTrustSettingsDomainSystem, LList);
    HarvestDomain(KSecTrustSettingsDomainAdmin, LList);
    HarvestDomain(KSecTrustSettingsDomainUser, LList);
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
  APosture: TRevocationPosture; const AClock: ITlsClock;
  const AStrengthPolicy: TCertificateStrengthPolicy;
  const AAdvertised: TArray<UInt16>);
begin
  inherited Create;
  FProvider := AProvider;
  FPosture := APosture;
  FClock := AClock;
  FStrengthPolicy := AStrengthPolicy;
  FAdvertised := AAdvertised;
end;

function TAppleDelegateVerifier.VerifyServerCertificate(const AChain: TArray<TBytes>;
  const AServerName: TServerName; const AOcspStaple: TBytes;
  out AAlert: TTlsAlertDescription): Boolean;
begin
  Result := TAppleTrustApi.EvaluateSslChain(AChain, AServerName.ToString, FPosture,
    FClock, AOcspStaple, FProvider, FStrengthPolicy, FAdvertised, AAlert);
end;

{ TAppleServerVerifierSource }

function TAppleServerVerifierSource.CreateServerVerifier(
  const AContext: TServerTrustContext): IServerCertificateVerifier;
begin
  Result := TAppleDelegateVerifier.Create(AContext.Provider,
    AContext.RevocationPosture, AContext.Clock, AContext.StrengthPolicy,
    AContext.AdvertisedSignatureSchemes) as IServerCertificateVerifier;
end;

{ TAppleClientDelegateVerifier }

constructor TAppleClientDelegateVerifier.Create(const AProvider: ICryptoProvider;
  const AAnchors: TArray<TBytes>; APosture: TRevocationPosture;
  const AClock: ITlsClock; const AStrengthPolicy: TCertificateStrengthPolicy;
  const AAdvertised: TArray<UInt16>);
begin
  inherited Create;
  FProvider := AProvider;
  FAnchors := AAnchors;
  FPosture := APosture;
  FClock := AClock;
  FStrengthPolicy := AStrengthPolicy;
  FAdvertised := AAdvertised;
end;

function TAppleClientDelegateVerifier.VerifyClientCertificate(
  const AChain: TArray<TBytes>; out AAlert: TTlsAlertDescription): Boolean;
begin
  Result := TAppleTrustApi.EvaluateClientChain(AChain, FAnchors, FPosture,
    FClock, FProvider, FStrengthPolicy, FAdvertised, AAlert);
end;

{ TAppleClientVerifierSource }

function TAppleClientVerifierSource.CreateClientVerifier(
  const AContext: TClientTrustContext): IClientCertificateVerifier;
var
  LAnchors: TArray<TBytes>;
begin
  LAnchors := nil;
  if AContext.TrustStore <> nil then
    LAnchors := AContext.TrustStore.RootCertificates;
  Result := TAppleClientDelegateVerifier.Create(AContext.Provider, LAnchors,
    AContext.RevocationPosture, AContext.Clock, AContext.StrengthPolicy,
    AContext.AdvertisedSignatureSchemes) as IClientCertificateVerifier;
end;

initialization
  TAppleTrustApi.ResolveDynamicImports;

{$IFEND}

end.
