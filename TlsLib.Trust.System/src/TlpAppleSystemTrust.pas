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
  TlpICertificateTrust,
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
  TAppleAnchorStore = class sealed(TSystemTrustBase)
  strict protected
    function HarvestRoots: TArray<TBytes>; override;
    function SourceName: string; override;
  end;
{$ENDIF}

type
  /// <summary>
  /// Delegates verification to Security.framework: SecTrust with an SSL server
  /// policy, network fetch disabled (cache-only), evaluated via
  /// SecTrustEvaluateWithError. Shared by macOS and iOS. Fail-closed.
  /// </summary>
  TAppleDelegateVerifier = class sealed(TInterfacedObject, ICertificateVerifier)
  public
    function Verify(const AChain: TArray<TBytes>; const AHostName: string;
      const AOcspStaple: TBytes; out AAlert: TTlsAlertDescription): Boolean;
  end;

{$IFEND}

implementation

const
  // errSec OSStatus values (SecBase.h) whose meaning we surface as a granular alert.
  ErrSecCertificateExpired = -67818;
  ErrSecCertificateNotValidYet = -67819;
  ErrSecCertificateRevoked = -67820;
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

type
  CFIndex = NativeInt;
  CFArrayRef = Pointer;
  CFDataRef = Pointer;
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
{$IFDEF TLSLIB_MACOS}
    class function CopyCertificateDer(ACertificate: SecCertificateRef)
      : TBytes; static;
    class function DomainDeniesCertificate(ACertificate: SecCertificateRef;
      ADomain: SecTrustSettingsDomain): Boolean; static;
    class procedure HarvestDomain(ADomain: SecTrustSettingsDomain;
      const ADest: TList<TBytes>); static;
{$ENDIF}
  private
    class procedure ResolveDynamicImports; static;
    /// <summary>Runs the OS SSL-server trust evaluation with network fetch off.
    /// Returns True when the chain is trusted; on rejection returns False with
    /// AAlert set to the matching fatal alert.</summary>
    class function EvaluateSslChain(const AChain: TArray<TBytes>;
      const AHostName: string; out AAlert: TTlsAlertDescription): Boolean; static;
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
    System.Assigned(FCFArrayCreate) and
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

class function TAppleTrustApi.EvaluateSslChain(const AChain: TArray<TBytes>;
  const AHostName: string; out AAlert: TTlsAlertDescription): Boolean;
var
  LCertRefs: array of Pointer;
  LCertArray: CFArrayRef;
  LPolicy: SecPolicyRef;
  LTrust: SecTrustRef;
  LHostRef: CFStringRef;
  LData: CFDataRef;
  LHostUtf8: UTF8String;
  LI, LMade: Integer;
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

  SetLength(LCertRefs, Length(AChain));
  LMade := 0;
  LCertArray := nil;
  LPolicy := nil;
  LTrust := nil;
  LHostRef := nil;
  LError := nil;
  try
    for LI := 0 to Length(AChain) - 1 do
    begin
      if Length(AChain[LI]) = 0 then
        Continue;
      LData := FCFDataCreate(nil, PByte(AChain[LI]), Length(AChain[LI]));
      if LData = nil then
        Exit;
      try
        LCertRefs[LMade] := FSecCertificateCreateWithData(nil, LData);
      finally
        FCFRelease(LData);
      end;
      if LCertRefs[LMade] = nil then
        Exit;
      Inc(LMade);
    end;

    if LMade = 0 then
      Exit;

    LCertArray := FCFArrayCreate(nil, @LCertRefs[0], LMade, nil);
    if LCertArray = nil then
      Exit;

    if AHostName <> '' then
    begin
      LHostUtf8 := UTF8String(AHostName);
      LHostRef := FCFStringCreateWithCString(nil, PAnsiChar(LHostUtf8),
        KCFStringEncodingUTF8);
    end;

    LPolicy := FSecPolicyCreateSSL(True, LHostRef);
    if LPolicy = nil then
    begin
      AAlert := TTlsAlertDescription.InternalError;
      Exit;
    end;

    LStatus := FSecTrustCreateWithCertificates(LCertArray, LPolicy, LTrust);
    if (LStatus <> ErrSecSuccess) or (LTrust = nil) then
    begin
      AAlert := TTlsAlertDescription.BadCertificate;
      Exit;
    end;

    // Cache-only: never open a socket for AIA / revocation during evaluation.
    FSecTrustSetNetworkFetchAllowed(LTrust, False);

    if FSecTrustEvaluateWithError(LTrust, @LError) then
    begin
      Result := True;
      Exit;
    end;

    // Rejected: default to unknown_ca, then refine ONLY from an OSStatus-domain
    // CFError (best-effort) so the real reason (expired/revoked/host/EKU) reaches
    // the peer. Any other domain or a missing accessor stays unknown_ca - a
    // rejection is never softened into success.
    AAlert := TTlsAlertDescription.UnknownCa;
    if (LError <> nil) and FCanDecodeError and
      FCFEqual(FCFErrorGetDomain(LError), FkCFErrorDomainOSStatus) then
      AAlert := TAppleAlertMap.OsStatusToAlert(Int32(FCFErrorGetCode(LError)));
  finally
    if LError <> nil then
      FCFRelease(LError);
    if LHostRef <> nil then
      FCFRelease(LHostRef);
    if LTrust <> nil then
      FCFRelease(LTrust);
    if LPolicy <> nil then
      FCFRelease(LPolicy);
    if LCertArray <> nil then
      FCFRelease(LCertArray);
    for LI := 0 to LMade - 1 do
    begin
      if LCertRefs[LI] <> nil then
        FCFRelease(LCertRefs[LI]);
    end;
  end;
end;

{$IFDEF TLSLIB_MACOS}

class function TAppleTrustApi.CopyCertificateDer(
  ACertificate: SecCertificateRef): TBytes;
var
  LData: CFDataRef;
  LLen: CFIndex;
  LPtr: PByte;
begin
  Result := nil;
  if ACertificate = nil then
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

{ TAppleAnchorStore }

function TAppleAnchorStore.HarvestRoots: TArray<TBytes>;
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

function TAppleAnchorStore.SourceName: string;
begin
  Result := 'macOS';
end;
{$ENDIF}

{ TAppleDelegateVerifier }

function TAppleDelegateVerifier.Verify(const AChain: TArray<TBytes>;
  const AHostName: string; const AOcspStaple: TBytes;
  out AAlert: TTlsAlertDescription): Boolean;
begin
  Result := TAppleTrustApi.EvaluateSslChain(AChain, AHostName, AAlert);
end;

initialization
  TAppleTrustApi.ResolveDynamicImports;

{$IFEND}

end.
