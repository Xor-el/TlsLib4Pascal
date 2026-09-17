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
  TlpICertificateTrust,
  TlpICertificateVerifierSource,
  TlpTrustPolicy,
  TlpIClock,
  TlpServerName,
  TlpSystemTrustBase;

type
  /// <summary>
  /// Harvests the Windows machine/user trust anchors from the "ROOT" and "CA"
  /// system stores, subtracting any certificate present in the "Disallowed" store
  /// so OS distrust is honored. Emits neutral DER.
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
    FPosture: TRevocationPosture;
    FClock: ITlsClock;
  public
    constructor Create(APosture: TRevocationPosture; const AClock: ITlsClock);
    function VerifyServerCertificate(const AChain: TArray<TBytes>;
      const AServerName: TServerName; const AOcspStaple: TBytes;
      out AAlert: TTlsAlertDescription): Boolean;
  end;

  /// <summary>
  /// The Windows server-certificate verifier source: builds a delegate verifier from the
  /// connection's trust context, so its revocation posture and clock are injected the same
  /// way the built-in verifier receives them.
  /// </summary>
  TWindowsServerVerifierSource = class sealed(TInterfacedObject,
    IServerCertificateVerifierSource)
  public
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
    FAnchors: TArray<TBytes>;
    FPosture: TRevocationPosture;
    FClock: ITlsClock;
  public
    constructor Create(const AAnchors: TArray<TBytes>;
      APosture: TRevocationPosture; const AClock: ITlsClock);
    function VerifyClientCertificate(const AChain: TArray<TBytes>;
      out AAlert: TTlsAlertDescription): Boolean;
  end;

  /// <summary>
  /// The Windows client-certificate verifier source: builds a client delegate over the client-CA
  /// anchors in the context (the exclusive trust root), with the connection's posture and clock.
  /// </summary>
  TWindowsClientVerifierSource = class sealed(TInterfacedObject,
    IClientCertificateVerifierSource)
  public
    function CreateClientVerifier(const AContext: TClientTrustContext)
      : IClientCertificateVerifier;
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
  // the leaf property crypt32 reads a stapled OCSP response from, so revocation is decided
  // from the handshake staple without a network fetch
  CERT_OCSP_RESPONSE_PROP_ID = 70;

  USAGE_MATCH_TYPE_AND = $00000000;
  AUTHTYPE_SERVER = 2;
  AUTHTYPE_CLIENT = 1;
  CERT_CHAIN_POLICY_SSL = PAnsiChar(4);

  SZOID_PKIX_KP_SERVER_AUTH: PAnsiChar = '1.3.6.1.5.5.7.3.1';
  SZOID_PKIX_KP_CLIENT_AUTH: PAnsiChar = '1.3.6.1.5.5.7.3.2';

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
  TCertGetCertificateChainFunc = function(AChainEngine: Pointer;
    ACertContext: PCERT_CONTEXT; ATime: Pointer; AAdditionalStore: HCERTSTORE;
    const AChainPara: CERT_CHAIN_PARA; AFlags: DWORD; AReserved: Pointer;
    var AChainContext: Pointer): BOOL; stdcall;
  TCertFreeCertificateChainProc = procedure(AChainContext: Pointer); stdcall;
  TCertVerifyCertificateChainPolicyFunc = function(APolicyOID: PAnsiChar;
    AChainContext: Pointer; const APolicyPara: CERT_CHAIN_POLICY_PARA;
    var APolicyStatus: CERT_CHAIN_POLICY_STATUS): BOOL; stdcall;
  TCertCreateCertificateChainEngineFunc = function(
    const AConfig: CERT_CHAIN_ENGINE_CONFIG; var AChainEngine: Pointer): BOOL; stdcall;
  TCertFreeCertificateChainEngineProc = procedure(AChainEngine: Pointer); stdcall;

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
    class function GetProc(const AName: AnsiString): Pointer; static;
    class procedure CollectStore(AStoreName: PWideChar;
      const AExclude: TDictionary<TBytes, Boolean>;
      const ADest: TList<TBytes>); static;
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
    /// <summary>The raw DER of the ROOT and CA stores minus the Disallowed store.
    /// Validation and de-duplication are the caller's responsibility.</summary>
    class function HarvestAnchors: TArray<TBytes>; static;
    /// <summary>Runs the OS SSL-server chain evaluation with URL retrieval cache-only,
    /// consuming the stapled OCSP response as cached revocation data, at the validation time
    /// AClock supplies (nil = system time). APosture governs an indeterminate revocation
    /// outcome (accept under Soft, reject under Hard; a definitive Revoked always rejects).
    /// Returns True when trusted; on rejection False with AAlert set to the matching fatal
    /// alert.</summary>
    class function EvaluateChain(const AChain: TArray<TBytes>;
      const AHostName: string; const AOcspStaple: TBytes;
      APosture: TRevocationPosture; const AClock: ITlsClock;
      out AAlert: TTlsAlertDescription): Boolean; static;
    /// <summary>Runs the OS chain evaluation for a peer CLIENT certificate against an
    /// exclusive-root engine built over AAnchors alone (never the OS/public roots), with the
    /// clientAuth EKU and the AUTHTYPE_CLIENT SSL policy. Same cache-only revocation, posture and
    /// clock handling as the server path (a client certificate is never stapled). Returns False
    /// with internal_error when the exclusive-engine entry point is unavailable.</summary>
    class function EvaluateClientChain(const AChain, AAnchors: TArray<TBytes>;
      APosture: TRevocationPosture; const AClock: ITlsClock;
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
    System.Assigned(FCertVerifyCertificateChainPolicy);
end;

class procedure TWindowsTrustApi.ReleaseDynamicImports;
begin
  if FModule <> 0 then
  begin
    FreeLibrary(FModule);
    FModule := 0;
  end;
end;

class procedure TWindowsTrustApi.CollectStore(AStoreName: PWideChar;
  const AExclude: TDictionary<TBytes, Boolean>; const ADest: TList<TBytes>);
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
      if (LContext^.cbCertEncoded > 0) and (LContext^.pbCertEncoded <> nil) then
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
    // Distrust first, so it can be subtracted from the trusted stores.
    CollectStore('Disallowed', nil, LDisallowed);
    LExclude := TDictionary<TBytes, Boolean>.Create;
    try
      for LI := 0 to LDisallowed.Count - 1 do
        LExclude.AddOrSetValue(LDisallowed[LI], True);
      LTrusted := TList<TBytes>.Create;
      try
        CollectStore('ROOT', LExclude, LTrusted);
        CollectStore('CA', LExclude, LTrusted);
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

class function TWindowsTrustApi.EvaluateChain(const AChain: TArray<TBytes>;
  const AHostName: string; const AOcspStaple: TBytes;
  APosture: TRevocationPosture; const AClock: ITlsClock;
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
    if APosture <> TRevocationPosture.Off then
      LFlags := LFlags or CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT or
        CERT_CHAIN_REVOCATION_ACCUMULATIVE_TIMEOUT;

    // the injected clock pins the validation time; nil defers to system time
    LTimePtr := nil;
    if AClock <> nil then
    begin
      LFileTime := UnixMillisToFileTime(AClock.NowUnixMillis);
      LTimePtr := @LFileTime;
    end;

    if not FCertGetCertificateChain(nil, LLeaf, LTimePtr, LStore, LChainPara,
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
      Result := True
    else
      Result := MapPolicyError(LStatus.dwError, APosture, AAlert);
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
    CERT_E_REVOKED:
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
  AAnchors: TArray<TBytes>; APosture: TRevocationPosture; const AClock: ITlsClock;
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
begin
  Result := False;
  AAlert := TTlsAlertDescription.BadCertificate;

  if Length(AChain) = 0 then
    Exit;

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
    if APosture <> TRevocationPosture.Off then
      LFlags := LFlags or CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT or
        CERT_CHAIN_REVOCATION_ACCUMULATIVE_TIMEOUT;

    LTimePtr := nil;
    if AClock <> nil then
    begin
      LFileTime := UnixMillisToFileTime(AClock.NowUnixMillis);
      LTimePtr := @LFileTime;
    end;

    if not FCertGetCertificateChain(LEngine, LLeaf, LTimePtr, LInterStore, LChainPara,
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
      Result := True
    else
      Result := MapPolicyError(LStatus.dwError, APosture, AAlert);
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

constructor TWindowsDelegateVerifier.Create(APosture: TRevocationPosture;
  const AClock: ITlsClock);
begin
  inherited Create;
  FPosture := APosture;
  FClock := AClock;
end;

function TWindowsDelegateVerifier.VerifyServerCertificate(const AChain: TArray<TBytes>;
  const AServerName: TServerName; const AOcspStaple: TBytes;
  out AAlert: TTlsAlertDescription): Boolean;
begin
  Result := TWindowsTrustApi.EvaluateChain(AChain, AServerName.ToString,
    AOcspStaple, FPosture, FClock, AAlert);
end;

{ TWindowsServerVerifierSource }

function TWindowsServerVerifierSource.CreateServerVerifier(
  const AContext: TServerTrustContext): IServerCertificateVerifier;
begin
  Result := TWindowsDelegateVerifier.Create(AContext.RevocationPosture,
    AContext.Clock) as IServerCertificateVerifier;
end;

{ TWindowsClientDelegateVerifier }

constructor TWindowsClientDelegateVerifier.Create(const AAnchors: TArray<TBytes>;
  APosture: TRevocationPosture; const AClock: ITlsClock);
begin
  inherited Create;
  FAnchors := AAnchors;
  FPosture := APosture;
  FClock := AClock;
end;

function TWindowsClientDelegateVerifier.VerifyClientCertificate(
  const AChain: TArray<TBytes>; out AAlert: TTlsAlertDescription): Boolean;
begin
  Result := TWindowsTrustApi.EvaluateClientChain(AChain, FAnchors, FPosture,
    FClock, AAlert);
end;

{ TWindowsClientVerifierSource }

function TWindowsClientVerifierSource.CreateClientVerifier(
  const AContext: TClientTrustContext): IClientCertificateVerifier;
var
  LAnchors: TArray<TBytes>;
begin
  LAnchors := nil;
  if AContext.TrustStore <> nil then
    LAnchors := AContext.TrustStore.RootCertificates;
  Result := TWindowsClientDelegateVerifier.Create(LAnchors,
    AContext.RevocationPosture, AContext.Clock) as IClientCertificateVerifier;
end;

initialization
  TWindowsTrustApi.ResolveDynamicImports;

finalization
  TWindowsTrustApi.ReleaseDynamicImports;

{$ENDIF}

end.
