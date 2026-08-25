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
{$IFDEF FPC}
  Windows,
{$ELSE}
  Winapi.Windows,
{$ENDIF}
  Generics.Collections,
  SysUtils,
  TlpTlsAlert,
  TlpICertificateTrust,
  TlpSystemTrustBase;

type
  /// <summary>
  /// Harvests the Windows machine/user trust anchors from the "ROOT" and "CA"
  /// system stores, subtracting any certificate present in the "Disallowed" store
  /// so OS distrust is honored. Emits neutral DER.
  /// </summary>
  TWindowsAnchorStore = class sealed(TSystemTrustBase)
  strict protected
    function HarvestRoots: TArray<TBytes>; override;
    function SourceName: string; override;
  end;

  /// <summary>
  /// Delegates verification to the Windows chain engine: builds the chain with URL
  /// retrieval forced cache-only (no socket), then applies the SSL server policy
  /// (server-auth EKU + host name). Fail-closed; maps the policy error to the
  /// matching fatal alert.
  /// </summary>
  TWindowsDelegateVerifier = class sealed(TInterfacedObject, ICertificateVerifier)
  public
    function Verify(const AChain: TArray<TBytes>; const AHostName: string;
      const AOcspStaple: TBytes; out AAlert: TTlsAlertDescription): Boolean;
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

  USAGE_MATCH_TYPE_AND = $00000000;
  AUTHTYPE_SERVER = 2;
  CERT_CHAIN_POLICY_SSL = PAnsiChar(4);

  SZOID_PKIX_KP_SERVER_AUTH: PAnsiChar = '1.3.6.1.5.5.7.3.1';

  // CertVerifyCertificateChainPolicy dwError values worth mapping precisely.
  CERT_E_EXPIRED = DWORD($800B0101);
  CERT_E_VALIDITYPERIODNESTING = DWORD($800B0102);
  CERT_E_UNTRUSTEDROOT = DWORD($800B0109);
  CERT_E_CHAINING = DWORD($800B010A);
  CERT_E_REVOKED = DWORD($800B010C);
  CERT_E_WRONG_USAGE = DWORD($800B0110);
  CERT_E_UNTRUSTEDCA = DWORD($800B0112);
  TRUST_E_CERT_SIGNATURE = DWORD($80096004);

type
  HCERTSTORE = Pointer;

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
    FCertOpenStore: TCertOpenStoreFunc;
    FCertAddEncodedCertificateToStore: TCertAddEncodedCertificateToStoreFunc;
    FCertGetCertificateChain: TCertGetCertificateChainFunc;
    FCertFreeCertificateChain: TCertFreeCertificateChainProc;
    FCertVerifyCertificateChainPolicy: TCertVerifyCertificateChainPolicyFunc;
    class function GetProc(const AName: AnsiString): Pointer; static;
    class procedure CollectStore(AStoreName: PWideChar;
      const AExclude: TDictionary<TBytes, Boolean>;
      const ADest: TList<TBytes>); static;
  private
    class procedure ResolveDynamicImports; static;
    /// <summary>Frees the loaded crypt32 module (unit teardown).</summary>
    class procedure ReleaseDynamicImports; static;
    /// <summary>The raw DER of the ROOT and CA stores minus the Disallowed store.
    /// Validation and de-duplication are the caller's responsibility.</summary>
    class function HarvestAnchors: TArray<TBytes>; static;
    /// <summary>Runs the OS SSL-server chain evaluation with URL retrieval
    /// cache-only. Returns True when trusted; on rejection False with AAlert set to
    /// the matching fatal alert.</summary>
    class function EvaluateChain(const AChain: TArray<TBytes>;
      const AHostName: string; out AAlert: TTlsAlertDescription): Boolean; static;
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
  FCertOpenStore := TCertOpenStoreFunc(GetProc('CertOpenStore'));
  FCertAddEncodedCertificateToStore := TCertAddEncodedCertificateToStoreFunc(
    GetProc('CertAddEncodedCertificateToStore'));
  FCertGetCertificateChain := TCertGetCertificateChainFunc(
    GetProc('CertGetCertificateChain'));
  FCertFreeCertificateChain := TCertFreeCertificateChainProc(
    GetProc('CertFreeCertificateChain'));
  FCertVerifyCertificateChainPolicy := TCertVerifyCertificateChainPolicyFunc(
    GetProc('CertVerifyCertificateChainPolicy'));

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

class function TWindowsTrustApi.EvaluateChain(const AChain: TArray<TBytes>;
  const AHostName: string; out AAlert: TTlsAlertDescription): Boolean;
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

    if not FCertGetCertificateChain(nil, LLeaf, nil, LStore, LChainPara,
      CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL, nil, LChain) then
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
    begin
      Result := True;
      Exit;
    end;

    case LStatus.dwError of
      CERT_E_EXPIRED, CERT_E_VALIDITYPERIODNESTING:
        AAlert := TTlsAlertDescription.CertificateExpired;
      CERT_E_UNTRUSTEDROOT, CERT_E_UNTRUSTEDCA, CERT_E_CHAINING,
        TRUST_E_CERT_SIGNATURE:
        AAlert := TTlsAlertDescription.UnknownCa;
      CERT_E_REVOKED:
        AAlert := TTlsAlertDescription.CertificateRevoked;
      CERT_E_WRONG_USAGE:
        AAlert := TTlsAlertDescription.UnsupportedCertificate;
    else
      // CERT_E_CN_NO_MATCH and everything else map to bad_certificate.
      AAlert := TTlsAlertDescription.BadCertificate;
    end;
  finally
    if LChain <> nil then
      FCertFreeCertificateChain(LChain);
    if LStore <> nil then
      FCertCloseStore(LStore, 0);
    FCertFreeCertificateContext(LLeaf);
  end;
end;

{ TWindowsAnchorStore }

function TWindowsAnchorStore.HarvestRoots: TArray<TBytes>;
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

function TWindowsAnchorStore.SourceName: string;
begin
  Result := 'Windows';
end;

{ TWindowsDelegateVerifier }

function TWindowsDelegateVerifier.Verify(const AChain: TArray<TBytes>;
  const AHostName: string; const AOcspStaple: TBytes;
  out AAlert: TTlsAlertDescription): Boolean;
begin
  Result := TWindowsTrustApi.EvaluateChain(AChain, AHostName, AAlert);
end;

initialization
  TWindowsTrustApi.ResolveDynamicImports;

finalization
  TWindowsTrustApi.ReleaseDynamicImports;

{$ENDIF}

end.
