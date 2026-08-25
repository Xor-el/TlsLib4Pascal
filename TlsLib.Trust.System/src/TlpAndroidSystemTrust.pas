{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpAndroidSystemTrust;

{$I ..\..\TlsLib\src\Include\TlsLib.inc}

interface

{$IF DEFINED(TLSLIB_ANDROID)}

uses
  SysUtils,
{$IFDEF FPC}
  jni,
{$ELSE}
  Androidapi.Jni,
{$ENDIF}
  TlpICryptoProvider,
  TlpICertificateTrust,
  TlpEndpointIdentity,
  TlpPosixDynLib,
  TlpTlsAlert;

type
  /// <summary>
  /// Delegates chain trust to the platform's Java engine over JNI - roots, revocation,
  /// network-security-config (per-domain trust, user-CA opt-in, pinning) - via
  /// android.net.http.X509TrustManagerExtensions.checkServerTrusted, then enforces RFC
  /// 6125 hostname identity in-library, because checkServerTrusted validates the chain
  /// but NOT the host (Android splits TrustManager from HostnameVerifier). Construction
  /// is init-independent; the JVM is acquired lazily inside Verify (Delphi resolves it
  /// automatically, FPC needs TlsLibAndroidInitTrust). Fail-closed.
  /// </summary>
  TAndroidDelegateVerifier = class sealed(TInterfacedObject, ICertificateVerifier)
  strict private
    FProvider: ICryptoProvider;
  public
    constructor Create(const AProvider: ICryptoProvider);
    function Verify(const AChain: TArray<TBytes>; const AHostName: string;
      const AOcspStaple: TBytes; out AAlert: TTlsAlertDescription): Boolean;
  end;

/// <summary>
/// Hands the library the running JavaVM, which lets Verify attach arbitrary (non-Java)
/// handshake threads. Idempotent - the first non-nil call wins. On Delphi it is called
/// automatically from this unit's initialization with System.JavaMachine (the RTL has set
/// it by then), so a NativeActivity app needs nothing. On FPC it is REQUIRED (no RTL handle
/// to auto-resolve): call it once with the JavaVM from your JNI_OnLoad, or Verify fails closed.
/// </summary>
procedure TlsLibAndroidInitTrust(AJavaVM: Pointer);

{$IFEND}

implementation

{$IF DEFINED(TLSLIB_ANDROID)}

const
  ANDROID_LOG_ERROR = 6;
  ANDROID_LOG_LIB = 'liblog.so';

type
  // __android_log_write(prio, tag, text): a malformed runtime or use-before-init cannot
  // travel through the boolean seam, so the guidance reaches the developer through logcat
  // instead - it never affects the verdict.
  TAndroidLogWriteFunc = function(APrio: Integer; const ATag: PAnsiChar;
    const AText: PAnsiChar): Integer; cdecl;

type
  // Neutral aliases over the two compilers' JNI primitive names (FPC's lower-case
  // jobject/jclass/... vs Delphi's JNIObject/JNIClass/...) so one body serves both.
{$IFDEF FPC}
  TJObject = jobject;
  TJClass = jclass;
  TJString = jstring;
  TJThrowable = jthrowable;
  TJMethodID = jmethodID;
  TJByteArray = jbyteArray;
  TJObjectArray = jobjectArray;
  TJValue = jvalue;
  TJInt = jint;
  TJSize = jsize;
  PJByteN = Pjbyte;
{$ELSE}
  TJObject = JNIObject;
  TJClass = JNIClass;
  TJString = JNIString;
  TJThrowable = JNIThrowable;
  TJMethodID = JNIMethodID;
  TJByteArray = JNIByteArray;
  TJObjectArray = JNIObjectArray;
  TJValue = JNIValue;
  TJInt = JNIInt;
  TJSize = JNISize;
  PJByteN = PJNIByte;
{$ENDIF}

  /// <summary>
  /// The JNI machinery for the delegate: a one-shot capture of the JavaVM, thread
  /// attach/detach, and the chain build + trust call. State is process-wide; every
  /// local ref lives inside a JNI local frame reclaimed on the way out.
  /// </summary>
  TAndroidTrustApi = class sealed
  strict private
  class var
    FJavaVM: PJavaVM;
    FLogLibHandle: NativeUInt;
    FLogWrite: TAndroidLogWriteFunc;
    class procedure ClearPending(AEnv: PJNIEnv); static;
    class procedure LogError(const AMsg: string); static;
    class function TryGetVm(out AVm: PJavaVM): Boolean; static;
    class function AttachEnv(AVm: PJavaVM; out AEnv: PJNIEnv;
      out AAttached: Boolean): Boolean; static;
    class function BuildChainArray(AEnv: PJNIEnv; const AChain: TArray<TBytes>;
      out AAlert: TTlsAlertDescription): TJObjectArray; static;
    class function DeriveAuthType(AEnv: PJNIEnv; ALeaf: TJObject): string; static;
    class function DefaultX509TrustManager(AEnv: PJNIEnv): TJObject; static;
    class function MapPendingException(AEnv: PJNIEnv): TTlsAlertDescription; static;
  public
    class procedure ResolveDynamicImports; static;
    class procedure ReleaseDynamicImports; static;
    class procedure Capture(AJavaVM: Pointer); static;
    /// <summary>Runs the platform CHAIN trust decision for the peer chain with no network
    /// fetch of our own (hostname identity is enforced by the caller). Returns True when
    /// the OS trusts the chain; on rejection or any failure returns False with AAlert set
    /// to the matching fatal alert.</summary>
    class function Evaluate(const AChain: TArray<TBytes>; const AHostName: string;
      out AAlert: TTlsAlertDescription): Boolean; static;
  end;

{ TAndroidTrustApi }

class procedure TAndroidTrustApi.ClearPending(AEnv: PJNIEnv);
begin
  if AEnv^^.ExceptionCheck(AEnv) <> 0 then
    AEnv^^.ExceptionClear(AEnv);
end;

class procedure TAndroidTrustApi.ResolveDynamicImports;
begin
  // liblog exports __android_log_write; an absent library or symbol leaves FLogWrite nil
  FLogLibHandle := TPosixDynLib.Open(ANDROID_LOG_LIB);
  FLogWrite := TAndroidLogWriteFunc(
    TPosixDynLib.Resolve(FLogLibHandle, '__android_log_write'));
end;

class procedure TAndroidTrustApi.ReleaseDynamicImports;
begin
  FLogWrite := nil;
  TPosixDynLib.Close(FLogLibHandle);
  FLogLibHandle := 0;
end;

class procedure TAndroidTrustApi.LogError(const AMsg: string);
var
  LUtf8: UTF8String;
begin
  // best-effort diagnostic: a runtime without the resolved symbol simply logs nothing
  if not Assigned(FLogWrite) then
    Exit;
  LUtf8 := UTF8String(AMsg);
  FLogWrite(ANDROID_LOG_ERROR, 'TlsLib', PAnsiChar(LUtf8));
end;

class procedure TAndroidTrustApi.Capture(AJavaVM: Pointer);
begin
  // The JavaVM is captured once at startup - from this unit's initialization on Delphi, or
  // from the caller's JNI_OnLoad on FPC - never during a handshake. So a first-non-nil-wins
  // write over an atomic pointer needs no lock: the startup write happens-before every later
  // handshake thread (each created afterwards), so all Verify reads observe it. Only the
  // JavaVM is needed; no Android Context (the default trust manager already carries the app's
  // network-security-config, and a global ref to a Context would risk pinning the Activity).
  if FJavaVM = nil then
    FJavaVM := PJavaVM(AJavaVM);
end;

class function TAndroidTrustApi.TryGetVm(out AVm: PJavaVM): Boolean;
begin
  AVm := FJavaVM;
  Result := FJavaVM <> nil;
end;

class function TAndroidTrustApi.AttachEnv(AVm: PJavaVM; out AEnv: PJNIEnv;
  out AAttached: Boolean): Boolean;
var
  LEnvRaw: Pointer;
  LStatus: TJInt;
begin
  Result := False;
  AEnv := nil;
  AAttached := False;
  LEnvRaw := nil;
  LStatus := AVm^^.GetEnv(AVm, @LEnvRaw, JNI_VERSION_1_6);
  if LStatus = JNI_OK then
  begin
    AEnv := PJNIEnv(LEnvRaw);
    Result := AEnv <> nil;
    Exit;
  end;
  if LStatus = JNI_EDETACHED then
  begin
    if AVm^^.AttachCurrentThread(AVm, @LEnvRaw, nil) = JNI_OK then
    begin
      AEnv := PJNIEnv(LEnvRaw);
      AAttached := True;
      Result := AEnv <> nil;
    end;
  end;
end;

class function TAndroidTrustApi.BuildChainArray(AEnv: PJNIEnv;
  const AChain: TArray<TBytes>; out AAlert: TTlsAlertDescription): TJObjectArray;
var
  LCfClass, LX509Class, LBaisClass: TJClass;
  LGetInstance, LGenerate, LBaisCtor: TJMethodID;
  LFactory, LStream, LCert: TJObject;
  LTypeStr: TJString;
  LByteArr: TJByteArray;
  LArr: TJObjectArray;
  LArgs: array [0 .. 0] of TJValue;
  LI: Integer;
begin
  Result := nil;
  // A missing framework class/method means a runtime we do not understand.
  AAlert := TTlsAlertDescription.InternalError;

  LCfClass := AEnv^^.FindClass(AEnv, 'java/security/cert/CertificateFactory');
  LX509Class := AEnv^^.FindClass(AEnv, 'java/security/cert/X509Certificate');
  LBaisClass := AEnv^^.FindClass(AEnv, 'java/io/ByteArrayInputStream');
  if (LCfClass = nil) or (LX509Class = nil) or (LBaisClass = nil) then
  begin
    ClearPending(AEnv);
    Exit;
  end;

  LGetInstance := AEnv^^.GetStaticMethodID(AEnv, LCfClass, 'getInstance',
    '(Ljava/lang/String;)Ljava/security/cert/CertificateFactory;');
  LGenerate := AEnv^^.GetMethodID(AEnv, LCfClass, 'generateCertificate',
    '(Ljava/io/InputStream;)Ljava/security/cert/Certificate;');
  LBaisCtor := AEnv^^.GetMethodID(AEnv, LBaisClass, '<init>', '([B)V');
  if (LGetInstance = nil) or (LGenerate = nil) or (LBaisCtor = nil) then
    Exit;

  LTypeStr := AEnv^^.NewStringUTF(AEnv, 'X.509');
  LArgs[0].l := LTypeStr;
  LFactory := AEnv^^.CallStaticObjectMethodA(AEnv, LCfClass, LGetInstance,
    @LArgs[0]);
  if (LFactory = nil) or (AEnv^^.ExceptionCheck(AEnv) <> 0) then
  begin
    ClearPending(AEnv);
    Exit;
  end;

  LArr := AEnv^^.NewObjectArray(AEnv, Length(AChain), LX509Class, nil);
  if LArr = nil then
    Exit;

  for LI := 0 to Length(AChain) - 1 do
  begin
    if Length(AChain[LI]) = 0 then
    begin
      AAlert := TTlsAlertDescription.BadCertificate;
      Exit;
    end;
    LByteArr := AEnv^^.NewByteArray(AEnv, Length(AChain[LI]));
    if LByteArr = nil then
      Exit;
    AEnv^^.SetByteArrayRegion(AEnv, LByteArr, 0, Length(AChain[LI]),
      PJByteN(@AChain[LI][0]));
    LArgs[0].l := LByteArr;
    LStream := AEnv^^.NewObjectA(AEnv, LBaisClass, LBaisCtor, @LArgs[0]);
    if LStream = nil then
    begin
      AEnv^^.DeleteLocalRef(AEnv, LByteArr);
      Exit;
    end;
    LArgs[0].l := LStream;
    LCert := AEnv^^.CallObjectMethodA(AEnv, LFactory, LGenerate, @LArgs[0]);
    if (LCert = nil) or (AEnv^^.ExceptionCheck(AEnv) <> 0) then
    begin
      // An unparseable peer certificate is a bad certificate, not a broken runtime.
      ClearPending(AEnv);
      AEnv^^.DeleteLocalRef(AEnv, LStream);
      AEnv^^.DeleteLocalRef(AEnv, LByteArr);
      AAlert := TTlsAlertDescription.BadCertificate;
      Exit;
    end;
    AEnv^^.SetObjectArrayElement(AEnv, LArr, LI, LCert);
    // The array now holds the cert; drop the per-iteration local refs so they do not
    // accumulate across a long chain (keeps local-ref use O(1), not O(chain length)).
    AEnv^^.DeleteLocalRef(AEnv, LCert);
    AEnv^^.DeleteLocalRef(AEnv, LStream);
    AEnv^^.DeleteLocalRef(AEnv, LByteArr);
  end;
  Result := LArr;
end;

class function TAndroidTrustApi.DeriveAuthType(AEnv: PJNIEnv;
  ALeaf: TJObject): string;
var
  LX509Class, LKeyClass: TJClass;
  LGetPubKey, LGetAlg: TJMethodID;
  LPubKey, LAlgStr: TJObject;
  LChars: PAnsiChar;
  LAlg: string;
begin
  // Conscrypt only needs authType non-empty; a mismatch fails closed, never open, so
  // deriving it is about honesty. RSA is the battle-tested default for exotic keys.
  Result := 'RSA';
  if ALeaf = nil then
    Exit;

  LX509Class := AEnv^^.FindClass(AEnv, 'java/security/cert/X509Certificate');
  if LX509Class = nil then
  begin
    ClearPending(AEnv);
    Exit;
  end;
  LGetPubKey := AEnv^^.GetMethodID(AEnv, LX509Class, 'getPublicKey',
    '()Ljava/security/PublicKey;');
  if LGetPubKey = nil then
    Exit;
  LPubKey := AEnv^^.CallObjectMethodA(AEnv, ALeaf, LGetPubKey, nil);
  if (LPubKey = nil) or (AEnv^^.ExceptionCheck(AEnv) <> 0) then
  begin
    ClearPending(AEnv);
    Exit;
  end;

  LKeyClass := AEnv^^.FindClass(AEnv, 'java/security/PublicKey');
  if LKeyClass = nil then
  begin
    ClearPending(AEnv);
    Exit;
  end;
  LGetAlg := AEnv^^.GetMethodID(AEnv, LKeyClass, 'getAlgorithm',
    '()Ljava/lang/String;');
  if LGetAlg = nil then
    Exit;
  LAlgStr := AEnv^^.CallObjectMethodA(AEnv, LPubKey, LGetAlg, nil);
  if (LAlgStr = nil) or (AEnv^^.ExceptionCheck(AEnv) <> 0) then
  begin
    ClearPending(AEnv);
    Exit;
  end;

  LChars := AEnv^^.GetStringUTFChars(AEnv, LAlgStr, nil);
  if LChars = nil then
    Exit;
  try
    LAlg := string(AnsiString(LChars));
  finally
    AEnv^^.ReleaseStringUTFChars(AEnv, LAlgStr, LChars);
  end;
  if (LAlg = 'RSA') or (LAlg = 'EC') or (LAlg = 'DSA') then
    Result := LAlg;
end;

class function TAndroidTrustApi.DefaultX509TrustManager(AEnv: PJNIEnv): TJObject;
var
  LTmfClass, LX509TmClass: TJClass;
  LGetDefAlg, LGetInstance, LInit, LGetTms: TJMethodID;
  LAlgStr, LFactory, LTm: TJObject;
  LTms: TJObjectArray;
  LArgs: array [0 .. 0] of TJValue;
  LCount, LI: TJSize;
begin
  Result := nil;

  LTmfClass := AEnv^^.FindClass(AEnv, 'javax/net/ssl/TrustManagerFactory');
  LX509TmClass := AEnv^^.FindClass(AEnv, 'javax/net/ssl/X509TrustManager');
  if (LTmfClass = nil) or (LX509TmClass = nil) then
  begin
    ClearPending(AEnv);
    Exit;
  end;

  LGetDefAlg := AEnv^^.GetStaticMethodID(AEnv, LTmfClass, 'getDefaultAlgorithm',
    '()Ljava/lang/String;');
  LGetInstance := AEnv^^.GetStaticMethodID(AEnv, LTmfClass, 'getInstance',
    '(Ljava/lang/String;)Ljavax/net/ssl/TrustManagerFactory;');
  LInit := AEnv^^.GetMethodID(AEnv, LTmfClass, 'init',
    '(Ljava/security/KeyStore;)V');
  LGetTms := AEnv^^.GetMethodID(AEnv, LTmfClass, 'getTrustManagers',
    '()[Ljavax/net/ssl/TrustManager;');
  if (LGetDefAlg = nil) or (LGetInstance = nil) or (LInit = nil) or
    (LGetTms = nil) then
    Exit;

  LAlgStr := AEnv^^.CallStaticObjectMethodA(AEnv, LTmfClass, LGetDefAlg, nil);
  if (LAlgStr = nil) or (AEnv^^.ExceptionCheck(AEnv) <> 0) then
  begin
    ClearPending(AEnv);
    Exit;
  end;
  LArgs[0].l := LAlgStr;
  LFactory := AEnv^^.CallStaticObjectMethodA(AEnv, LTmfClass, LGetInstance,
    @LArgs[0]);
  if (LFactory = nil) or (AEnv^^.ExceptionCheck(AEnv) <> 0) then
  begin
    ClearPending(AEnv);
    Exit;
  end;

  // init(null) selects the platform's system trust store.
  LArgs[0].l := nil;
  AEnv^^.CallVoidMethodA(AEnv, LFactory, LInit, @LArgs[0]);
  if AEnv^^.ExceptionCheck(AEnv) <> 0 then
  begin
    ClearPending(AEnv);
    Exit;
  end;

  LTms := AEnv^^.CallObjectMethodA(AEnv, LFactory, LGetTms, nil);
  if (LTms = nil) or (AEnv^^.ExceptionCheck(AEnv) <> 0) then
  begin
    ClearPending(AEnv);
    Exit;
  end;

  LCount := AEnv^^.GetArrayLength(AEnv, LTms);
  for LI := 0 to LCount - 1 do
  begin
    LTm := AEnv^^.GetObjectArrayElement(AEnv, LTms, LI);
    if (LTm <> nil) and (AEnv^^.IsInstanceOf(AEnv, LTm, LX509TmClass) <> 0) then
    begin
      Result := LTm;
      Exit;
    end;
  end;
end;

class function TAndroidTrustApi.MapPendingException(AEnv: PJNIEnv)
  : TTlsAlertDescription;
var
  LExc: TJThrowable;
  LClass: TJClass;
begin
  // A pending exception aborts the next JNI call, so capture then clear immediately.
  Result := TTlsAlertDescription.UnknownCa;
  LExc := AEnv^^.ExceptionOccurred(AEnv);
  AEnv^^.ExceptionClear(AEnv);
  if LExc = nil then
    Exit;

  // Refine only the two cheaply inspectable cases; every other reason (and the common
  // CertificateException wrapper) stays unknown_ca - a rejection is never softened.
  LClass := AEnv^^.FindClass(AEnv,
    'java/security/cert/CertificateExpiredException');
  if (LClass <> nil) and (AEnv^^.IsInstanceOf(AEnv, LExc, LClass) <> 0) then
  begin
    Result := TTlsAlertDescription.CertificateExpired;
    ClearPending(AEnv);
    Exit;
  end;

  LClass := AEnv^^.FindClass(AEnv,
    'java/security/cert/CertificateNotYetValidException');
  if (LClass <> nil) and (AEnv^^.IsInstanceOf(AEnv, LExc, LClass) <> 0) then
    Result := TTlsAlertDescription.CertificateExpired;
  ClearPending(AEnv);
end;

class function TAndroidTrustApi.Evaluate(const AChain: TArray<TBytes>;
  const AHostName: string; out AAlert: TTlsAlertDescription): Boolean;
var
  LVm: PJavaVM;
  LEnv: PJNIEnv;
  LAttached: Boolean;
  LExtClass, LTmClass: TJClass;
  LExtCtor, LCheck: TJMethodID;
  LX509Tm, LExtObj, LChainArr, LLeaf, LAuthStr, LHostStr: TJObject;
  LAuthUtf8, LHostUtf8: UTF8String;
  LBuildAlert: TTlsAlertDescription;
  LOneArg: array [0 .. 0] of TJValue;
  LCheckArgs: array [0 .. 2] of TJValue;
begin
  Result := False;
  AAlert := TTlsAlertDescription.InternalError;

  if Length(AChain) = 0 then
  begin
    AAlert := TTlsAlertDescription.BadCertificate;
    Exit;
  end;

  if not TryGetVm(LVm) then
  begin
    LogError('could not acquire a JavaVM; call TlsLibAndroidInitTrust(javaVM) at ' +
      'startup (FPC: from your JNI_OnLoad)');
    Exit;
  end;

  if not AttachEnv(LVm, LEnv, LAttached) then
  begin
    LogError('could not obtain a JNIEnv for the current thread');
    Exit;
  end;
  try
    // One local frame reclaims every ref the chain build and trust call create.
    if LEnv^^.PushLocalFrame(LEnv, 16 + Length(AChain) * 4) <> 0 then
    begin
      ClearPending(LEnv);
      Exit;
    end;
    try
      LChainArr := BuildChainArray(LEnv, AChain, LBuildAlert);
      if LChainArr = nil then
      begin
        AAlert := LBuildAlert;
        Exit;
      end;

      LLeaf := LEnv^^.GetObjectArrayElement(LEnv, LChainArr, 0);
      LAuthUtf8 := UTF8String(DeriveAuthType(LEnv, LLeaf));
      LAuthStr := LEnv^^.NewStringUTF(LEnv, PAnsiChar(LAuthUtf8));

      LX509Tm := DefaultX509TrustManager(LEnv);
      if LX509Tm = nil then
        Exit;

      if AHostName <> '' then
      begin
        // Primary path: X509TrustManagerExtensions also applies the app's
        // network-security-config and pinning; plain checkServerTrusted does not.
        LExtClass := LEnv^^.FindClass(LEnv,
          'android/net/http/X509TrustManagerExtensions');
        if LExtClass = nil then
        begin
          ClearPending(LEnv);
          Exit;
        end;
        LExtCtor := LEnv^^.GetMethodID(LEnv, LExtClass, '<init>',
          '(Ljavax/net/ssl/X509TrustManager;)V');
        LCheck := LEnv^^.GetMethodID(LEnv, LExtClass, 'checkServerTrusted',
          '([Ljava/security/cert/X509Certificate;Ljava/lang/String;' +
          'Ljava/lang/String;)Ljava/util/List;');
        if (LExtCtor = nil) or (LCheck = nil) then
          Exit;
        LOneArg[0].l := LX509Tm;
        LExtObj := LEnv^^.NewObjectA(LEnv, LExtClass, LExtCtor, @LOneArg[0]);
        if (LExtObj = nil) or (LEnv^^.ExceptionCheck(LEnv) <> 0) then
        begin
          ClearPending(LEnv);
          Exit;
        end;
        LHostUtf8 := UTF8String(AHostName);
        LHostStr := LEnv^^.NewStringUTF(LEnv, PAnsiChar(LHostUtf8));
        LCheckArgs[0].l := LChainArr;
        LCheckArgs[1].l := LAuthStr;
        LCheckArgs[2].l := LHostStr;
        LEnv^^.CallObjectMethodA(LEnv, LExtObj, LCheck, @LCheckArgs[0]);
      end
      else
      begin
        // No host (server-by-IP / mutual-TLS peer cert): plain check, still the OS
        // decision but without host binding - mirrors the Apple delegate's empty-host
        // SecPolicyCreateSSL(True, nil). No per-domain NSC/pin lookup applies here.
        LTmClass := LEnv^^.FindClass(LEnv, 'javax/net/ssl/X509TrustManager');
        if LTmClass = nil then
        begin
          ClearPending(LEnv);
          Exit;
        end;
        LCheck := LEnv^^.GetMethodID(LEnv, LTmClass, 'checkServerTrusted',
          '([Ljava/security/cert/X509Certificate;Ljava/lang/String;)V');
        if LCheck = nil then
          Exit;
        LCheckArgs[0].l := LChainArr;
        LCheckArgs[1].l := LAuthStr;
        LEnv^^.CallVoidMethodA(LEnv, LX509Tm, LCheck, @LCheckArgs[0]);
      end;

      if LEnv^^.ExceptionCheck(LEnv) <> 0 then
        AAlert := MapPendingException(LEnv)
      else
        Result := True;
    finally
      // Never let a pending JNI exception (e.g. a NoSuchMethodError from a bailed lookup)
      // leak into the caller's thread, which would break its next JNI call when the
      // thread was already attached and we do not detach it below.
      ClearPending(LEnv);
      LEnv^^.PopLocalFrame(LEnv, nil);
    end;
  finally
    if LAttached then
      LVm^^.DetachCurrentThread(LVm);
  end;
end;

{ TAndroidDelegateVerifier }

constructor TAndroidDelegateVerifier.Create(const AProvider: ICryptoProvider);
begin
  inherited Create;
  FProvider := AProvider;
end;

function TAndroidDelegateVerifier.Verify(const AChain: TArray<TBytes>;
  const AHostName: string; const AOcspStaple: TBytes;
  out AAlert: TTlsAlertDescription): Boolean;
begin
  // AOcspStaple is ignored: Android runs its own revocation inside the trust engine.
  Result := TAndroidTrustApi.Evaluate(AChain, AHostName, AAlert);
  if not Result then
    Exit;
  // The OS engine validates the chain but NOT the hostname (Android separates
  // X509TrustManager from HostnameVerifier), so enforce RFC 6125 endpoint identity with
  // the library's own matcher. An empty host skips it, mirroring the iOS delegate. A nil
  // provider cannot match, so it fails closed rather than trusting blindly.
  if AHostName <> '' then
    if (FProvider = nil) or
      (not TEndpointIdentity.Matches(AHostName,
      FProvider.Certificates.DnsNames(AChain[0]),
      FProvider.Certificates.IpAddresses(AChain[0]))) then
    begin
      Result := False;
      AAlert := TTlsAlertDescription.BadCertificate;
    end;
end;

procedure TlsLibAndroidInitTrust(AJavaVM: Pointer);
begin
  TAndroidTrustApi.Capture(AJavaVM);
end;

initialization

  TAndroidTrustApi.ResolveDynamicImports;

{$IFNDEF FPC}
  // Delphi: the RTL sets System.JavaMachine (in ANativeActivity_onCreate) before this unit
  // initializes, so capturing it here makes a NativeActivity app zero-config. FPC has no
  // such global - its caller passes the JavaVM from JNI_OnLoad.
  TlsLibAndroidInitTrust(System.JavaMachine);
{$ENDIF}

finalization

  TAndroidTrustApi.ReleaseDynamicImports;

{$IFEND}

end.
