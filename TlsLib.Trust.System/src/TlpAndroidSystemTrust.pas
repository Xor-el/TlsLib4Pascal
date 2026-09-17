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
  TlpICertificateVerifierSource,
  TlpCertificateVerifier,
  TlpTrustPolicy,
  TlpIClock,
  TlpEndpointIdentity,
  TlpServerName,
  TlpPosixDynLib,
  TlpTlsAlert;

type
  /// <summary>
  /// Delegates chain trust to the platform's Java engine over JNI - roots, revocation,
  /// network-security-config (per-domain trust, user-CA opt-in, pinning) - via
  /// android.net.http.X509TrustManagerExtensions.checkServerTrusted. The platform TrustManager
  /// does not consult a stapled OCSP response, so a revocation post-check over the injected
  /// provider and clock decides the staple (a definitive Revoked always rejects; an indeterminate
  /// outcome rejects only under a Hard posture) - run before the RFC 6125 hostname identity so a
  /// revoked certificate is not masked by a name mismatch. Hostname identity is enforced
  /// in-library because checkServerTrusted validates the chain but NOT the host (Android splits
  /// TrustManager from HostnameVerifier). Construction is init-independent; the JVM is acquired
  /// lazily inside Verify (Delphi resolves it automatically, FPC needs TlsLibAndroidInitTrust).
  /// Fail-closed.
  /// </summary>
  TAndroidDelegateVerifier = class sealed(TInterfacedObject, IServerCertificateVerifier)
  strict private
    FProvider: ICryptoProvider;
    FPosture: TRevocationPosture;
    FClock: ITlsClock;
  public
    constructor Create(const AProvider: ICryptoProvider;
      APosture: TRevocationPosture; const AClock: ITlsClock);
    function VerifyServerCertificate(const AChain: TArray<TBytes>;
      const AServerName: TServerName; const AOcspStaple: TBytes;
      out AAlert: TTlsAlertDescription): Boolean;
  end;

  /// <summary>
  /// The Android server-certificate verifier source: builds a delegate from the connection's
  /// trust context, so the provider, revocation posture and clock (the staple post-check) are
  /// injected the same way the built-in verifier receives them.
  /// </summary>
  TAndroidServerVerifierSource = class sealed(TInterfacedObject,
    IServerCertificateVerifierSource)
  public
    function CreateServerVerifier(const AContext: TServerTrustContext)
      : IServerCertificateVerifier;
  end;

  /// <summary>
  /// Verifies a peer CLIENT certificate (mTLS) via the platform's Java engine, restricted to an
  /// exclusive trust root built from the configured client-CA anchors alone - a KeyStore holding
  /// only those anchors, never the OS or public-web-PKI roots. Applies the platform's client-auth
  /// chain check (checkClientTrusted); a client certificate is not stapled. Fail-closed.
  /// </summary>
  TAndroidClientDelegateVerifier = class sealed(TInterfacedObject,
    IClientCertificateVerifier)
  strict private
    FAnchors: TArray<TBytes>;
  public
    constructor Create(const AAnchors: TArray<TBytes>);
    function VerifyClientCertificate(const AChain: TArray<TBytes>;
      out AAlert: TTlsAlertDescription): Boolean;
  end;

  /// <summary>
  /// The Android client-certificate verifier source: builds a client delegate over the client-CA
  /// anchors in the context (the exclusive trust root).
  /// </summary>
  TAndroidClientVerifierSource = class sealed(TInterfacedObject,
    IClientCertificateVerifierSource)
  public
    function CreateClientVerifier(const AContext: TClientTrustContext)
      : IClientCertificateVerifier;
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
    /// <summary>The platform X509TrustManager over AKeyStore: nil selects the system trust store
    /// (the server path), a KeyStore of client-CA anchors selects an exclusive private root (the
    /// client-auth path) - so the client path never falls back to the system roots.</summary>
    class function DefaultX509TrustManager(AEnv: PJNIEnv;
      AKeyStore: TJObject): TJObject; static;
    /// <summary>An empty KeyStore holding only the anchor certificates (each under a unique
    /// alias), the exclusive private trust root for client-auth. Nil on any failure.</summary>
    class function BuildAnchorKeyStore(AEnv: PJNIEnv;
      AAnchorArr: TJObjectArray): TJObject; static;
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
    /// <summary>Runs the platform client-auth trust decision for the peer CLIENT chain against a
    /// KeyStore of the configured client-CA anchors alone (checkClientTrusted) - never the system
    /// roots. Zero anchors reject before the engine. Returns True when trusted; on rejection or
    /// any failure returns False with AAlert set.</summary>
    class function EvaluateClient(const AChain, AAnchors: TArray<TBytes>;
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

class function TAndroidTrustApi.DefaultX509TrustManager(AEnv: PJNIEnv;
  AKeyStore: TJObject): TJObject;
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

  // init(keystore): a nil KeyStore selects the platform's system trust store; a KeyStore of
  // client-CA anchors selects that exclusive private root
  LArgs[0].l := AKeyStore;
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

      LX509Tm := DefaultX509TrustManager(LEnv, nil);
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

class function TAndroidTrustApi.BuildAnchorKeyStore(AEnv: PJNIEnv;
  AAnchorArr: TJObjectArray): TJObject;
var
  LKsClass: TJClass;
  LGetDefType, LGetInstance, LLoad, LSetEntry: TJMethodID;
  LTypeStr, LKeyStore, LCert, LAlias: TJObject;
  LArgs: array [0 .. 1] of TJValue;
  LCount, LI: TJSize;
  LAliasUtf8: UTF8String;
begin
  Result := nil;

  LKsClass := AEnv^^.FindClass(AEnv, 'java/security/KeyStore');
  if LKsClass = nil then
  begin
    ClearPending(AEnv);
    Exit;
  end;
  LGetDefType := AEnv^^.GetStaticMethodID(AEnv, LKsClass, 'getDefaultType',
    '()Ljava/lang/String;');
  LGetInstance := AEnv^^.GetStaticMethodID(AEnv, LKsClass, 'getInstance',
    '(Ljava/lang/String;)Ljava/security/KeyStore;');
  LLoad := AEnv^^.GetMethodID(AEnv, LKsClass, 'load',
    '(Ljava/io/InputStream;[C)V');
  LSetEntry := AEnv^^.GetMethodID(AEnv, LKsClass, 'setCertificateEntry',
    '(Ljava/lang/String;Ljava/security/cert/Certificate;)V');
  if (LGetDefType = nil) or (LGetInstance = nil) or (LLoad = nil) or
    (LSetEntry = nil) then
    Exit;

  LTypeStr := AEnv^^.CallStaticObjectMethodA(AEnv, LKsClass, LGetDefType, nil);
  if (LTypeStr = nil) or (AEnv^^.ExceptionCheck(AEnv) <> 0) then
  begin
    ClearPending(AEnv);
    Exit;
  end;
  LArgs[0].l := LTypeStr;
  LKeyStore := AEnv^^.CallStaticObjectMethodA(AEnv, LKsClass, LGetInstance,
    @LArgs[0]);
  if (LKeyStore = nil) or (AEnv^^.ExceptionCheck(AEnv) <> 0) then
  begin
    ClearPending(AEnv);
    Exit;
  end;

  // load(null, null) initializes an empty, in-memory keystore
  LArgs[0].l := nil;
  LArgs[1].l := nil;
  AEnv^^.CallVoidMethodA(AEnv, LKeyStore, LLoad, @LArgs[0]);
  if AEnv^^.ExceptionCheck(AEnv) <> 0 then
  begin
    ClearPending(AEnv);
    Exit;
  end;

  LCount := AEnv^^.GetArrayLength(AEnv, AAnchorArr);
  for LI := 0 to LCount - 1 do
  begin
    LCert := AEnv^^.GetObjectArrayElement(AEnv, AAnchorArr, LI);
    if LCert = nil then
      Continue;
    LAliasUtf8 := UTF8String('a' + IntToStr(LI));
    LAlias := AEnv^^.NewStringUTF(AEnv, PAnsiChar(LAliasUtf8));
    LArgs[0].l := LAlias;
    LArgs[1].l := LCert;
    AEnv^^.CallVoidMethodA(AEnv, LKeyStore, LSetEntry, @LArgs[0]);
    if AEnv^^.ExceptionCheck(AEnv) <> 0 then
    begin
      // a bad anchor entry is a broken trust configuration; fail closed
      ClearPending(AEnv);
      AEnv^^.DeleteLocalRef(AEnv, LAlias);
      AEnv^^.DeleteLocalRef(AEnv, LCert);
      Exit;
    end;
    AEnv^^.DeleteLocalRef(AEnv, LAlias);
    AEnv^^.DeleteLocalRef(AEnv, LCert);
  end;
  Result := LKeyStore;
end;

class function TAndroidTrustApi.EvaluateClient(const AChain, AAnchors: TArray<TBytes>;
  out AAlert: TTlsAlertDescription): Boolean;
var
  LVm: PJavaVM;
  LEnv: PJNIEnv;
  LAttached: Boolean;
  LTmClass: TJClass;
  LCheck: TJMethodID;
  LChainArr, LAnchorArr: TJObjectArray;
  LKeyStore, LX509Tm, LLeaf, LAuthStr: TJObject;
  LAuthUtf8: UTF8String;
  LBuildAlert: TTlsAlertDescription;
  LCheckArgs: array [0 .. 1] of TJValue;
begin
  Result := False;
  AAlert := TTlsAlertDescription.InternalError;

  if Length(AChain) = 0 then
  begin
    AAlert := TTlsAlertDescription.BadCertificate;
    Exit;
  end;

  // zero configured client-CA anchors can trust nothing: reject before the engine so an empty
  // anchor set can never fall through to the system roots
  if Length(AAnchors) = 0 then
  begin
    AAlert := TTlsAlertDescription.UnknownCa;
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
    // one frame reclaims the peer chain, the anchor certs and the keystore/trust-manager refs
    if LEnv^^.PushLocalFrame(LEnv,
      16 + (Length(AChain) + Length(AAnchors)) * 4) <> 0 then
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
      // a configured anchor that will not parse is a broken trust configuration
      LAnchorArr := BuildChainArray(LEnv, AAnchors, LBuildAlert);
      if LAnchorArr = nil then
        Exit;

      LKeyStore := BuildAnchorKeyStore(LEnv, LAnchorArr);
      if LKeyStore = nil then
        Exit;
      LX509Tm := DefaultX509TrustManager(LEnv, LKeyStore);
      if LX509Tm = nil then
        Exit;

      LLeaf := LEnv^^.GetObjectArrayElement(LEnv, LChainArr, 0);
      LAuthUtf8 := UTF8String(DeriveAuthType(LEnv, LLeaf));
      LAuthStr := LEnv^^.NewStringUTF(LEnv, PAnsiChar(LAuthUtf8));

      LTmClass := LEnv^^.FindClass(LEnv, 'javax/net/ssl/X509TrustManager');
      if LTmClass = nil then
      begin
        ClearPending(LEnv);
        Exit;
      end;
      LCheck := LEnv^^.GetMethodID(LEnv, LTmClass, 'checkClientTrusted',
        '([Ljava/security/cert/X509Certificate;Ljava/lang/String;)V');
      if LCheck = nil then
        Exit;
      LCheckArgs[0].l := LChainArr;
      LCheckArgs[1].l := LAuthStr;
      LEnv^^.CallVoidMethodA(LEnv, LX509Tm, LCheck, @LCheckArgs[0]);

      if LEnv^^.ExceptionCheck(LEnv) <> 0 then
        AAlert := MapPendingException(LEnv)
      else
        Result := True;
    finally
      ClearPending(LEnv);
      LEnv^^.PopLocalFrame(LEnv, nil);
    end;
  finally
    if LAttached then
      LVm^^.DetachCurrentThread(LVm);
  end;
end;

{ TAndroidDelegateVerifier }

constructor TAndroidDelegateVerifier.Create(const AProvider: ICryptoProvider;
  APosture: TRevocationPosture; const AClock: ITlsClock);
begin
  inherited Create;
  FProvider := AProvider;
  FPosture := APosture;
  FClock := AClock;
end;

function TAndroidDelegateVerifier.VerifyServerCertificate(const AChain: TArray<TBytes>;
  const AServerName: TServerName; const AOcspStaple: TBytes;
  out AAlert: TTlsAlertDescription): Boolean;
begin
  // the platform chain verdict first (roots, blocklist, network-security-config, pinning)
  Result := TAndroidTrustApi.Evaluate(AChain, AServerName.ToString, AAlert);
  if not Result then
    Exit;

  // revocation before identity, as the built-in pipeline orders it: the platform TrustManager
  // does not consult a stapled OCSP response, so decide the staple here with the library's own
  // verdict. A definitive Revoked rejects under every posture; an indeterminate outcome rejects
  // only under a Hard posture.
  case TCertificateVerifier.StapleVerdict(FProvider, FClock, AChain, AOcspStaple) of
    TStapleVerdict.Revoked:
      begin
        Result := False;
        AAlert := TTlsAlertDescription.CertificateRevoked;
        Exit;
      end;
    TStapleVerdict.Indeterminate:
      if FPosture = TRevocationPosture.Hard then
      begin
        Result := False;
        AAlert := TTlsAlertDescription.BadCertificateStatusResponse;
        Exit;
      end;
  end;

  // endpoint identity (RFC 6125): the platform validates the chain but NOT the host (Android
  // separates X509TrustManager from HostnameVerifier). An empty name skips it; a nil provider
  // cannot match, so it fails closed rather than trusting blindly.
  if AServerName.ToString <> '' then
    if (FProvider = nil) or
      (not TEndpointIdentity.Matches(AServerName,
      FProvider.Certificates.DnsNames(AChain[0]),
      FProvider.Certificates.IpAddresses(AChain[0]))) then
    begin
      Result := False;
      AAlert := TTlsAlertDescription.BadCertificate;
    end;
end;

{ TAndroidServerVerifierSource }

function TAndroidServerVerifierSource.CreateServerVerifier(
  const AContext: TServerTrustContext): IServerCertificateVerifier;
begin
  Result := TAndroidDelegateVerifier.Create(AContext.Provider,
    AContext.RevocationPosture, AContext.Clock) as IServerCertificateVerifier;
end;

{ TAndroidClientDelegateVerifier }

constructor TAndroidClientDelegateVerifier.Create(const AAnchors: TArray<TBytes>);
begin
  inherited Create;
  FAnchors := AAnchors;
end;

function TAndroidClientDelegateVerifier.VerifyClientCertificate(
  const AChain: TArray<TBytes>; out AAlert: TTlsAlertDescription): Boolean;
begin
  Result := TAndroidTrustApi.EvaluateClient(AChain, FAnchors, AAlert);
end;

{ TAndroidClientVerifierSource }

function TAndroidClientVerifierSource.CreateClientVerifier(
  const AContext: TClientTrustContext): IClientCertificateVerifier;
var
  LAnchors: TArray<TBytes>;
begin
  LAnchors := nil;
  if AContext.TrustStore <> nil then
    LAnchors := AContext.TrustStore.RootCertificates;
  Result := TAndroidClientDelegateVerifier.Create(LAnchors)
    as IClientCertificateVerifier;
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
