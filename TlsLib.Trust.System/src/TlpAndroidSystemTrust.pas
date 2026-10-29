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
  TlpArrayUtilities,
  TlpTrustPolicy,
  TlpDynamicLibrary,
  TlpSystemTrustBase,
  TlpIPlatformChainEngine,
  TlpTlsAlert;

type
  /// <summary>What a Java trust-manager rejection exposes: whether it is a CertificateException, a
  /// time-validity one, and whether its cause is a CertPathValidatorException with that cause's path
  /// index, message and reason name; and whether a network-security-config domain-config governs
  /// the host.</summary>
  TJavaTrustFacts = record
    CertificateException: Boolean;
    TimeInvalid: Boolean;
    PathValidatorCause: Boolean;
    CauseIndex: Int32;
    CauseMessage: string;
    CauseReason: string;
    DomainScoped: Boolean;
  end;

  /// <summary>Classifies a Java trust-manager rejection from its facts. Only a CertificateException
  /// is a peer trust failure (anything else is an internal error); it is NoTrustAnchor only when its
  /// cause is a path-validation failure at index -1 whose message names the missing trust anchor
  /// and no domain-config governs the host (that config alone decides, so a missing anchor there is
  /// final), and every other shape (pin, expiry, revocation, unrecognised) is Other. A missing
  /// anchor outranks the rest, so a bad signature directly under a trust anchor reads as one and
  /// stays unknown_ca. Otherwise a failed signature check is decrypt_error, and an unrecognised
  /// critical extension or a name constraint failure is certificate_unknown. Expiry is decided
  /// first, but the platform may check a signature before validity, so a certificate that is both
  /// badly signed and expired can still read as decrypt_error.</summary>
  TJavaTrustClassifier = class sealed(TObject)
  public
    class procedure Classify(const AFacts: TJavaTrustFacts; out AAlert: TTlsAlertDescription;
      out AFailure: TPlatformChainFailure); static;
  end;

  /// <summary>
  /// The Android platform chain engine behind the OS trust delegate: builds and trusts a
  /// certificate path with the platform's Java engine over JNI - the system trust store and its
  /// network-security-config (per-domain trust, user-CA opt-in, pinning) for a server certificate
  /// via android.net.http.X509TrustManagerExtensions.checkServerTrusted (or, given anchors, an
  /// exclusive KeyStore of them that the network-security-config does not govern; the delegate
  /// offers host roots that way only for hosts no network-security-config domain-config names), an
  /// exclusive KeyStore of the configured client-CA anchors for a client certificate via
  /// checkClientTrusted (never the OS or public-web-PKI roots). The platform TrustManager owns
  /// revocation and exposes no cached outcome and no network-revocation knob, so the engine renders
  /// an indeterminate revocation outcome and matches no host - posture, the strength policy, the
  /// staple decision and the RFC 9525 identity belong to the delegate that owns it, as do the name
  /// constraints and, for a client certificate, the path build. The server host is passed as the
  /// network-security-config domain key (a null host throws once a per-domain config exists), never
  /// a name check. The platform validates at device time: the request's clock is not used.
  /// Construction is init-independent; the JVM is acquired lazily inside the evaluation (Delphi
  /// resolves it automatically, FPC needs TlsLibAndroidInitTrust). Stateless and thread-reusable.
  /// Fail-closed.
  /// </summary>
  TAndroidChainEngine = class sealed(TInterfacedObject, IPlatformChainEngine)
  public
    function Capabilities: TPlatformChainCapabilities;
    function EvaluateServer(const ARequest: TPlatformChainRequest;
      out AResult: TPlatformChainResult; out AAlert: TTlsAlertDescription): Boolean;
    function EvaluateClient(const ARequest: TPlatformChainRequest;
      out AResult: TPlatformChainResult; out AAlert: TTlsAlertDescription): Boolean;
  end;

/// <summary>
/// Hands the library the running JavaVM, which lets Verify attach arbitrary (non-Java)
/// handshake threads. Idempotent - the first non-nil call wins. On Delphi it is called
/// automatically, so a NativeActivity app needs nothing. On FPC it is REQUIRED: call it once
/// with the JavaVM from your JNI_OnLoad, or Verify fails closed.
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
    class function IsInstanceOfNamed(AEnv: PJNIEnv; AObj: TJObject;
      const AClassName: PAnsiChar): Boolean; static;
    /// <summary>True when the exception or one of its bounded causes is an expired or
    /// not-yet-valid certificate; any lookup failure answers False.</summary>
    class function HasTimeInvalidInChain(AEnv: PJNIEnv; AExc: TJThrowable): Boolean; static;
    /// <summary>The name of a CertPathValidatorException's Reason (API 24+); any lookup
    /// failure answers an empty string.</summary>
    class function ReadReasonName(AEnv: PJNIEnv; ACause: TJObject;
      ACpvClass: TJClass): string; static;
    /// <summary>The facts of a trust-manager exception that the classifier decides on; a lookup
    /// that fails leaves its fact unset, so the rejection classifies as Other.</summary>
    class function ReadExceptionFacts(AEnv: PJNIEnv; AExc: TJThrowable)
      : TJavaTrustFacts; static;
    /// <summary>Takes and clears the pending exception and classifies it. Given the extensions
    /// object and host (the pass over the system roots), a missing trust anchor is first checked
    /// against the network-security-config: a host a domain-config names is scoped to it.</summary>
    class function MapPendingException(AEnv: PJNIEnv; AExtObj, AHostStr: TJObject;
      const AHostName: string; out AFailure: TPlatformChainFailure): TTlsAlertDescription; static;
    /// <summary>Reads the DER of a validated java.util.List&lt;X509Certificate&gt; (leaf first,
    /// anchor last) into APath. False on a nil list, a pending exception or an unreadable
    /// element, so the caller fails closed.</summary>
    class function ReadListPath(AEnv: PJNIEnv; AList: TJObject;
      out APath: TArray<TBytes>): Boolean; static;
  public
    class procedure ResolveDynamicImports; static;
    class procedure ReleaseDynamicImports; static;
    class procedure Capture(AJavaVM: Pointer); static;
    /// <summary>Runs the platform CHAIN trust decision for the peer chain with no network fetch
    /// of our own (hostname identity is enforced by the caller), returning the validated path the
    /// platform built (leaf first, anchor last) in AOsPath. Non-empty AAnchors select an exclusive
    /// KeyStore root in place of the system roots and their network-security-config. Returns True
    /// when the OS trusts the chain; on rejection or any failure returns False with AAlert set to
    /// the matching fatal alert and AFailure to its class. AHostRoots (host roots will follow a
    /// missing anchor) enables the network-security-config domain probe.</summary>
    class function Evaluate(const AChain, AAnchors: TArray<TBytes>; const AHostName: string;
      AHostRoots: Boolean; out AOsPath: TArray<TBytes>; out AAlert: TTlsAlertDescription;
      out AFailure: TPlatformChainFailure): Boolean; static;
    /// <summary>Runs the platform client-auth trust decision for the peer CLIENT chain against a
    /// KeyStore of the configured client-CA anchors alone (checkClientTrusted) - never the system
    /// roots. Zero anchors reject before the engine. Returns True when trusted; on rejection or
    /// any failure returns False with AAlert set.</summary>
    class function EvaluateClient(const AChain, AAnchors: TArray<TBytes>;
      out AAlert: TTlsAlertDescription): Boolean; static;
  end;

{ TJavaTrustClassifier }

class procedure TJavaTrustClassifier.Classify(const AFacts: TJavaTrustFacts;
  out AAlert: TTlsAlertDescription; out AFailure: TPlatformChainFailure);
var
  LMessage: string;
begin
  AFailure := TPlatformChainFailure.Other;
  if not AFacts.CertificateException then
  begin
    AAlert := TTlsAlertDescription.InternalError;
    Exit;
  end;
  if AFacts.TimeInvalid then
  begin
    AAlert := TTlsAlertDescription.CertificateExpired;
    Exit;
  end;
  LMessage := LowerCase(AFacts.CauseMessage);
  AAlert := TTlsAlertDescription.UnknownCa;
  if AFacts.PathValidatorCause and (AFacts.CauseIndex = -1) and
    (Pos('trust anchor', LMessage) > 0) and (not AFacts.DomainScoped) then
  begin
    AFailure := TPlatformChainFailure.NoTrustAnchor;
    Exit;
  end;
  if not AFacts.PathValidatorCause then
    Exit;
  if (AFacts.CauseReason = 'INVALID_SIGNATURE') or
    (Pos('signature check failed', LMessage) > 0) or
    (Pos('could not validate certificate signature', LMessage) > 0) then
    AAlert := TTlsAlertDescription.DecryptError
  else if (AFacts.CauseReason = 'UNRECOGNIZED_CRIT_EXT') or (AFacts.CauseReason = 'INVALID_NAME') or
    (Pos('critical extension', LMessage) > 0) or (Pos('subtree check', LMessage) > 0) or
    (Pos('name constraints check failed', LMessage) > 0) then
    AAlert := TTlsAlertDescription.CertificateUnknown;
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
  FLogLibHandle := TDynamicLibrary.Open(ANDROID_LOG_LIB);
  FLogWrite := TAndroidLogWriteFunc(
    TDynamicLibrary.Resolve(FLogLibHandle, '__android_log_write'));
end;

class procedure TAndroidTrustApi.ReleaseDynamicImports;
begin
  FLogWrite := nil;
  TDynamicLibrary.Close(FLogLibHandle);
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
  begin
    ClearPending(AEnv);
    Exit;
  end;

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
  begin
    ClearPending(AEnv);
    Exit;
  end;
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
  begin
    ClearPending(AEnv);
    Exit;
  end;
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
  begin
    ClearPending(AEnv);
    Exit;
  end;

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

class function TAndroidTrustApi.IsInstanceOfNamed(AEnv: PJNIEnv; AObj: TJObject;
  const AClassName: PAnsiChar): Boolean;
var
  LClass: TJClass;
begin
  LClass := AEnv^^.FindClass(AEnv, AClassName);
  if LClass = nil then
  begin
    ClearPending(AEnv);
    Exit(False);
  end;
  Result := AEnv^^.IsInstanceOf(AEnv, AObj, LClass) <> 0;
end;

class function TAndroidTrustApi.HasTimeInvalidInChain(AEnv: PJNIEnv;
  AExc: TJThrowable): Boolean;
const
  MAX_CAUSE_DEPTH = 4;
var
  LThrowableClass: TJClass;
  LGetCause: TJMethodID;
  LCur: TJObject;
  LDepth: Integer;
begin
  Result := False;
  LThrowableClass := AEnv^^.FindClass(AEnv, 'java/lang/Throwable');
  if LThrowableClass = nil then
  begin
    ClearPending(AEnv);
    Exit;
  end;
  LGetCause := AEnv^^.GetMethodID(AEnv, LThrowableClass, 'getCause',
    '()Ljava/lang/Throwable;');
  if LGetCause = nil then
  begin
    ClearPending(AEnv);
    Exit;
  end;
  LCur := AExc;
  for LDepth := 0 to MAX_CAUSE_DEPTH do
  begin
    if IsInstanceOfNamed(AEnv, LCur, 'java/security/cert/CertificateExpiredException') or
      IsInstanceOfNamed(AEnv, LCur, 'java/security/cert/CertificateNotYetValidException') then
      Exit(True);
    LCur := AEnv^^.CallObjectMethodA(AEnv, LCur, LGetCause, nil);
    if (LCur = nil) or (AEnv^^.ExceptionCheck(AEnv) <> 0) then
    begin
      ClearPending(AEnv);
      Exit;
    end;
  end;
end;

class function TAndroidTrustApi.ReadReasonName(AEnv: PJNIEnv; ACause: TJObject;
  ACpvClass: TJClass): string;
var
  LObjectClass: TJClass;
  LGetReason, LToString: TJMethodID;
  LReason, LName: TJObject;
  LChars: PAnsiChar;
begin
  Result := '';
  LGetReason := AEnv^^.GetMethodID(AEnv, ACpvClass, 'getReason',
    '()Ljava/security/cert/CertPathValidatorException$Reason;');
  if LGetReason = nil then
  begin
    ClearPending(AEnv);
    Exit;
  end;
  LObjectClass := AEnv^^.FindClass(AEnv, 'java/lang/Object');
  if LObjectClass = nil then
  begin
    ClearPending(AEnv);
    Exit;
  end;
  LToString := AEnv^^.GetMethodID(AEnv, LObjectClass, 'toString', '()Ljava/lang/String;');
  if LToString = nil then
  begin
    ClearPending(AEnv);
    Exit;
  end;
  LReason := AEnv^^.CallObjectMethodA(AEnv, ACause, LGetReason, nil);
  if (LReason = nil) or (AEnv^^.ExceptionCheck(AEnv) <> 0) then
  begin
    ClearPending(AEnv);
    Exit;
  end;
  LName := AEnv^^.CallObjectMethodA(AEnv, LReason, LToString, nil);
  if (LName = nil) or (AEnv^^.ExceptionCheck(AEnv) <> 0) then
  begin
    ClearPending(AEnv);
    Exit;
  end;
  LChars := AEnv^^.GetStringUTFChars(AEnv, LName, nil);
  if LChars = nil then
  begin
    ClearPending(AEnv);
    Exit;
  end;
  try
    Result := string(AnsiString(LChars));
  finally
    AEnv^^.ReleaseStringUTFChars(AEnv, LName, LChars);
  end;
end;

class function TAndroidTrustApi.ReadExceptionFacts(AEnv: PJNIEnv;
  AExc: TJThrowable): TJavaTrustFacts;
var
  LThrowableClass, LCpvClass: TJClass;
  LGetCause, LGetMessage, LGetIndex: TJMethodID;
  LCause, LMessage: TJObject;
  LChars: PAnsiChar;
begin
  Result := Default(TJavaTrustFacts);
  if AExc = nil then
    Exit;
  Result.CertificateException := IsInstanceOfNamed(AEnv, AExc,
    'java/security/cert/CertificateException');
  if not Result.CertificateException then
    Exit;
  Result.TimeInvalid := HasTimeInvalidInChain(AEnv, AExc);

  LThrowableClass := AEnv^^.FindClass(AEnv, 'java/lang/Throwable');
  LCpvClass := AEnv^^.FindClass(AEnv, 'java/security/cert/CertPathValidatorException');
  if (LThrowableClass = nil) or (LCpvClass = nil) then
  begin
    ClearPending(AEnv);
    Exit;
  end;
  LGetCause := AEnv^^.GetMethodID(AEnv, LThrowableClass, 'getCause',
    '()Ljava/lang/Throwable;');
  LGetMessage := AEnv^^.GetMethodID(AEnv, LThrowableClass, 'getMessage',
    '()Ljava/lang/String;');
  LGetIndex := AEnv^^.GetMethodID(AEnv, LCpvClass, 'getIndex', '()I');
  if (LGetCause = nil) or (LGetMessage = nil) or (LGetIndex = nil) then
  begin
    ClearPending(AEnv);
    Exit;
  end;

  LCause := AEnv^^.CallObjectMethodA(AEnv, AExc, LGetCause, nil);
  if (LCause = nil) or (AEnv^^.ExceptionCheck(AEnv) <> 0) or
    (AEnv^^.IsInstanceOf(AEnv, LCause, LCpvClass) = 0) then
  begin
    ClearPending(AEnv);
    Exit;
  end;
  Result.CauseIndex := AEnv^^.CallIntMethodA(AEnv, LCause, LGetIndex, nil);
  if AEnv^^.ExceptionCheck(AEnv) <> 0 then
  begin
    ClearPending(AEnv);
    Result.CauseIndex := 0;
    Exit;
  end;
  Result.PathValidatorCause := True;
  Result.CauseReason := ReadReasonName(AEnv, LCause, LCpvClass);
  LMessage := AEnv^^.CallObjectMethodA(AEnv, LCause, LGetMessage, nil);
  if AEnv^^.ExceptionCheck(AEnv) <> 0 then
  begin
    ClearPending(AEnv);
    Exit;
  end;
  if LMessage = nil then
    Exit;
  LChars := AEnv^^.GetStringUTFChars(AEnv, LMessage, nil);
  if LChars = nil then
  begin
    ClearPending(AEnv);
    Exit;
  end;
  try
    Result.CauseMessage := string(AnsiString(LChars));
  finally
    AEnv^^.ReleaseStringUTFChars(AEnv, LMessage, LChars);
  end;
end;

class function TAndroidTrustApi.MapPendingException(AEnv: PJNIEnv; AExtObj, AHostStr: TJObject;
  const AHostName: string; out AFailure: TPlatformChainFailure): TTlsAlertDescription;
var
  LExc: TJThrowable;
  LFacts: TJavaTrustFacts;
  LExtClass: TJClass;
  LSameConfig: TJMethodID;
  LEmptyStr: TJString;
  LThrew: Boolean;
  LArgs: array [0 .. 1] of TJValue;
begin
  LThrew := False;
  // A pending exception aborts the next JNI call, so capture then clear immediately.
  LExc := AEnv^^.ExceptionOccurred(AEnv);
  AEnv^^.ExceptionClear(AEnv);
  LFacts := ReadExceptionFacts(AEnv, LExc);
  TJavaTrustClassifier.Classify(LFacts, Result, AFailure);
  // a throw or false stays scoped; a missing method is API 23, which has no NSC
  if (AFailure = TPlatformChainFailure.NoTrustAnchor) and (AExtObj <> nil) and
    (AHostStr <> nil) then
  begin
    LFacts.DomainScoped := True;
    LExtClass := AEnv^^.FindClass(AEnv, 'android/net/http/X509TrustManagerExtensions');
    LSameConfig := nil;
    if LExtClass <> nil then
      LSameConfig := AEnv^^.GetMethodID(AEnv, LExtClass, 'isSameTrustConfiguration',
        '(Ljava/lang/String;Ljava/lang/String;)Z');
    if LSameConfig = nil then
    begin
      ClearPending(AEnv);
      LFacts.DomainScoped := False;
    end
    else
    begin
      LEmptyStr := AEnv^^.NewStringUTF(AEnv, '');
      if LEmptyStr <> nil then
      begin
        LArgs[0].l := AHostStr;
        LArgs[1].l := LEmptyStr;
        LFacts.DomainScoped := AEnv^^.CallBooleanMethodA(AEnv, AExtObj, LSameConfig,
          @LArgs[0]) = 0;
      end;
      LThrew := AEnv^^.ExceptionCheck(AEnv) <> 0;
      if LThrew then
        LFacts.DomainScoped := True;
    end;
    if LFacts.DomainScoped then
    begin
      if LThrew then
        LogError('host roots not applied to ' + AHostName + ': the NSC domain probe threw')
      else
        LogError('host roots do not apply to ' + AHostName + ': a network-security-config ' +
          'domain entry governs it; add the root to that domain''s trust-anchors');
      TJavaTrustClassifier.Classify(LFacts, Result, AFailure);
    end;
  end;
  ClearPending(AEnv);
end;

class function TAndroidTrustApi.ReadListPath(AEnv: PJNIEnv; AList: TJObject;
  out APath: TArray<TBytes>): Boolean;
var
  LListClass, LX509Class: TJClass;
  LSize, LGet, LGetEncoded: TJMethodID;
  LCert, LEncoded: TJObject;
  LArg: array [0 .. 0] of TJValue;
  LCount, LI: TJInt;
  LLen: TJSize;
begin
  Result := False;
  APath := nil;
  if AList = nil then
    Exit;
  LListClass := AEnv^^.FindClass(AEnv, 'java/util/List');
  LX509Class := AEnv^^.FindClass(AEnv, 'java/security/cert/X509Certificate');
  if (LListClass = nil) or (LX509Class = nil) then
  begin
    ClearPending(AEnv);
    Exit;
  end;
  LSize := AEnv^^.GetMethodID(AEnv, LListClass, 'size', '()I');
  LGet := AEnv^^.GetMethodID(AEnv, LListClass, 'get', '(I)Ljava/lang/Object;');
  LGetEncoded := AEnv^^.GetMethodID(AEnv, LX509Class, 'getEncoded', '()[B');
  if (LSize = nil) or (LGet = nil) or (LGetEncoded = nil) then
  begin
    ClearPending(AEnv);
    Exit;
  end;
  LCount := AEnv^^.CallIntMethodA(AEnv, AList, LSize, nil);
  if LCount <= 0 then
    Exit;
  SetLength(APath, LCount);
  for LI := 0 to LCount - 1 do
  begin
    LArg[0].i := LI;
    LCert := AEnv^^.CallObjectMethodA(AEnv, AList, LGet, @LArg[0]);
    if (LCert = nil) or (AEnv^^.ExceptionCheck(AEnv) <> 0) then
    begin
      ClearPending(AEnv);
      Exit;
    end;
    // getEncoded() may throw - treated as unreadable
    LEncoded := AEnv^^.CallObjectMethodA(AEnv, LCert, LGetEncoded, nil);
    if (LEncoded = nil) or (AEnv^^.ExceptionCheck(AEnv) <> 0) then
    begin
      ClearPending(AEnv);
      AEnv^^.DeleteLocalRef(AEnv, LCert);
      Exit;
    end;
    LLen := AEnv^^.GetArrayLength(AEnv, LEncoded);
    if LLen > 0 then
    begin
      SetLength(APath[LI], LLen);
      AEnv^^.GetByteArrayRegion(AEnv, LEncoded, 0, LLen, PJByteN(@APath[LI][0]));
    end;
    // reclaim the per-iteration refs
    AEnv^^.DeleteLocalRef(AEnv, LEncoded);
    AEnv^^.DeleteLocalRef(AEnv, LCert);
    if LLen <= 0 then
      Exit;
  end;
  Result := True;
end;

class function TAndroidTrustApi.Evaluate(const AChain, AAnchors: TArray<TBytes>;
  const AHostName: string; AHostRoots: Boolean; out AOsPath: TArray<TBytes>;
  out AAlert: TTlsAlertDescription; out AFailure: TPlatformChainFailure): Boolean;
var
  LVm: PJavaVM;
  LEnv: PJNIEnv;
  LAttached: Boolean;
  LExtClass: TJClass;
  LExtCtor, LCheck: TJMethodID;
  LX509Tm, LExtObj, LKeyStore, LLeaf, LAuthStr, LHostStr, LList: TJObject;
  LChainArr, LAnchorArr: TJObjectArray;
  LAuthUtf8, LHostUtf8: UTF8String;
  LBuildAlert: TTlsAlertDescription;
  LOneArg: array [0 .. 0] of TJValue;
  LCheckArgs: array [0 .. 2] of TJValue;
begin
  Result := False;
  AOsPath := nil;
  AAlert := TTlsAlertDescription.InternalError;
  AFailure := TPlatformChainFailure.None;

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
    // one frame reclaims the chain build, trust call and returned-list refs
    if LEnv^^.PushLocalFrame(LEnv, 48 + (Length(AChain) + Length(AAnchors)) * 4) <> 0 then
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

      // a nil KeyStore selects the system roots with the app's network-security-config; configured
      // anchors select an exclusive root that config does not govern
      LKeyStore := nil;
      if Length(AAnchors) > 0 then
      begin
        LAnchorArr := BuildChainArray(LEnv, AAnchors, LBuildAlert);
        if LAnchorArr = nil then
          Exit;
        LKeyStore := BuildAnchorKeyStore(LEnv, LAnchorArr);
        if LKeyStore = nil then
          Exit;
      end;
      LX509Tm := DefaultX509TrustManager(LEnv, LKeyStore);
      if LX509Tm = nil then
        Exit;

      // Extensions.checkServerTrusted returns the validated path and applies network-security-config
      // + pinning; a nil host (server-by-IP / mTLS peer) is accepted - it just skips host pinning
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
      begin
        ClearPending(LEnv);
        Exit;
      end;
      LOneArg[0].l := LX509Tm;
      LExtObj := LEnv^^.NewObjectA(LEnv, LExtClass, LExtCtor, @LOneArg[0]);
      if (LExtObj = nil) or (LEnv^^.ExceptionCheck(LEnv) <> 0) then
      begin
        ClearPending(LEnv);
        Exit;
      end;
      LHostStr := nil;
      if AHostName <> '' then
      begin
        LHostUtf8 := UTF8String(AHostName);
        LHostStr := LEnv^^.NewStringUTF(LEnv, PAnsiChar(LHostUtf8));
      end;
      LCheckArgs[0].l := LChainArr;
      LCheckArgs[1].l := LAuthStr;
      LCheckArgs[2].l := LHostStr;
      LList := LEnv^^.CallObjectMethodA(LEnv, LExtObj, LCheck, @LCheckArgs[0]);

      if LEnv^^.ExceptionCheck(LEnv) <> 0 then
      begin
        // only the system-roots pass is NSC-governed, and only host roots make the probe matter
        if (Length(AAnchors) = 0) and AHostRoots then
          AAlert := MapPendingException(LEnv, LExtObj, LHostStr, AHostName, AFailure)
        else
          AAlert := MapPendingException(LEnv, nil, nil, AHostName, AFailure);
        Exit;
      end;

      // trusted: capture the validated path
      if not ReadListPath(LEnv, LList, AOsPath) then
      begin
        AAlert := TTlsAlertDescription.InternalError;
        Exit;
      end;
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
  begin
    ClearPending(AEnv);
    Exit;
  end;

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
  LFailure: TPlatformChainFailure;
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
      32 + (Length(AChain) + Length(AAnchors)) * 4) <> 0 then
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
      begin
        ClearPending(LEnv);
        Exit;
      end;
      LCheckArgs[0].l := LChainArr;
      LCheckArgs[1].l := LAuthStr;
      LEnv^^.CallVoidMethodA(LEnv, LX509Tm, LCheck, @LCheckArgs[0]);

      if LEnv^^.ExceptionCheck(LEnv) <> 0 then
        AAlert := MapPendingException(LEnv, nil, nil, '', LFailure)
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

{ TAndroidChainEngine }

function TAndroidChainEngine.Capabilities: TPlatformChainCapabilities;
begin
  // no revocation outcome and no host check (staple and SAN are the delegate's); exclusive roots work
  Result := [TPlatformChainCapability.ExclusiveServerAnchors];
end;

function TAndroidChainEngine.EvaluateServer(const ARequest: TPlatformChainRequest;
  out AResult: TPlatformChainResult; out AAlert: TTlsAlertDescription): Boolean;
var
  LOsPath: TArray<TBytes>;
begin
  AResult := Default(TPlatformChainResult);
  // the host is the network-security-config domain key, NOT a name check (Android's host-aware
  // TrustManager requires a non-null host once per-domain configs exist), so it is passed as-is;
  // the RFC 9525 identity is matched in-library by the delegate
  Result := TAndroidTrustApi.Evaluate(
    TArrayUtilities.Concat<TBytes>(ARequest.Chain, ARequest.Intermediates), ARequest.Anchors,
    ARequest.ServerName.ToString, Length(ARequest.ExtraAnchors) > 0, LOsPath, AAlert,
    AResult.Failure);
  if not Result then
    Exit;
  // the OS-built path (leaf first, anchor last) is the validated chain, its anchor (last element)
  // exempt from the strength policy; the platform renders no revocation outcome of its own
  AResult.Path := LOsPath;
  AResult.PolicyExempt := TArray<TBytes>.Create(LOsPath[High(LOsPath)]);
  AResult.Outcome := TLiveRevocationOutcome.Indeterminate;
end;

function TAndroidChainEngine.EvaluateClient(const ARequest: TPlatformChainRequest;
  out AResult: TPlatformChainResult; out AAlert: TTlsAlertDescription): Boolean;
begin
  AResult := Default(TPlatformChainResult);
  // checkClientTrusted reports no path, so the delegate builds one to the configured anchors
  Result := TAndroidTrustApi.EvaluateClient(
    TArrayUtilities.Concat<TBytes>(ARequest.Chain, ARequest.Intermediates),
    ARequest.Anchors, AAlert);
  if not Result then
    Exit;
  AResult.Path := TArray<TBytes>.Create(ARequest.Chain[0]);
  AResult.PolicyExempt := nil;
  AResult.Outcome := TLiveRevocationOutcome.Indeterminate;
end;

procedure TlsLibAndroidInitTrust(AJavaVM: Pointer);
begin
  TAndroidTrustApi.Capture(AJavaVM);
end;

initialization

  TAndroidTrustApi.ResolveDynamicImports;

{$IFNDEF FPC}
  // Delphi captures the JavaVM automatically; FPC callers pass it from JNI_OnLoad.
  TlsLibAndroidInitTrust(System.JavaMachine);
{$ENDIF}

finalization

  TAndroidTrustApi.ReleaseDynamicImports;

{$IFEND}

end.
