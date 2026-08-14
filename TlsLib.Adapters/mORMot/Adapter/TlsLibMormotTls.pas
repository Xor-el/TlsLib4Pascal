{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

/// <summary>
/// The mORMot integration adapter: drives TlsLib4Pascal's managed TLS engine behind
/// mORMot's own INetTls "swap-your-SSL" seam. An existing mORMot app gets our managed
/// TLS by pointing the global NewNetTls factory at NewTlsLib4PascalTls - no fork, no
/// recompile of mORMot. This unit is the only place our types and mORMot's types meet;
/// the core library references nothing here.
/// </summary>
unit TlsLibMormotTls;

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

interface

uses
  SysUtils,
  Classes,
  mormot.net.sock,
  mormot.core.os.security,
  mormot.core.base,
  mormot.core.unicode,
  TlpTlsAlert,
  TlpTlsVersion,
  TlpICryptoProvider,
  TlpDefaultCryptoProvider,
  TlpICertificateTrust,
  TlpCertificateVerifier,
  TlpTrustPolicy,
  TlpTlsCredential,
  TlpITlsConfig,
  TlpITlsConfigBuilder,
  TlpTlsPresets,
  TlpITlsEngine,
  TlpTlsEngineFactory,
  TlpITlsConfigMemo,
  TlpTlsConfigMemo,
  TlpTlsSignatureBuilder,
  TlpITlsTransport,
  TlpTlsStreamPump,
  TlpTlsStream,
  TlpSystemTrustFacade;

/// <summary>Sets a process-wide augment-only verify callback the adapter threads into every
/// client handshake (it runs after the built-in pipeline and can only additionally reject).
/// mORMot builds an INetTls per connection through a global factory, so the adapter's neutral
/// hooks are configured with these unit-level setters. nil clears it.</summary>
procedure SetTlsLibMormotVerifyCallback(const ACallback: TTlsCertificateVerifyCallback);
/// <summary>Sets a process-wide out-of-band verdict resolver (e.g. live OCSP/CRL): when set,
/// every client handshake parks after the pipeline accepts the chain and this decides it.
/// ADeadlineMs is advisory. nil clears it.</summary>
procedure SetTlsLibMormotVerdictResolver(const AResolver: TTlsVerdictResolver;
  ADeadlineMs: Cardinal);
/// <summary>Sets a process-wide, fully-built client config that REPLACES the context-driven build:
/// when set, every client handshake uses it as-is (the TNetTlsContext trust/cert fields are ignored).
/// The escape hatch to the full builder API - cipher order, groups, resumption, ALPN. nil clears it.</summary>
procedure SetTlsLibMormotClientConfig(const AConfig: ITlsClientConfig);
/// <summary>Sets a process-wide, fully-built server config that REPLACES the context-driven build
/// (the server-side counterpart of SetTlsLibMormotClientConfig). nil clears it.</summary>
procedure SetTlsLibMormotServerConfig(const AConfig: ITlsServerConfig);

type
  /// <summary>An ITlsTransport over a mORMot TNetSocket: raw ciphertext moves through the
  /// socket's blocking Recv/Send. nrClosed is an orderly EOF (0); nrRetry is retried.</summary>
  TMormotSocketTransport = class sealed(TInterfacedObject, ITlsTransport)
  strict private
  var
    FSocket: TNetSocket;
  public
    constructor Create(ASocket: TNetSocket);
    function Read(var ABuffer: TBytes; AOffset, AMaxLength: Int32): Int32;
    procedure Write(const ABuffer: TBytes; AOffset, ALength: Int32);
  end;

  /// <summary>
  /// TlsLib4Pascal's implementation of mORMot's INetTls. AfterConnection runs the client
  /// handshake; AfterAccept runs the server handshake; Send / Receive / ReceivePending move
  /// application data. It maps the input fields of TNetTlsContext onto our immutable config
  /// (cert/key, trust, client-auth, and the loud IgnoreCertificateErrors escape hatch).
  /// </summary>
  TTlsLibNetTls = class sealed(TInterfacedObject, INetTls)
  strict private
  var
    FStream: TTlsStream;
    FTransport: ITlsTransport;
    FEngine: ITlsEngine;
    FServerName: string;
    class function LoadFile(const APath: RawUtf8): TBytes; static;
    /// <summary>Whether the context names any cert/trust field a process-wide config would replace.</summary>
    class function ContextCarriesTrustOrCredential(
      const AContext: TNetTlsContext): Boolean; static;
    class function BuildClientConfig(const AContext: TNetTlsContext): ITlsClientConfig; static;
    class function BuildServerConfig(const AContext: TNetTlsContext): ITlsServerConfig; static;
    class function ClientSignature(const AContext: TNetTlsContext): string; static;
    class function ServerSignature(const AContext: TNetTlsContext): string; static;
    class function BuildClientEngine(var AContext: TNetTlsContext;
      const AHost: string): ITlsEngine; static;
    class function BuildServerEngine(const AContext: TNetTlsContext): ITlsEngine; static;
    procedure DriveHandshake(ASocket: TNetSocket; const AEngine: ITlsEngine;
      AIsClient: Boolean; const AHost: string);
  public
    destructor Destroy; override;
    // INetTls
    procedure AfterConnection(Socket: TNetSocket; var Context: TNetTlsContext;
      const ServerAddress: RawUtf8);
    procedure AfterBind(Socket: TNetSocket; var Context: TNetTlsContext;
      const ServerAddress: RawUtf8);
    procedure AfterAccept(Socket: TNetSocket; const BoundContext: TNetTlsContext;
      LastError, CipherName: PRawUtf8);
    function GetCipherName: RawUtf8;
    function GetRawTls: pointer;
    function GetRawCert(SignHashName: PRawUtf8 = nil): RawByteString;
    function Receive(Buffer: pointer; var Length: integer): TNetResult;
    function ReceivePending: integer;
    function Send(Buffer: pointer; var Length: integer): TNetResult;
  end;

/// <summary>The factory to point mORMot's global at: `NewNetTls := @NewTlsLib4PascalTls;`.</summary>
function NewTlsLib4PascalTls: INetTls;

/// <summary>Convenience one-liner: makes TlsLib4Pascal the process-wide TLS provider for
/// every mORMot TCrtSocket created afterwards.</summary>
procedure RegisterTlsLib4PascalTls;

implementation

resourcestring
  SNoCredential = 'the mORMot TLS context supplies no server certificate/key';
  SCARawUnsupported = 'the mORMot TLS context supplies CACertificatesRaw (in-memory OpenSSL ' +
    'X509 handles); TlsLib4Pascal is OpenSSL-free and cannot consume them - pass the CA chain ' +
    'as a PEM/DER file via CACertificatesFile, or use TSystemTrust for the OS anchors';
  SConfigAndContextConflict = 'a process-wide config installed via %s is used together with a ' +
    'TNetTlsContext that carries cert/trust fields; use either the process-wide config or the ' +
    'context fields, not both';

var
  // process-wide neutral hooks the per-connection adapter threads into each client handshake
  GVerifyCallback: TTlsCertificateVerifyCallback;
  GVerdictResolver: TTlsVerdictResolver;
  GVerdictDeadlineMs: Cardinal;
  // process-wide fully-built configs that, when set, REPLACE the context-driven build
  GClientConfig: ITlsClientConfig;
  GServerConfig: ITlsServerConfig;
  // mORMot builds an INetTls per connection, so the build-once memos for the context-driven
  // path live process-wide
  GServerConfigMemo: ITlsServerConfigMemo;
  GClientConfigMemo: ITlsClientConfigMemo;

procedure SetTlsLibMormotVerifyCallback(
  const ACallback: TTlsCertificateVerifyCallback);
begin
  GVerifyCallback := ACallback;
end;

procedure SetTlsLibMormotVerdictResolver(const AResolver: TTlsVerdictResolver;
  ADeadlineMs: Cardinal);
begin
  GVerdictResolver := AResolver;
  GVerdictDeadlineMs := ADeadlineMs;
end;

procedure SetTlsLibMormotClientConfig(const AConfig: ITlsClientConfig);
begin
  GClientConfig := AConfig;
end;

procedure SetTlsLibMormotServerConfig(const AConfig: ITlsServerConfig);
begin
  GServerConfig := AConfig;
end;

{ TMormotSocketTransport }

constructor TMormotSocketTransport.Create(ASocket: TNetSocket);
begin
  inherited Create;
  FSocket := ASocket;
end;

function TMormotSocketTransport.Read(var ABuffer: TBytes; AOffset,
  AMaxLength: Int32): Int32;
var
  LLen: Integer;
  LRes: TNetResult;
begin
  repeat
    LLen := AMaxLength;
    LRes := FSocket.Recv(@ABuffer[AOffset], LLen);
    case LRes of
      nrOK:
        if LLen > 0 then
          Exit(LLen)
        else
          Exit(0); // a zero-length OK read means the peer closed
      nrClosed:
        Exit(0);
      nrRetry:
        ; // a blocking socket rarely reports this; loop and read again
    else
      raise ETlsStreamError.Create(TTlsAlertDescription.InternalError,
        Format('mORMot socket receive failed (nr=%d)', [Ord(LRes)]));
    end;
  until False;
end;

procedure TMormotSocketTransport.Write(const ABuffer: TBytes; AOffset,
  ALength: Int32);
var
  LOff, LRemain, LLen: Integer;
  LRes: TNetResult;
begin
  LOff := AOffset;
  LRemain := ALength;
  while LRemain > 0 do
  begin
    LLen := LRemain;
    LRes := FSocket.Send(@ABuffer[LOff], LLen);
    case LRes of
      nrOK:
        begin
          Inc(LOff, LLen);
          Dec(LRemain, LLen);
        end;
      nrRetry:
        ; // loop and send the remainder
    else
      raise ETlsStreamError.Create(TTlsAlertDescription.InternalError,
        Format('mORMot socket send failed (nr=%d)', [Ord(LRes)]));
    end;
  end;
end;

{ TTlsLibNetTls }

destructor TTlsLibNetTls.Destroy;
begin
  FStream.Free;
  inherited Destroy;
end;

class function TTlsLibNetTls.LoadFile(const APath: RawUtf8): TBytes;
var
  LStream: TFileStream;
begin
  Result := nil;
  LStream := TFileStream.Create(Utf8ToString(APath), fmOpenRead or fmShareDenyWrite);
  try
    SetLength(Result, LStream.Size);
    if LStream.Size > 0 then
      LStream.ReadBuffer(Result[0], LStream.Size);
  finally
    LStream.Free;
  end;
end;

class function TTlsLibNetTls.ContextCarriesTrustOrCredential(
  const AContext: TNetTlsContext): Boolean;
begin
  Result := (AContext.CertificateFile <> '') or (AContext.PrivateKeyFile <> '') or
    (AContext.CACertificatesFile <> '') or (AContext.CASystemStores <> []) or
    (AContext.CACertificatesRaw <> nil);
end;

class function TTlsLibNetTls.BuildClientConfig(
  const AContext: TNetTlsContext): ITlsClientConfig;
var
  LProvider: ICryptoProvider;
  LClient: ITlsClientConfigBuilder;
  LHasTrust: Boolean;
begin
  LProvider := TDefaultCryptoProvider.Create as ICryptoProvider;
  LClient := TTlsPresets.Compatible(LProvider).Client;
  LHasTrust := False;
  // trust: a CASystemStores set that names an anchor-bearing store (the ROOT and/or CA store -
  // exactly what our OS harvester collects) routes to the OS trust store (Windows crypt32 /
  // macOS SecTrust / Unix bundle). scsMY (personal identity) and scsSpc (code-signing) are not
  // server-auth anchors, so they alone must not turn this on. CACertificatesFile adds a CA
  // bundle; the two sources union - either counts.
  if (scsRoot in AContext.CASystemStores) or
    (scsCA in AContext.CASystemStores) then
  begin
    TSystemTrust.WithSystemTrust(LClient, LProvider);
    LHasTrust := True;
  end;
  if AContext.CACertificatesFile <> '' then
  begin
    LClient.WithTrustAnchors(LoadFile(AContext.CACertificatesFile));
    LHasTrust := True;
  end;
  // the loud escape hatch: mORMot's IgnoreCertificateErrors maps only onto our
  // dangerous InsecureSkipVerify - never a silent full bypass
  if AContext.IgnoreCertificateErrors then
  begin
    LClient.WithDangerousInsecureSkipVerify(True);
    // a client build still requires a trust source; an empty store suffices when the
    // pipeline is being skipped anyway
    if not LHasTrust then
      LClient.WithTrustStore(TTrustAnchorStore.Create(nil) as ITrustAnchorStore);
  end;
  // a client certificate for mutual TLS, when the context carries a cert+key file pair
  if AContext.CertificateFile <> '' then
    LClient.WithCredential(LoadFile(AContext.CertificateFile),
      LoadFile(AContext.PrivateKeyFile), Utf8ToString(AContext.PrivatePassword));
  // the process-wide neutral augment hook, and an out-of-band verdict resolver that parks
  // the handshake for a decision (live revocation etc.)
  if Assigned(GVerifyCallback) then
    LClient.WithCertificateVerifyCallback(GVerifyCallback);
  if Assigned(GVerdictResolver) then
    LClient.WithAsyncCertificateVerdict(True, GVerdictDeadlineMs);
  Result := LClient.Build;
end;

class function TTlsLibNetTls.BuildServerConfig(
  const AContext: TNetTlsContext): ITlsServerConfig;
var
  LProvider: ICryptoProvider;
  LServer: ITlsServerConfigBuilder;
begin
  LProvider := TDefaultCryptoProvider.Create as ICryptoProvider;
  LServer := TTlsPresets.Compatible(LProvider).Server;
  if AContext.CertificateFile <> '' then
    LServer.WithCredential(LoadFile(AContext.CertificateFile),
      LoadFile(AContext.PrivateKeyFile), Utf8ToString(AContext.PrivatePassword))
  else
    raise ETlsStreamError.Create(TTlsAlertDescription.InternalError, SNoCredential);
  // mutual TLS: request and verify the client certificate against the CA bundle
  if AContext.ClientCertificateAuthentication then
  begin
    LServer.WithPeerAuth(TClientAuthMode.Required);
    // same anchor-store semantics as the client: only ROOT/CA trigger the OS harvest. NOTE this
    // validates CLIENT certificates against the OS public web-PKI roots - a very broad trust
    // surface that is rarely what an mTLS server wants (client certs normally chain to a private
    // CA supplied via CACertificatesFile). We map mORMot's config faithfully; the caller opted in.
    if (scsRoot in AContext.CASystemStores) or
      (scsCA in AContext.CASystemStores) then
      TSystemTrust.WithSystemTrust(LServer, LProvider);
    if AContext.CACertificatesFile <> '' then
      LServer.WithTrustAnchors(LoadFile(AContext.CACertificatesFile));
  end;
  Result := LServer.Build;
end;

class function TTlsLibNetTls.ClientSignature(const AContext: TNetTlsContext): string;
var
  LSig: TTlsSignatureBuilder;
begin
  LSig := TTlsSignatureBuilder.Create(nil); // mORMot inputs are all files/scalars
  LSig.AddFile('cert', Utf8ToString(AContext.CertificateFile));
  LSig.AddFile('key', Utf8ToString(AContext.PrivateKeyFile));
  LSig.AddText('keypw', Utf8ToString(AContext.PrivatePassword));
  LSig.AddFile('ca', Utf8ToString(AContext.CACertificatesFile));
  LSig.AddFlag('scsRoot', scsRoot in AContext.CASystemStores);
  LSig.AddFlag('scsCA', scsCA in AContext.CASystemStores);
  LSig.AddFlag('ignoreErrors', AContext.IgnoreCertificateErrors);
  LSig.AddMethod('verifyCb', TMethod(GVerifyCallback));
  LSig.AddFlag('asyncVerdict', Assigned(GVerdictResolver));
  LSig.AddCardinal('deadline', GVerdictDeadlineMs);
  Result := LSig.Value;
end;

class function TTlsLibNetTls.ServerSignature(const AContext: TNetTlsContext): string;
var
  LSig: TTlsSignatureBuilder;
begin
  LSig := TTlsSignatureBuilder.Create(nil);
  LSig.AddFile('cert', Utf8ToString(AContext.CertificateFile));
  LSig.AddFile('key', Utf8ToString(AContext.PrivateKeyFile));
  LSig.AddText('keypw', Utf8ToString(AContext.PrivatePassword));
  LSig.AddFlag('clientAuth', AContext.ClientCertificateAuthentication);
  LSig.AddFile('ca', Utf8ToString(AContext.CACertificatesFile));
  LSig.AddFlag('scsRoot', scsRoot in AContext.CASystemStores);
  LSig.AddFlag('scsCA', scsCA in AContext.CASystemStores);
  Result := LSig.Value;
end;

class function TTlsLibNetTls.BuildClientEngine(var AContext: TNetTlsContext;
  const AHost: string): ITlsEngine;
var
  LCfg: ITlsClientConfig;
  LSig: string;
begin
  // a process-wide fully-built config REPLACES the context-driven build outright; a context that
  // also carries cert/trust fields fails loud rather than dropping them silently (the verify
  // callback and verdict resolver are runtime hooks and still apply)
  if GClientConfig <> nil then
  begin
    if ContextCarriesTrustOrCredential(AContext) then
      raise ETlsStreamError.Create(TTlsAlertDescription.InternalError,
        Format(SConfigAndContextConflict, ['SetTlsLibMormotClientConfig']));
    AContext.Enabled := True;
    Exit(TTlsEngineFactory.CreateClientEngine(GClientConfig, AHost));
  end;
  // CACertificatesRaw carries live OpenSSL X509 handles we cannot consume; reject before the memo
  // (it is per-context, never part of the build signature)
  if AContext.CACertificatesRaw <> nil then
    raise ETlsStreamError.Create(TTlsAlertDescription.InternalError, SCARawUnsupported);
  LSig := ClientSignature(AContext);
  if not GClientConfigMemo.TryGet(LSig, LCfg) then
    LCfg := GClientConfigMemo.StoreOrAdopt(LSig, BuildClientConfig(AContext));
  AContext.Enabled := True;
  Result := TTlsEngineFactory.CreateClientEngine(LCfg, AHost);
end;

class function TTlsLibNetTls.BuildServerEngine(
  const AContext: TNetTlsContext): ITlsEngine;
var
  LCfg: ITlsServerConfig;
  LSig: string;
begin
  // a context that also carries cert/trust fields fails loud rather than being dropped silently
  if GServerConfig <> nil then
  begin
    if ContextCarriesTrustOrCredential(AContext) then
      raise ETlsStreamError.Create(TTlsAlertDescription.InternalError,
        Format(SConfigAndContextConflict, ['SetTlsLibMormotServerConfig']));
    Exit(TTlsEngineFactory.CreateServerEngine(GServerConfig));
  end;
  if AContext.CACertificatesRaw <> nil then
    raise ETlsStreamError.Create(TTlsAlertDescription.InternalError, SCARawUnsupported);
  LSig := ServerSignature(AContext);
  if not GServerConfigMemo.TryGet(LSig, LCfg) then
    LCfg := GServerConfigMemo.StoreOrAdopt(LSig, BuildServerConfig(AContext));
  Result := TTlsEngineFactory.CreateServerEngine(LCfg);
end;

procedure TTlsLibNetTls.DriveHandshake(ASocket: TNetSocket;
  const AEngine: ITlsEngine; AIsClient: Boolean; const AHost: string);
begin
  FEngine := AEngine;
  FServerName := AHost;
  FTransport := TMormotSocketTransport.Create(ASocket) as ITlsTransport;
  FStream := TTlsStream.Create(FTransport, FEngine, AIsClient, AHost);
  if AIsClient and Assigned(GVerdictResolver) then
    FStream.SetCertificateVerdictResolver(GVerdictResolver);
  FStream.Handshake;
end;

procedure TTlsLibNetTls.AfterConnection(Socket: TNetSocket;
  var Context: TNetTlsContext; const ServerAddress: RawUtf8);
var
  LHost: string;
begin
  LHost := Utf8ToString(ServerAddress);
  DriveHandshake(Socket, BuildClientEngine(Context, LHost), True, LHost);
  Context.CipherName := GetCipherName;
end;

procedure TTlsLibNetTls.AfterBind(Socket: TNetSocket;
  var Context: TNetTlsContext; const ServerAddress: RawUtf8);
begin
  // we build a fresh engine per accepted connection from the bound context, so there is
  // no shared server state to set up here (unlike an OpenSSL SSL_CTX)
  Context.Enabled := True;
end;

procedure TTlsLibNetTls.AfterAccept(Socket: TNetSocket;
  const BoundContext: TNetTlsContext; LastError, CipherName: PRawUtf8);
begin
  try
    DriveHandshake(Socket, BuildServerEngine(BoundContext), False, '');
    if CipherName <> nil then
      CipherName^ := GetCipherName;
  except
    on E: Exception do
    begin
      if LastError <> nil then
        LastError^ := StringToUtf8(E.Message);
      raise;
    end;
  end;
end;

function TTlsLibNetTls.GetCipherName: RawUtf8;
var
  LVersion: TTlsVersion;
begin
  // we do not surface the raw suite name; report the negotiated protocol version, which is
  // what mORMot logs the cipher for
  LVersion := FEngine.NegotiatedVersion;
  if LVersion.WireValue = TlsWireVersionTls13 then
    Result := 'TLSv1.3'
  else if LVersion.WireValue = TlsWireVersionTls12 then
    Result := 'TLSv1.2'
  else
    Result := '';
end;

function TTlsLibNetTls.GetRawTls: pointer;
begin
  // there is no underlying PSSL/OpenSSL handle: TlsLib4Pascal is a managed engine
  Result := nil;
end;

function TTlsLibNetTls.GetRawCert(SignHashName: PRawUtf8): RawByteString;
var
  LChain: TArray<TBytes>;
begin
  // the peer leaf certificate DER (mORMot uses it for certificate pinning / peer info). We do
  // not surface the signature-hash name, so TLS channel binding that requires it stays inert.
  Result := '';
  if FEngine = nil then
    Exit;
  LChain := FEngine.PeerCertificates;
  if (System.Length(LChain) > 0) and (System.Length(LChain[0]) > 0) then
    SetString(Result, PAnsiChar(@LChain[0][0]), System.Length(LChain[0]));
end;

function TTlsLibNetTls.Receive(Buffer: pointer; var Length: integer): TNetResult;
var
  LGot: Integer;
begin
  try
    LGot := FStream.Read(Buffer^, Length);
    Length := LGot;
    if LGot > 0 then
      Result := nrOK
    else
      // a zero-length read is a clean close_notify EOF (truncation raises)
      Result := nrClosed;
  except
    Length := 0;
    Result := nrFatalError;
  end;
end;

function TTlsLibNetTls.ReceivePending: integer;
begin
  Result := FStream.PendingReadBytes;
end;

function TTlsLibNetTls.Send(Buffer: pointer; var Length: integer): TNetResult;
begin
  try
    FStream.Write(Buffer^, Length);
    Result := nrOK;
  except
    Length := 0;
    Result := nrFatalError;
  end;
end;

function NewTlsLib4PascalTls: INetTls;
begin
  Result := TTlsLibNetTls.Create;
end;

procedure RegisterTlsLib4PascalTls;
begin
  NewNetTls := NewTlsLib4PascalTls;
end;

initialization
  GServerConfigMemo := NewTlsServerConfigMemo;
  GClientConfigMemo := NewTlsClientConfigMemo;

end.
