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
/// The fcl-net integration adapter: drives TlsLib4Pascal's managed TLS engine behind Free
/// Pascal's own TSSLSocketHandler "swap-your-SSL" seam - so a stock TFPHTTPClient HTTPS request
/// (or any TInetSocket) speaks our managed TLS instead of OpenSSL. Include this unit and its
/// initialization block registers TTlsLibSocketHandler as fcl-net's default SSL handler class.
/// This unit is the only place our types and fcl-net's types meet: it maps fcl-net's
/// CertificateData and handler settings onto the host-neutral adapter core (config composition,
/// timed transport, session drive) and supplies the fcl-net socket glue. Free Pascal only.
/// </summary>
unit TlsLibFclNetTls;

{$I ..\..\..\TlsLib\src\Include\TlsLib.inc}

interface

uses
  SysUtils,
  Classes,
  TypInfo,
  sockets,
  ssockets,
  sslsockets,
  sslbase,
  TlpTlsAlert,
  TlpTlsVersion,
  TlpEchConfig,
  TlpServerName,
  TlpICryptoProvider,
  TlpIPkixProvider,
  TlpICertificateTrust,
  TlpITrustAnchorStore,
  TlpTrustPolicy,
  TlpITlsConfig,
  TlpITlsConfigBuilder,
  TlpISystemTrustInstaller,
  TlpITlsConfigMemo,
  TlpTlsConfigMemo,
  TlpTlsLibExceptions,
  TlpPem,
  TlpDer,
  TlpArrayUtilities,
  TlpBinaryPrimitives,
  TlpDataEncoding,
  TlpCryptoDomainTypes,
  TlpTlsCredential,
  TlpITlsTransport,
  TlpAlpnProtocols,
  TlpTlsConnection,
  TlpTlsConnectionInfo,
  TlpSystemTrustFacade,
  TlpNetSocket;

type
  /// <summary>The subject-name hash that names the files of a hashed certificate directory: SHA-1
  /// over the canonical form of a certificate's subject Name, its first four digest bytes read
  /// little-endian and written as eight lowercase hexadecimal digits. The canonical form
  /// re-encodes every string value as UTF-8 with surrounding white space removed, inner runs of
  /// white space folded to one space and ASCII letters lowercased, and orders each SET OF by its
  /// encodings.</summary>
  TOpenSslNameHash = class sealed(TObject)
  strict private
  const
    MaxNameLength = Int32(16384);
    TagOid = Byte($06);
    TagUtf8String = Byte($0C);
    TagNumericString = Byte($12);
    TagPrintableString = Byte($13);
    TagT61String = Byte($14);
    TagIa5String = Byte($16);
    TagUniversalString = Byte($1C);
    TagBmpString = Byte($1E);
    TagSequence = Byte($30);
    TagSet = Byte($31);
    TagVersion = Byte($A0);
    class function IsSpace(AByte: Byte): Boolean; static;
    /// <summary>The contents of the TLVs, all tagged ATag, that make up AParent exactly; False
    /// when AParent is anything else.</summary>
    class function ChildContents(const AParent: TBytes; ATag: Byte;
      out AChildren: TArray<TBytes>): Boolean; static;
    /// <summary>A string value as UTF-8; False for a string type outside the supported set, a
    /// UTF-8 string that is not valid, or a surrogate or code point above 10FFFF.</summary>
    class function ToUtf8(ATag: Byte; const AValue: TBytes;
      out AUtf8: TBytes): Boolean; static;
    class function Canonical(const AUtf8: TBytes): TBytes; static;
    /// <summary>The canonical encoding of one attribute of a Name; False when its value type has
    /// no hash.</summary>
    class function CanonicalAttribute(const AAttribute: TBytes;
      out AEncoded: TBytes): Boolean; static;
    /// <summary>The canonical encoding of the SET OF whose content is ASet.</summary>
    class function CanonicalSet(const ASet: TBytes; out AEncoded: TBytes): Boolean; static;
    class function SubjectName(const ACertificate: TBytes;
      out AName: TBytes): Boolean; static;
  public
    /// <summary>The hash of the DER Name AName; empty when it does not parse strictly, is larger
    /// than 16 KiB, uses a string type outside the supported set or holds a string that does not
    /// convert.</summary>
    class function OfName(const ACrypto: ICryptoProvider; const AName: TBytes): string; static;
    /// <summary>The file-name prefix of the DER certificate ACertificate; empty when its subject
    /// has no hash (see OfName).</summary>
    class function OfCertificate(const ACrypto: ICryptoProvider;
      const ACertificate: TBytes): string; static;
  end;

  /// <summary>An ITlsTransport over a raw fcl-net socket handle: raw ciphertext moves through
  /// TlsLib.Net's TNetOs on Socket.Handle, bypassing the SSL-aware handler methods
  /// (which carry decrypted application data and would otherwise recurse). A wait before each
  /// receive enforces the handshake cap and read timeouts on every CPU, so Socket.IOTimeout is not
  /// needed. An expiry is ETlsHandshakeTimeout under the handshake cap and the retryable
  /// ETlsReadTimeout on an application read, never end of stream.</summary>
  TFclNetSocketTransport = class sealed(TTlsTimedTransportBase)
  strict private
  var
    FHandle: THandle;
    FSocketError: Integer;
    FCancelled: Boolean;
  strict protected
    function WaitReadable(AMs: Int32): Boolean; override;
    function ReceiveRaw(var ABuffer: TBytes; AOffset, AMaxLength: Int32): Int32; override;
    function SendRaw(const ABuffer: TBytes; AOffset, ALength: Int32): Int32; override;
  public
    constructor Create(AHandle: THandle);
    /// <summary>The operating system's error number of the last send or receive that failed, 0
    /// when none has since it was cleared.</summary>
    property SocketError: Integer read FSocketError write FSocketError;
    /// <summary>When set, a read waiting for the peer ends as an end of stream.</summary>
    property Cancelled: Boolean read FCancelled write FCancelled;
  end;

  /// <summary>The benign certificate generator fcl-net's TSSLSocketHandler constructor demands:
  /// TlsLib4Pascal never mints self-signed certificates (a server must supply a real
  /// CertificateData.Certificate/PrivateKey), so an attempt to generate one fails loudly rather
  /// than silently.</summary>
  TFclNetNoCertGenerator = class(TX509Certificate)
  public
    function CreateCertificateAndKey: TCertAndKey; override;
  end;

  /// <summary>Process-wide DEFAULTS a freshly created handler adopts at construction, for the
  /// TFPHTTPClient case where fcl-net exposes no handler to configure (it auto-creates one per
  /// connection). Explicit opt-in - everything here is off unless you set it, so trust stays
  /// fail-closed and system trust is never implicit. Per-connection config (a handler you build in
  /// OnGetSocketHandler, or one passed to a raw TInetSocket) still overrides these.</summary>
  TFclNetTrustDefaults = record
  public
    /// <summary>When True, every new handler starts with UseSystemTrust set - so a plain
    /// TFPHTTPClient verifies against the OS store with no OnGetSocketHandler hook. Set once at
    /// startup. Defaults to False.</summary>
    UseSystemTrust: Boolean;
    /// <summary>A crypto provider every new handler starts with (hashing, RNG, cert parsing) - so
    /// an auto-created handler (a plain TFPHTTPClient) uses a custom backend (HSM, FIPS, a test
    /// mock). nil (the default) uses the process-wide shared default. Set once at startup.</summary>
    Crypto: ICryptoProvider;
    /// <summary>A PKIX provider every new handler starts with (certificate parsing, path
    /// validation, revocation). nil (the default) uses the process-wide shared default. Set once
    /// at startup.</summary>
    Pkix: IPkixProvider;
    /// <summary>Whether every new handler starts with TLS session resumption enabled (a server
    /// issues tickets; a client caches and reuses them), so a reconnect skips the asymmetric
    /// handshake. Forward-secret (TLS 1.3 psk_dhe_ke); 0-RTT is never enabled. Defaults to True
    /// (set at unit init); set False at startup to make resumption opt-in.</summary>
    SessionResumption: Boolean;
  end;

  /// <summary>
  /// TlsLib4Pascal's implementation of fcl-net's TSSLSocketHandler. Connect / Accept run the
  /// handshake over Socket.Handle; Send / Recv move application data; Shutdown / Close send
  /// close_notify; BytesAvailable and Select report buffered plaintext. Peer trust is sourced from
  /// fcl-net's native CertificateData slots (CertCA / TrustedCertificate / TrustedCertsDir ->
  /// anchors, Certificate + PrivateKey -> our own credential, ALPNProtocols -> the ALPN list) plus
  /// the extension properties fcl-net lacks (UseSystemTrust, a custom store/verifier, the augment /
  /// async verdict hooks). Verification is governed by VerifyPeerCert: this adapter defaults it
  /// True (secure by default, overriding fcl-net's own False), so real verification runs and fails
  /// closed when no trust source is named. Set VerifyPeerCert := False for the loud dangerous
  /// bypass (system trust is never implicit); a write through the generic handler type counts only
  /// in units that use this one.
  /// fcl-net's SSLType pins the version: stAny offers TLS 1.3 and 1.2, stTLSv1_2 only 1.2, and any
  /// other value fails the handshake.
  /// </summary>
  TTlsLibSocketHandler = class(TSSLSocketHandler)
  strict private
  var
    FConnection: TTlsConnection;
    FUserCrypto: ICryptoProvider;
    FUserPkix: IPkixProvider;
    FSessionResumption: Boolean;
    FLastErrorDesc: string;
    FUseSystemTrust: Boolean;
    FClientAuth: TClientAuthMode;
    FCheckHostName: Boolean;
    FCustomTrustStore: ITrustAnchorStore;
    FCustomServerCertVerifier: IServerCertificateVerifier;
    FCustomClientCertVerifier: IClientCertificateVerifier;
    FAlpnProtocols: TArray<string>;
    FVerifyCallback: TTlsCertificateVerifyCallback;
    FVerdictResolver: TCertificateVerdictResolver;
    FVerdictDeadlineMs: Cardinal;
    FServerVerdictResolver: TCertificateVerdictResolver;
    FServerVerdictDeadlineMs: Cardinal;
    FClientConfig: ITlsClientConfig;
    FServerConfig: ITlsServerConfig;
    FHandshakeTimeoutMs: Integer;
    FVerifyPeerCert: Boolean;
    FSocketTransport: TFclNetSocketTransport;
    FLastSslCode: Integer;
    FInFlight: LongInt;
    FClosing: LongInt;
    FReaderThread: TThreadID;
    /// <summary>Clears the recorded failure at the start of a call.</summary>
    procedure BeginCall;
    /// <summary>Records AError as the failure of the current call when it belongs to a family a
    /// connection is expected to fail with (this library's own exceptions and the stream errors of
    /// reading a configured file), or, with AAnyHookError, when it is anything but a memory,
    /// stack or privilege fault; False for anything else, which the caller must let propagate. A server's
    /// failed accept is freed by fcl-net, so the text recorded there is never read.</summary>
    function RecordFailure(AError: Exception; AAnyHookError: Boolean): Boolean;
    /// <summary>Stops new calls from entering Recv, ends a Recv that is inside and waits for it to
    /// leave; True when none was inside.</summary>
    function EndInFlight: Boolean;
    /// <summary>A fcl-net cert slot as a host-neutral blob source: its inline bytes when present,
    /// else its file path, else empty.</summary>
    class function SslDataBlob(const AData: TSSLData): TTlsBlobSource; static;
    /// <summary>A published string property of CertificateData by name, empty when this fcl-net
    /// lacks it.</summary>
    function CertificateDataText(const AName: string): string;
    /// <summary>The ALPN protocols to offer or select from: AlpnProtocols, or the comma-separated
    /// CertificateData.ALPNProtocols (each name trimmed, empty ones skipped). Both set must name
    /// the same protocols in the same order, else it refuses.</summary>
    function EffectiveAlpnProtocols: TArray<string>;
    /// <summary>Adds the trust anchors of CertificateData.TrustedCertsDir as they are on disk
    /// now; with AConfigSupplied the directory is only noted, as the supplied config conflicts
    /// with it.</summary>
    procedure AddTrustedCertsDir(var AOptions: TTlsOptions; AConfigSupplied: Boolean);
    /// <summary>The host-neutral snapshot the adapter core composes into a TLS configuration: one
    /// value per handshake, so a handler setting changed mid-connection is never seen half-applied.
    /// The role (client vs server) is chosen by the caller when it resolves the config and attaches
    /// the resolver, not here.</summary>
    function Snapshot: TTlsOptions;
    function BuildClientConfig(const AHost: string): ITlsClientConfig;
    function BuildServerConfig: ITlsServerConfig;
    function DriveHandshake(AIsClient: Boolean; const AHost: string): Boolean;
  private
  class var
    // unit-private: FlushTlsLibFclNetConfigCache clears them
    FServerConfigMemo: ITlsServerConfigMemo;
    FClientConfigMemo: ITlsClientConfigMemo;
{$IF FPC_FULLVERSION >= 30203}
  protected
    // fcl-net declares these abstract from 3.2.3
    function GetLastSSLErrorString: string; override;
    function GetLastSSLErrorCode: Integer; override;
{$IFEND}
  public
    class constructor Create;
    constructor Create; override;
    destructor Destroy; override;
    function CreateCertGenerator: TX509Certificate; override;
    function Connect: Boolean; override;
    function Accept: Boolean; override;
    function Close: Boolean; override;
    function Shutdown(BiDirectional: Boolean): Boolean; override;
    function Send(const Buffer; Count: Integer): Integer; override;
    function Recv(const Buffer; Count: Integer): Integer; override;
    function BytesAvailable: Integer; override;
{$IF DECLARED(TSocketStates)}
    function Select(ACheck: TSocketStates; ATimeOut: Integer): TSocketStates; override;
{$IFEND}
{$IF sslbase.StrDataCount >= 3}
    function GetSelectedALPNProtocol: string; override;
{$IFEND}
    /// <summary>The negotiated protocol version once the handshake completes.</summary>
    function NegotiatedVersion: TTlsVersion;
    /// <summary>The negotiated cipher-suite wire codepoint once the handshake completes (0 if none).</summary>
    function NegotiatedCipherSuite: UInt16;
    /// <summary>The negotiated named group (key_share curve) wire codepoint once the handshake
    /// completes (0 if none).</summary>
    function NegotiatedGroup: UInt16;
    /// <summary>The SNI server_name for this connection: the host a client requested (server side)
    /// or the host we sent (client side); empty when none.</summary>
    function PeerServerName: string;
    /// <summary>The Encrypted Client Hello outcome for this connection (RFC 9849).</summary>
    function EchStatus: TEchStatus;
    /// <summary>Whether this connection resumed an earlier session rather than doing a full
    /// handshake (RFC 9846 2.2 / RFC 5246 7.3).</summary>
    function Resumed: Boolean;
    /// <summary>The ALPN protocol the peer selected as text; empty when none was negotiated or
    /// the name is not ASCII (RFC 7301).</summary>
    function NegotiatedAlpn: string;
    /// <summary>A human-readable description of the last Connect/Accept/Send/Recv failure.</summary>
    property LastErrorDesc: string read FLastErrorDesc;
    /// <summary>Opt into the OS system-trust anchors (Windows crypt32 / macOS SecTrust / Unix
    /// bundle). Unions with a CertCA / TrustedCertificate / TrustedCertsDir and any
    /// CustomTrustStore. System trust is never implicit: when verifying you must name at least one
    /// source or the build fails closed. Defaults to False.</summary>
    property UseSystemTrust: Boolean read FUseSystemTrust write FUseSystemTrust;
    /// <summary>Server role: whether to request a client certificate (mutual TLS). None (the
    /// default) never asks; Requested asks and tolerates a client that sends none; Required asks and
    /// aborts when none is presented. Orthogonal to the client-CA the presented chain must reach -
    /// CertCA / TrustedCertificate / TrustedCertsDir or a CustomTrustStore - and a mode other than
    /// None needs one (the build fails closed). UseSystemTrust is a server-certificate source (a
    /// client verifying a server) and is never a client-CA: a mode whose only source is it fails
    /// the build. Per handler, never a process-wide default: set it in the
    /// OnCreateClientSocketHandler hook that builds each server-side handler. Ignored on a client
    /// connection.</summary>
    property ClientAuth: TClientAuthMode read FClientAuth write FClientAuth;
    /// <summary>Whether the peer certificate's identity is checked against the host (RFC 9525).
    /// Defaults to True; set False to verify the chain but not the name.</summary>
    property CheckHostName: Boolean read FCheckHostName write FCheckHostName;
    /// <summary>An injected anchor store; when set it UNIONS with the CertCA / TrustedCertificate /
    /// TrustedCertsDir anchors and UseSystemTrust.</summary>
    property CustomTrustStore: ITrustAnchorStore read FCustomTrustStore
      write FCustomTrustStore;
    /// <summary>A whole-verifier for the peer SERVER certificate (client connections) that
    /// REPLACES the built-in pipeline outright (exclusive of every anchor source).</summary>
    property CustomServerCertificateVerifier: IServerCertificateVerifier
      read FCustomServerCertVerifier write FCustomServerCertVerifier;
    /// <summary>A whole-verifier for the peer CLIENT certificate (mTLS server connections) that
    /// REPLACES the built-in pipeline outright.</summary>
    property CustomClientCertificateVerifier: IClientCertificateVerifier
      read FCustomClientCertVerifier write FCustomClientCertVerifier;
    /// <summary>The ALPN protocols to offer (client) or select from (server), most-preferred
    /// first (e.g. ['h2', 'http/1.1']). Empty offers none. A CertificateData.ALPNProtocols that
    /// names a different list refuses.</summary>
    property AlpnProtocols: TArray<string> read FAlpnProtocols write FAlpnProtocols;
    /// <summary>An augment-only peer-certificate hook: it runs after the built-in pipeline and can
    /// only additionally reject (never loosen it). On a server it vets the client chain, under
    /// client authentication only (the host name is empty); a server that requests no client
    /// certificate refuses to build with it.</summary>
    property VerifyCallback: TTlsCertificateVerifyCallback read FVerifyCallback
      write FVerifyCallback;
    /// <summary>The CLIENT-role verdict resolver: when assigned, a client handshake parks after
    /// the pipeline accepts the SERVER's chain and this resolves it out-of-band (e.g. live
    /// OCSP/CRL over a server-auth trust engine); augment-only, fail-closed. For an mTLS server
    /// that must vet the CLIENT chain use ServerVerdictResolver - the two roles bind different
    /// EKUs, so one resolver cannot serve both.</summary>
    property VerdictResolver: TCertificateVerdictResolver read FVerdictResolver
      write FVerdictResolver;
    /// <summary>The fetch budget (ms) the client-role resolver is given; 0 leaves it to the
    /// resolver.</summary>
    property VerdictDeadlineMs: Cardinal read FVerdictDeadlineMs
      write FVerdictDeadlineMs;
    /// <summary>The SERVER-role verdict resolver: when assigned, a server handshake that requests
    /// a client certificate parks after the pipeline accepts the CLIENT's chain and this resolves
    /// it out-of-band (live client-cert revocation over a client-auth trust engine); augment-only,
    /// fail-closed. A server that requests no client certificate refuses to build with it.</summary>
    property ServerVerdictResolver: TCertificateVerdictResolver read FServerVerdictResolver
      write FServerVerdictResolver;
    /// <summary>The fetch budget (ms) the server-role resolver is given; 0 leaves it to the
    /// resolver.</summary>
    property ServerVerdictDeadlineMs: Cardinal read FServerVerdictDeadlineMs
      write FServerVerdictDeadlineMs;
    /// <summary>A fully-built client config that REPLACES the property-driven build: when set, the
    /// cert/trust properties (CertificateData trust/cert, UseSystemTrust, a custom store/verifier,
    /// ALPN) and a pinned SSLType are not allowed alongside it (the handler raises). The verdict resolvers
    /// (VerdictResolver/ServerVerdictResolver) still apply - runtime stream hooks, not part of the
    /// frozen config - provided the supplied config itself armed the deferral
    /// (WithLiveRevocationVerdict/WithAsyncCertificateVerdict), else the handshake never parks. The
    /// escape hatch to the full builder API - cipher order, groups, resumption. For a stock
    /// TFPHTTPClient, set it in an OnGetSocketHandler hook.</summary>
    property ClientConfig: ITlsClientConfig read FClientConfig write FClientConfig;
    /// <summary>A fully-built server config that REPLACES the property-driven build (the server-side
    /// counterpart of ClientConfig; same conflict rule).</summary>
    property ServerConfig: ITlsServerConfig read FServerConfig write FServerConfig;
    /// <summary>The crypto provider the property-driven build uses (hashing, RNG, cert parsing);
    /// seeded from TlsLibFclNetTrustDefaults.Crypto at construction. nil uses the process-wide
    /// shared default; set it to inject a custom backend (HSM, FIPS, a test mock). Not allowed
    /// alongside a supplied ClientConfig/ServerConfig, which carries its own provider.</summary>
    property Crypto: ICryptoProvider read FUserCrypto write FUserCrypto;
    /// <summary>The PKIX provider the property-driven build uses (certificate parsing, path
    /// validation, revocation); seeded from TlsLibFclNetTrustDefaults.Pkix at construction. nil uses
    /// the process-wide shared default; set it to inject a custom backend. Not allowed alongside a
    /// supplied ClientConfig/ServerConfig, which carries its own PKIX provider.</summary>
    property Pkix: IPkixProvider read FUserPkix write FUserPkix;
    /// <summary>TLS session resumption (a server issues session tickets; a client caches and reuses
    /// them), so a reconnect skips the asymmetric handshake. Forward-secret (TLS 1.3 psk_dhe_ke);
    /// 0-RTT is never enabled. Seeded from TlsLibFclNetTrustDefaults.SessionResumption (True); set
    /// False to force a full handshake every connection.</summary>
    property SessionResumption: Boolean read FSessionResumption write FSessionResumption;
    /// <summary>The time budget (ms) for the whole handshake, so a peer that connects but sends no
    /// data cannot park the connection's thread. 0 (the default) falls back to Socket.IOTimeout when
    /// that is set, else the 30 s library default; a positive value overrides both. The cap is
    /// enforced by a wait before each receive.</summary>
    property HandshakeTimeoutMs: Integer read FHandshakeTimeoutMs write FHandshakeTimeoutMs;
  published
    /// <summary>True (the default) verifies the server; False is the dangerous bypass.</summary>
    property VerifyPeerCert: Boolean read FVerifyPeerCert write FVerifyPeerCert;
  end;

  /// <summary>Carries a VerifyPeerCert write through the generic handler type to our switch, in
  /// units that use this one.</summary>
  TFclNetVerifyPeerCertHelper = class helper for TSSLSocketHandler
  strict private
    function GetVerifyPeerCert: Boolean;
    procedure SetVerifyPeerCert(AValue: Boolean);
  private
    function BaseVerifyPeerCert: Boolean;
  public
    property VerifyPeerCert: Boolean read GetVerifyPeerCert write SetVerifyPeerCert;
  end;

var
  /// <summary>The process-wide handler defaults (see TFclNetTrustDefaults). Off by default; set a
  /// field once at startup to make the common case need no per-connection hook.</summary>
  TlsLibFclNetTrustDefaults: TFclNetTrustDefaults;

/// <summary>Clears the process-wide build-once config caches so the next handshake rebuilds from
/// current inputs. Call after rotating a certificate/key to purge the retired credential (a cached
/// config holds its private key alive). Call only with no TLS traffic in flight.</summary>
procedure FlushTlsLibFclNetConfigCache;

implementation

resourcestring
  SFclNetSslTypeUnsupported = 'SSLType selects a protocol this library does not implement; ' +
    'use stAny or stTLSv1_2';
  SFclNetCipherListHint = 'CertificateData.CipherList';
  SFclNetSendNoProgress = 'fcl-net socket send returned no progress';
  SFclNetNoSession = 'no TLS session is established on this socket';
  SPeerVerifyRejected = 'the OnVerifyCertificate handler rejected the peer certificate';
  SNoSelfSignedCerts = 'TlsLib4Pascal does not generate self-signed certificates; supply ' +
    'CertificateData.Certificate and CertificateData.PrivateKey, or CertificateData.PFX';
  SFclNetCredentialSourcesConflict = 'CertificateData sets PFX together with Certificate or ' +
    'PrivateKey; set one source for the credential';
  SFclNetCertCASourcesConflict = 'CertificateData.CertCA sets both Value and FileName; set one ' +
    'source for the CA';
  SFclNetAlpnSourcesConflict = 'AlpnProtocols and CertificateData.ALPNProtocols disagree; set ' +
    'one list';
  SFclNetCredentialSourceHint = 'CertificateData.Certificate and PrivateKey, or ' +
    'CertificateData.PFX';
  SNoHostForNameCheck = 'CheckHostName is on but the socket carries no host to verify the ' +
    'certificate identity against (RFC 9525); connect through a TInetSocket that carries the ' +
    'host, or set CheckHostName := False to skip the host-name check';
  SFclNetTrustSourceHint = 'CertificateData.CertCA / TrustedCertificate / TrustedCertsDir, ' +
    'UseSystemTrust, or a CustomTrustStore/CustomVerifier';
  SFclNetBaseVerifyIgnored = '(VerifyPeerCert was set False by code that does not use ' +
    'TlsLibFclNetTls, such as fcl-web''s VerifySSLCertificate; that write is ignored)';
  SFclNetClientAuthSourceHint = 'CertificateData.CertCA / TrustedCertificate / TrustedCertsDir, ' +
    'or a CustomTrustStore/CustomVerifier';
  SFclNetTrustedCertsDirNone = 'CertificateData.TrustedCertsDir ''%s'' names no directory';
  SFclNetTrustedCertsDirMissing = 'CertificateData.TrustedCertsDir names ''%s'', which is not a ' +
    'directory';
  SFclNetTrustedCertsDirUnreadable = 'CertificateData.TrustedCertsDir names ''%s'', which ' +
    'cannot be read';
  SFclNetTrustedCertsDirFileUnreadable = 'CertificateData.TrustedCertsDir file ''%s'' cannot be ' +
    'read: %s';
  SFclNetTrustedCertsDirFileNotPem = 'CertificateData.TrustedCertsDir file ''%s'' holds no ' +
    'PEM certificate';
  SFclNetTrustedCertsDirFileUnnamed = 'CertificateData.TrustedCertsDir file ''%s'' holds a ' +
    'certificate whose subject cannot be hashed';
  SFclNetTrustedCertsDirEmpty = 'CertificateData.TrustedCertsDir ''%s'' holds no hashed ' +
    'certificate files (<hash>.0, <hash>.1, ...); run openssl rehash on it';

const
  ShutdownReadWrite = 2;
  CancelPollMs = 100;

type
  /// <summary>The directory scan behind CertificateData.TrustedCertsDir.</summary>
  THashedCertsDirectory = class sealed(TObject)
  strict private
  type
    /// <summary>What a directory listing reported for one entry.</summary>
    TListedEntry = class
    public
      Attr: Integer;
    end;
    /// <summary>Fills AEntries with the names of ADir, each owning its TListedEntry, sorted and
    /// matched without regard to case; False when ADir cannot be listed.</summary>
    class function ListDirectory(const ADir: string; AEntries: TStringList): Boolean; static;
    /// <summary>Adds to APrefixes the lowercase text before the dot of every entry named as eight
    /// hex digits, a dot and anything.</summary>
    class procedure ListHashedPrefixes(AEntries, APrefixes: TStrings); static;
    /// <summary>Whether the file system has the exact name AName in ADir, given that the listing
    /// matched it as AListedName. A listed name whose case differs is confirmed with an exact
    /// lookup, so the file system decides what a name matches; the attributes found go to
    /// AEntry.</summary>
    class function ConfirmListedName(const ADir, AName, AListedName: string;
      AEntry: TListedEntry): Boolean; static;
    /// <summary>Whether a listed entry, followed once through a link, is a regular file; a link
    /// hands its target's attributes to AEntry.</summary>
    class function ProbeHashedFile(const APath: string; AEntry: TListedEntry): Boolean; static;
    /// <summary>The bytes of a hashed file; a file that cannot be read refuses.</summary>
    class function ReadHashedFile(const APath: string): TBytes; static;
    /// <summary>Appends to AAnchors the certificates of the PEM file APath, whose content is
    /// AContent, that belong under APrefix, and returns how many. A file that is not PEM or holds
    /// no certificate, and a certificate that cannot be named, refuse.</summary>
    class function AppendCertificates(const ACrypto: ICryptoProvider; const APath, APrefix: string;
      const AContent: TBytes; var AAnchors: TArray<TTlsBlobSource>): Integer; static;
  public
    /// <summary>Adds the trust anchors of a directory list the way a hashed certificate directory
    /// is read: per directory, each lowercase hex prefix's files prefix.0, prefix.1, ... up to the
    /// first missing number, all answered from one listing of the directory, each usable file read
    /// once. A certificate is an anchor only when the hash of its subject is the prefix it was
    /// found under.</summary>
    class procedure AppendAnchors(const ACrypto: ICryptoProvider; const ADirs: string;
      var AAnchors: TArray<TTlsBlobSource>); static;
  end;

{ TOpenSslNameHash }

class function TOpenSslNameHash.IsSpace(AByte: Byte): Boolean;
begin
  Result := (AByte = $20) or ((AByte >= $09) and (AByte <= $0D));
end;

class function TOpenSslNameHash.ChildContents(const AParent: TBytes; ATag: Byte;
  out AChildren: TArray<TBytes>): Boolean;
var
  LTag: Byte;
  LPos, LContent, LLength, LNext: Int32;
begin
  Result := False;
  AChildren := nil;
  LPos := 0;
  while LPos < System.Length(AParent) do
  begin
    if not TDer.ReadTlv(AParent, LPos, LTag, LContent, LLength, LNext) or (LTag <> ATag) then
      Exit;
    TArrayUtilities.Append<TBytes>(AChildren, System.Copy(AParent, LContent, LLength));
    LPos := LNext;
  end;
  Result := True;
end;

class function TOpenSslNameHash.ToUtf8(ATag: Byte; const AValue: TBytes;
  out AUtf8: TBytes): Boolean;
var
  LText: UnicodeString;
  LI, LUnits: Int32;
  LCode: UInt32;
begin
  Result := False;
  AUtf8 := nil;
  case ATag of
    TagUtf8String:
      begin
        AUtf8 := TEncoding.UTF8.GetBytes(TEncoding.UTF8.GetString(AValue));
        // a sequence that was not valid UTF-8 does not survive the round trip
        Exit(TArrayUtilities.AreEqual(AUtf8, AValue));
      end;
    TagBmpString:
      begin
        if (System.Length(AValue) mod 2) <> 0 then
          Exit;
        for LI := 0 to System.Length(AValue) div 2 - 1 do
        begin
          LCode := TBinaryPrimitives.ReadUInt16BigEndian(AValue, LI * 2);
          if (LCode >= $D800) and (LCode <= $DFFF) then
            Exit;
        end;
        LText := TEncoding.BigEndianUnicode.GetString(AValue);
      end;
    TagUniversalString:
      begin
        if (System.Length(AValue) mod 4) <> 0 then
          Exit;
        SetLength(LText, System.Length(AValue) div 4 * 2);
        LUnits := 0;
        for LI := 0 to System.Length(AValue) div 4 - 1 do
        begin
          LCode := TBinaryPrimitives.ReadUInt32BigEndian(AValue, LI * 4);
          if (LCode > $10FFFF) or ((LCode >= $D800) and (LCode <= $DFFF)) then
            Exit;
          if LCode < $10000 then
          begin
            Inc(LUnits);
            LText[LUnits] := WideChar(LCode);
          end
          else
          begin
            Dec(LCode, $10000);
            LText[LUnits + 1] := WideChar($D800 + (LCode shr 10));
            LText[LUnits + 2] := WideChar($DC00 + (LCode and $3FF));
            Inc(LUnits, 2);
          end;
        end;
        SetLength(LText, LUnits);
      end;
    // one byte per character, read as Latin-1
    TagPrintableString, TagT61String, TagIa5String:
      begin
        SetLength(LText, System.Length(AValue));
        for LI := 0 to System.High(AValue) do
          LText[LI + 1] := WideChar(AValue[LI]);
      end;
  else
    Exit;
  end;
  AUtf8 := TEncoding.UTF8.GetBytes(LText);
  Result := True;
end;

class function TOpenSslNameHash.Canonical(const AUtf8: TBytes): TBytes;
var
  LFrom, LTo, LI, LCount: Int32;
  LByte: Byte;
begin
  LFrom := 0;
  LTo := System.Length(AUtf8);
  while (LFrom < LTo) and IsSpace(AUtf8[LFrom]) do
    Inc(LFrom);
  while (LTo > LFrom) and IsSpace(AUtf8[LTo - 1]) do
    Dec(LTo);
  Result := nil;
  SetLength(Result, LTo - LFrom);
  LCount := 0;
  LI := LFrom;
  while LI < LTo do
  begin
    LByte := AUtf8[LI];
    if IsSpace(LByte) then
    begin
      LByte := $20;
      while (LI < LTo) and IsSpace(AUtf8[LI]) do
        Inc(LI);
    end
    else
    begin
      if (LByte >= Ord('A')) and (LByte <= Ord('Z')) then
        LByte := LByte + 32;
      Inc(LI);
    end;
    Result[LCount] := LByte;
    Inc(LCount);
  end;
  SetLength(Result, LCount);
end;

class function TOpenSslNameHash.CanonicalAttribute(const AAttribute: TBytes;
  out AEncoded: TBytes): Boolean;
var
  LOidTag, LValueTag: Byte;
  LOidContent, LOidLength, LOidNext, LValueContent, LValueLength, LValueNext: Int32;
  LText, LUtf8: TBytes;
begin
  Result := False;
  AEncoded := nil;
  if not TDer.ReadTlv(AAttribute, 0, LOidTag, LOidContent, LOidLength, LOidNext) or
    (LOidTag <> TagOid) then
    Exit;
  if not TDer.ReadTlv(AAttribute, LOidNext, LValueTag, LValueContent, LValueLength,
    LValueNext) or (LValueNext <> System.Length(AAttribute)) then
    Exit;
  LText := System.Copy(AAttribute, LValueContent, LValueLength);
  // a NumericString is already canonical
  if LValueTag <> TagNumericString then
  begin
    if not ToUtf8(LValueTag, LText, LUtf8) then
      Exit;
    LText := Canonical(LUtf8);
    LValueTag := TagUtf8String;
  end;
  AEncoded := TDer.Tlv(TagSequence, TArrayUtilities.Concat([
    TDer.Tlv(TagOid, System.Copy(AAttribute, LOidContent, LOidLength)),
    TDer.Tlv(LValueTag, LText)]));
  Result := True;
end;

class function TOpenSslNameHash.CanonicalSet(const ASet: TBytes;
  out AEncoded: TBytes): Boolean;
var
  LAttributes, LCanonical: TArray<TBytes>;
  LSwap: TBytes;
  LI, LJ: Int32;
begin
  Result := False;
  AEncoded := nil;
  if not ChildContents(ASet, TagSequence, LAttributes) or (System.Length(LAttributes) = 0) then
    Exit;
  SetLength(LCanonical, System.Length(LAttributes));
  for LI := 0 to System.High(LAttributes) do
    if not CanonicalAttribute(LAttributes[LI], LCanonical[LI]) then
      Exit;
  // the encodings of a SET OF are in ascending order
  for LI := 1 to System.High(LCanonical) do
    for LJ := LI downto 1 do
      if TArrayUtilities.CompareLexicographic(LCanonical[LJ], LCanonical[LJ - 1]) < 0 then
      begin
        LSwap := LCanonical[LJ];
        LCanonical[LJ] := LCanonical[LJ - 1];
        LCanonical[LJ - 1] := LSwap;
      end;
  AEncoded := TDer.Tlv(TagSet, TArrayUtilities.Concat(LCanonical));
  Result := True;
end;

class function TOpenSslNameHash.OfName(const ACrypto: ICryptoProvider;
  const AName: TBytes): string;
var
  LTag: Byte;
  LContent, LLength, LNext, LI: Int32;
  LSets, LCanonical: TArray<TBytes>;
  LAll, LDigest, LPrefix: TBytes;
  LHash: IHash;
begin
  Result := '';
  if (System.Length(AName) > MaxNameLength) or
    not TDer.ReadTlv(AName, 0, LTag, LContent, LLength, LNext) or (LTag <> TagSequence) or
    (LNext <> System.Length(AName)) then
    Exit;
  if not ChildContents(System.Copy(AName, LContent, LLength), TagSet, LSets) then
    Exit;
  SetLength(LCanonical, System.Length(LSets));
  for LI := 0 to System.High(LSets) do
    if not CanonicalSet(LSets[LI], LCanonical[LI]) then
      Exit;
  LAll := TArrayUtilities.Concat(LCanonical);
  LHash := ACrypto.Primitives.CreateHash(THashAlgorithm.SHA_1);
  LHash.Update(LAll, 0, System.Length(LAll));
  LDigest := LHash.DoFinal;
  LPrefix := TBytes.Create(LDigest[3], LDigest[2], LDigest[1], LDigest[0]);
  Result := TDataEncoding.HexEncode(LPrefix);
end;

class function TOpenSslNameHash.SubjectName(const ACertificate: TBytes;
  out AName: TBytes): Boolean;
var
  LCertificate, LTbs: TBytes;
  LTag: Byte;
  LContent, LLength, LNext, LStart, LStep: Int32;
begin
  Result := False;
  AName := nil;
  if not TDer.ReadTlv(ACertificate, 0, LTag, LContent, LLength, LNext) or
    (LTag <> TagSequence) then
    Exit;
  LCertificate := System.Copy(ACertificate, LContent, LLength);
  if not TDer.ReadTlv(LCertificate, 0, LTag, LContent, LLength, LNext) or
    (LTag <> TagSequence) then
    Exit;
  LTbs := System.Copy(LCertificate, LContent, LLength);
  LStart := 0;
  if not TDer.ReadTlv(LTbs, LStart, LTag, LContent, LLength, LNext) then
    Exit;
  if LTag = TagVersion then
  begin
    LStart := LNext;
    if not TDer.ReadTlv(LTbs, LStart, LTag, LContent, LLength, LNext) then
      Exit;
  end;
  // the serial number is read; the signature, issuer and validity are stepped over to the subject
  for LStep := 1 to 4 do
  begin
    LStart := LNext;
    if not TDer.ReadTlv(LTbs, LStart, LTag, LContent, LLength, LNext) then
      Exit;
  end;
  if LTag <> TagSequence then
    Exit;
  AName := System.Copy(LTbs, LStart, LNext - LStart);
  Result := True;
end;

class function TOpenSslNameHash.OfCertificate(const ACrypto: ICryptoProvider;
  const ACertificate: TBytes): string;
var
  LName: TBytes;
begin
  Result := '';
  if SubjectName(ACertificate, LName) then
    Result := OfName(ACrypto, LName);
end;

{ TFclNetSocketTransport }

constructor TFclNetSocketTransport.Create(AHandle: THandle);
begin
  inherited Create;
  FHandle := AHandle;
  TNetOs.ArmAgainstSigPipe(TNetHandle(FHandle));
end;

function TFclNetSocketTransport.WaitReadable(AMs: Int32): Boolean;
var
  LLeftMs, LSliceMs: Int32;
begin
  // sliced waits let Cancelled end a blocked read; on Windows a shutdown or close does not
  LLeftMs := AMs;
  repeat
    LSliceMs := LLeftMs;
    if LSliceMs > CancelPollMs then
      LSliceMs := CancelPollMs;
    Result := TNetOs.Wait(TNetHandle(FHandle), TNetWait.Readable, LSliceMs);
    Dec(LLeftMs, LSliceMs);
  until Result or FCancelled or (LLeftMs <= 0);
  // a cancelled wait ends as readable so the receive that follows reports the end
  Result := Result or FCancelled;
end;

function TFclNetSocketTransport.ReceiveRaw(var ABuffer: TBytes; AOffset,
  AMaxLength: Int32): Int32;
var
  LErr: Integer;
begin
  repeat
  until WaitReadable(CancelPollMs);
  if FCancelled then
    Exit(0);
  Result := TNetOs.ReceiveBytes(TNetHandle(FHandle), ABuffer, AOffset, AMaxLength);
  if Result >= 0 then
    Exit; // > 0 bytes, or 0 for an orderly close (the pump reports a truncated handshake)
  // a reset or a broken pipe is a receive failure carrying its errno, not an orderly end of stream
  LErr := TNetOs.LastError;
  if LErr > 0 then
    Result := -LErr
  else
    Result := -1;
  FSocketError := LErr;
end;

function TFclNetSocketTransport.SendRaw(const ABuffer: TBytes; AOffset,
  ALength: Int32): Int32;
begin
  Result := TNetOs.SendBytes(TNetHandle(FHandle), ABuffer, AOffset, ALength);
  if Result < 0 then
    FSocketError := TNetOs.LastError;
  if Result <= 0 then
    raise ETlsStreamError.CreateRes(@SFclNetSendNoProgress);
end;

{ TFclNetNoCertGenerator }

function TFclNetNoCertGenerator.CreateCertificateAndKey: TCertAndKey;
begin
  Result := Default(TCertAndKey);
  raise ESSLSocketError.Create(SNoSelfSignedCerts);
end;

{ TTlsLibSocketHandler }

class constructor TTlsLibSocketHandler.Create;
begin
  FServerConfigMemo := TTlsConfigMemos.NewServer;
  FClientConfigMemo := TTlsConfigMemos.NewClient;
end;

constructor TTlsLibSocketHandler.Create;
begin
  inherited Create;
  FCheckHostName := True;
  // client authentication is per-handler and never a process-wide default: an app-wide UseSystemTrust
  // (below) meant for HTTP clients must not escalate a server into mTLS
  FClientAuth := TClientAuthMode.None;
  // adopt the process-wide opt-in defaults (off unless the app set them); fcl-net auto-creates the
  // handler for TFPHTTPClient, so this is the only place a global "use the OS store" preference can
  // reach it. A per-connection handler still overrides afterwards.
  FUseSystemTrust := TlsLibFclNetTrustDefaults.UseSystemTrust;
  FUserCrypto := TlsLibFclNetTrustDefaults.Crypto;
  FUserPkix := TlsLibFclNetTrustDefaults.Pkix;
  FSessionResumption := TlsLibFclNetTrustDefaults.SessionResumption;
  // verify by default; the base switch also starts True so the failure hint fires only on a reset
  VerifyPeerCert := True;
  inherited VerifyPeerCert := True;
end;

destructor TTlsLibSocketHandler.Destroy;
begin
  // for a host that frees without Close
  EndInFlight;
  FConnection.Free;
  FConnection := nil;
  FSocketTransport := nil;
  inherited Destroy;
end;

procedure TTlsLibSocketHandler.BeginCall;
begin
  FLastError := 0;
  FLastErrorDesc := '';
  FLastSslCode := 0;
  if FSocketTransport <> nil then
    FSocketTransport.SocketError := 0;
end;

function TTlsLibSocketHandler.RecordFailure(AError: Exception; AAnyHookError: Boolean): Boolean;
begin
  Result := (AError is EBaseTlsLibException) or (AError is EStreamError) or
    (AAnyHookError and not ((AError is EAccessViolation) or (AError is EStackOverflow) or
    (AError is EPrivilege) or (AError is EHeapMemoryError)));
  if not Result then
    Exit;
  FLastError := 1;
  FLastErrorDesc := AError.Message;
  FLastSslCode := 0;
  if (AError is ETlsStreamError) and ETlsStreamError(AError).HasAlert then
    FLastSslCode := ETlsStreamError(AError).Alert.ToByte
  else if AError is EFatalAlertTlsLibException then
    FLastSslCode := EFatalAlertTlsLibException(AError).AlertDescription.ToByte;
  if (FSocketTransport <> nil) and (FSocketTransport.SocketError <> 0) then
    FLastError := FSocketTransport.SocketError;
end;

function TTlsLibSocketHandler.EndInFlight: Boolean;
begin
  // flag then count here, count then flag in Recv: one side always sees the other
  InterlockedExchange(FClosing, 1);
  if FSocketTransport <> nil then
    FSocketTransport.Cancelled := True;
  Result := InterlockedCompareExchange(FInFlight, 0, 0) = 0;
  if Result then
    Exit;
  if Socket <> nil then
    fpShutdown(Socket.Handle, ShutdownReadWrite);
  // the reader's own thread would never see the count fall
  if FReaderThread = GetCurrentThreadId then
    Exit;
  while InterlockedCompareExchange(FInFlight, 0, 0) > 0 do
    Sleep(1);
end;

{$IF FPC_FULLVERSION >= 30203}
function TTlsLibSocketHandler.GetLastSSLErrorString: string;
begin
  Result := FLastErrorDesc;
end;

function TTlsLibSocketHandler.GetLastSSLErrorCode: Integer;
begin
  // the alert the failure carries, which a local refusal may name without sending, 0 when none
  Result := FLastSslCode;
end;
{$IFEND}

function TTlsLibSocketHandler.CreateCertGenerator: TX509Certificate;
begin
  // the base constructor stores this; we never mint certificates, so hand back a placeholder that
  // refuses rather than the base's outright raise (which would break construction)
  Result := TFclNetNoCertGenerator.Create;
end;

class function TTlsLibSocketHandler.SslDataBlob(
  const AData: TSSLData): TTlsBlobSource;
begin
  // each fcl-net cert slot holds EITHER inline bytes OR a file path; prefer the bytes
  if System.Length(AData.Value) > 0 then
    Result := TTlsBlobSource.FromBytes(AData.Value)
  else
    Result := TTlsBlobSource.FromFile(AData.FileName);
end;

function TTlsLibSocketHandler.CertificateDataText(const AName: string): string;
begin
  // the slot exists only in newer fcl-net, so it is read by name
  if GetPropInfo(CertificateData, AName,
    [tkSString, tkLString, tkAString, tkWString, tkUString]) <> nil then
    Result := GetStrProp(CertificateData, AName)
  else
    Result := '';
end;

function TTlsLibSocketHandler.EffectiveAlpnProtocols: TArray<string>;
var
  LNames: TArray<string>;
  LSlot: TArray<string>;
  LName: string;
  LI: Integer;
begin
  Result := FAlpnProtocols;
  LNames := CertificateDataText('ALPNProtocols').Split([',']);
  LSlot := nil;
  for LI := 0 to System.High(LNames) do
  begin
    LName := Trim(LNames[LI]);
    if LName <> '' then
      TArrayUtilities.Append<string>(LSlot, LName);
  end;
  if System.Length(LSlot) = 0 then
    Exit;
  if System.Length(Result) = 0 then
    Exit(LSlot);
  // fcl-web's h2 server writes its own list into the slot, so an equal list is not a conflict
  if TArrayUtilities.AreEqual<string>(Result, LSlot) then
    Exit;
  raise ETlsStreamError.CreateRes(TTlsAlertDescription.InternalError,
    @SFclNetAlpnSourcesConflict);
end;

{ THashedCertsDirectory }

class function THashedCertsDirectory.ListDirectory(const ADir: string;
  AEntries: TStringList): Boolean;
var
  LFind: TSearchRec;
  LEntry: TListedEntry;
begin
  Result := FindFirst(ADir + '*', faAnyFile or faSymLink, LFind) = 0;
  if not Result then
    Exit;
  try
    AEntries.OwnsObjects := True;
    // the volume, not the platform, decides case; matches are confirmed by ConfirmListedName
    AEntries.CaseSensitive := False;
    repeat
      LEntry := TListedEntry.Create;
      AEntries.AddObject(LFind.Name, LEntry);
      LEntry.Attr := LFind.Attr;
    until FindNext(LFind) <> 0;
    AEntries.Sorted := True;
  finally
    FindClose(LFind);
  end;
end;

class procedure THashedCertsDirectory.ListHashedPrefixes(AEntries, APrefixes: TStrings);
var
  LName: string;
  LDigits: TBytes;
  LI: Integer;
begin
  for LI := 0 to AEntries.Count - 1 do
  begin
    LName := AEntries[LI];
    if (System.Length(LName) >= 9) and (LName[9] = '.') and
      TDataEncoding.TryHexDecode(System.Copy(LName, 1, 8), LDigits) then
      APrefixes.Add(LowerCase(System.Copy(LName, 1, 8)));
  end;
end;

class function THashedCertsDirectory.ConfirmListedName(const ADir, AName,
  AListedName: string; AEntry: TListedEntry): Boolean;
var
  LFind: TSearchRec;
begin
  Result := AListedName = AName;
  if Result then
    Exit;
  Result := FindFirst(ADir + AName, faAnyFile or faSymLink, LFind) = 0;
  if Result then
  begin
    AEntry.Attr := LFind.Attr;
    FindClose(LFind);
  end;
end;

class function THashedCertsDirectory.ReadHashedFile(const APath: string): TBytes;
var
  LStream: TFileStream;
  LSize: Int64;
begin
  try
    LStream := TFileStream.Create(APath, fmOpenRead or fmShareDenyWrite);
    try
      LSize := LStream.Size;
      SetLength(Result, LSize);
      if LSize > 0 then
        LStream.ReadBuffer(Result[0], LSize);
    finally
      LStream.Free;
    end;
  except
    on E: EStreamError do
      raise ETlsStreamError.CreateResFmt(TTlsAlertDescription.InternalError,
        @SFclNetTrustedCertsDirFileUnreadable, [APath, E.Message]);
  end;
end;

class function THashedCertsDirectory.AppendCertificates(const ACrypto: ICryptoProvider;
  const APath, APrefix: string; const AContent: TBytes;
  var AAnchors: TArray<TTlsBlobSource>): Integer;
var
  LBlocks: TArray<TPemBlock>;
  LI: Integer;
  LHashedName: string;
  LHasCertificate: Boolean;
begin
  Result := 0;
  try
    LBlocks := TPem.ReadBlocks(AContent);
  except
    on EArgumentTlsLibException do
      raise ETlsStreamError.CreateResFmt(TTlsAlertDescription.InternalError,
        @SFclNetTrustedCertsDirFileNotPem, [APath]);
  end;
  LHasCertificate := False;
  for LI := 0 to System.High(LBlocks) do
  begin
    if LBlocks[LI].PemType <> 'CERTIFICATE' then
      Continue;
    LHasCertificate := True;
    LHashedName := TOpenSslNameHash.OfCertificate(ACrypto, LBlocks[LI].Content);
    if LHashedName = '' then
      raise ETlsStreamError.CreateResFmt(TTlsAlertDescription.InternalError,
        @SFclNetTrustedCertsDirFileUnnamed, [APath]);
    if LHashedName <> APrefix then
      Continue;
    SetLength(AAnchors, System.Length(AAnchors) + 1);
    AAnchors[System.High(AAnchors)] := TTlsBlobSource.FromFileContent(APath, LBlocks[LI].Content);
    Inc(Result);
  end;
  if not LHasCertificate then
    raise ETlsStreamError.CreateResFmt(TTlsAlertDescription.InternalError,
      @SFclNetTrustedCertsDirFileNotPem, [APath]);
end;

class function THashedCertsDirectory.ProbeHashedFile(const APath: string;
  AEntry: TListedEntry): Boolean;
var
  LFind: TSearchRec;
begin
  if (AEntry.Attr and faSymLink) <> 0 then
  begin
    // the listing saw the link itself; what it points at is one more stat
    if FindFirst(APath, faAnyFile, LFind) <> 0 then
      Exit(False);
    AEntry.Attr := LFind.Attr;
    FindClose(LFind);
  end;
  Result := (AEntry.Attr and (faDirectory or faSysFile)) = 0;
end;

class procedure THashedCertsDirectory.AppendAnchors(const ACrypto: ICryptoProvider;
  const ADirs: string; var AAnchors: TArray<TTlsBlobSource>);
var
  LSegments: TArray<string>;
  LSeen, LPrefixes, LEntries: TStringList;
  LEntry: TListedEntry;
  LDir, LName, LPath: string;
  LI, LP, LNumber, LIndex, LFound, LNamed: Integer;
  LExists: Boolean;
begin
  LSegments := ADirs.Split([PathSep]);
  LSeen := TStringList.Create;
  LPrefixes := TStringList.Create;
  LEntries := TStringList.Create;
  try
    LSeen.CaseSensitive := True;
    LPrefixes.Sorted := True;
    LPrefixes.Duplicates := dupIgnore;
    LNamed := 0;
    for LI := 0 to System.High(LSegments) do
    begin
      if LSegments[LI] = '' then
        Continue;
      Inc(LNamed);
      LDir := IncludeTrailingPathDelimiter(LSegments[LI]);
      if LSeen.IndexOf(LDir) >= 0 then
        Continue;
      LSeen.Add(LDir);
      if not DirectoryExists(LDir) then
        raise ETlsStreamError.CreateResFmt(TTlsAlertDescription.InternalError,
          @SFclNetTrustedCertsDirMissing, [LSegments[LI]]);
      LEntries.Clear;
      LEntries.Sorted := False;
      if not ListDirectory(LDir, LEntries) then
        raise ETlsStreamError.CreateResFmt(TTlsAlertDescription.InternalError,
          @SFclNetTrustedCertsDirUnreadable, [LSegments[LI]]);
      LPrefixes.Clear;
      ListHashedPrefixes(LEntries, LPrefixes);
      LFound := 0;
      for LP := 0 to LPrefixes.Count - 1 do
      begin
        LNumber := 0;
        repeat
          LName := LPrefixes[LP] + '.' + IntToStr(LNumber);
          LIndex := LEntries.IndexOf(LName);
          LExists := LIndex >= 0;
          if LExists then
          begin
            LEntry := TListedEntry(LEntries.Objects[LIndex]);
            LExists := ConfirmListedName(LDir, LName, LEntries[LIndex], LEntry);
          end;
          if LExists then
          begin
            LPath := LDir + LName;
            if ProbeHashedFile(LPath, LEntry) then
            begin
              Inc(LFound, AppendCertificates(ACrypto, LPath, LPrefixes[LP],
                ReadHashedFile(LPath), AAnchors));
            end;
            Inc(LNumber);
          end;
        until not LExists;
      end;
      if LFound = 0 then
        raise ETlsStreamError.CreateResFmt(TTlsAlertDescription.InternalError,
          @SFclNetTrustedCertsDirEmpty, [LSegments[LI]]);
    end;
    if LNamed = 0 then
      raise ETlsStreamError.CreateResFmt(TTlsAlertDescription.InternalError,
        @SFclNetTrustedCertsDirNone, [ADirs]);
  finally
    LEntries.Free;
    LPrefixes.Free;
    LSeen.Free;
  end;
end;

{ TTlsLibSocketHandler }

procedure TTlsLibSocketHandler.AddTrustedCertsDir(var AOptions: TTlsOptions;
  AConfigSupplied: Boolean);
var
  LCertsDir: string;
begin
  LCertsDir := CertificateDataText('TrustedCertsDir');
  if LCertsDir = '' then
    Exit;
  if AConfigSupplied then
    TArrayUtilities.Append<TTlsBlobSource>(AOptions.TrustAnchors,
      TTlsBlobSource.FromFile(LCertsDir))
  else
    THashedCertsDirectory.AppendAnchors(TTlsConfigComposer.EffectiveCrypto(AOptions), LCertsDir,
      AOptions.TrustAnchors);
end;

function TTlsLibSocketHandler.Snapshot: TTlsOptions;
var
  LAnchors: TArray<TTlsBlobSource>;
begin
  // fcl-net applies the PFX last, over the certificate and key, so both together hide a mistake
  if (not CertificateData.PFX.Empty) and ((not CertificateData.Certificate.Empty) or
    (not CertificateData.PrivateKey.Empty)) then
    raise ETlsStreamError.CreateRes(TTlsAlertDescription.InternalError,
      @SFclNetCredentialSourcesConflict);
  // stock reads only the file of CertCA, while the bytes are what this adapter would use
  if (System.Length(CertificateData.CertCA.Value) > 0) and
    (CertificateData.CertCA.FileName <> '') then
    raise ETlsStreamError.CreateRes(TTlsAlertDescription.InternalError,
      @SFclNetCertCASourcesConflict);
  Result := TTlsOptions.Default;
  Result.Crypto := FUserCrypto;
  Result.Pkix := FUserPkix;
  if not CertificateData.PFX.Empty then
  begin
    Result.Certificate := SslDataBlob(CertificateData.PFX);
    Result.CredentialForm := TTlsCredentialForm.Pkcs12;
  end
  else
  begin
    Result.Certificate := SslDataBlob(CertificateData.Certificate);
    Result.PrivateKey := SslDataBlob(CertificateData.PrivateKey);
  end;
  Result.CredentialSourceHint := SFclNetCredentialSourceHint;
  Result.KeyPassword := CertificateData.KeyPassword;
  // fcl-net exposes two anchor slots; add each only when named so HasClientTrustSource stays honest
  LAnchors := nil;
  if not CertificateData.CertCA.Empty then
  begin
    SetLength(LAnchors, System.Length(LAnchors) + 1);
    LAnchors[System.High(LAnchors)] := SslDataBlob(CertificateData.CertCA);
  end;
  if not CertificateData.TrustedCertificate.Empty then
  begin
    SetLength(LAnchors, System.Length(LAnchors) + 1);
    LAnchors[System.High(LAnchors)] := SslDataBlob(CertificateData.TrustedCertificate);
  end;
  Result.TrustAnchors := LAnchors;
  // UseSystemTrust opts into the OS store through the host-neutral installer seam, so the core
  // never depends on the system-trust package
  if FUseSystemTrust then
    Result.SystemTrust := TSystemTrustInstaller.Shared;
  Result.CustomTrustStore := FCustomTrustStore;
  Result.ServerCertificateVerifier := FCustomServerCertVerifier;
  Result.ClientCertificateVerifier := FCustomClientCertVerifier;
  Result.VerifyPeer := VerifyPeerCert;
  Result.InsecureSkipVerify := not VerifyPeerCert;
  Result.CheckHostName := FCheckHostName;
  // SendHostAsSNI governs only the wire; the certificate is still checked against the host
  if SendHostAsSNI then
    Result.ServerNameIndication := TServerNameIndication.Send
  else
    Result.ServerNameIndication := TServerNameIndication.Omit;
  Result.ClientAuth := FClientAuth;
  Result.AlpnProtocols := EffectiveAlpnProtocols;
  Result.VerifyCallback := FVerifyCallback;
  Result.ClientVerdictResolver := FVerdictResolver;
  Result.ClientVerdictDeadlineMs := FVerdictDeadlineMs;
  Result.ServerVerdictResolver := FServerVerdictResolver;
  Result.ServerVerdictDeadlineMs := FServerVerdictDeadlineMs;
  Result.SessionResumption := FSessionResumption;
  Result.HandshakeTimeoutMs := FHandshakeTimeoutMs;
  // a version the host pinned must narrow the offer or fail; ignoring it would silently widen it
  case SSLType of
    stAny:
      ;
    stTLSv1_2:
      Result.SupportedVersions := TArray<UInt16>.Create(TlsWireVersionTls12);
  else
    raise ETlsStreamError.CreateRes(TTlsAlertDescription.InternalError,
      @SFclNetSslTypeUnsupported);
  end;
  Result.CipherSuites := THostCipherList.Parse(CertificateData.CipherList, SFclNetCipherListHint);
  Result.ClientConfig := FClientConfig;
  Result.ServerConfig := FServerConfig;
  Result.CipherSuitesHint := SFclNetCipherListHint;
  Result.TrustSourceHint := SFclNetTrustSourceHint;
  Result.ClientAuthSourceHint := SFclNetClientAuthSourceHint;
end;

function TTlsLibSocketHandler.BuildClientConfig(const AHost: string): ITlsClientConfig;
var
  LOptions: TTlsOptions;
begin
  LOptions := Snapshot;
  AddTrustedCertsDir(LOptions, FClientConfig <> nil);
  // no host to check the certificate name against: fail with the adapter's own message
  if FCheckHostName and (AHost = '') and (FClientConfig = nil) then
    raise ETlsStreamError.CreateRes(TTlsAlertDescription.InternalError, @SNoHostForNameCheck);
  Result := TTlsConfigComposer.ResolveClientConfig(LOptions, FClientConfigMemo, 'ClientConfig');
end;

function TTlsLibSocketHandler.BuildServerConfig: ITlsServerConfig;
var
  LOptions: TTlsOptions;
begin
  LOptions := Snapshot;
  // a server reads anchors only to verify a client certificate
  if (FClientAuth <> TClientAuthMode.None) or (FServerConfig <> nil) then
    AddTrustedCertsDir(LOptions, FServerConfig <> nil);
  // a server never consults VerifyPeerCert (that switch governs a client verifying a server); it
  // requests + verifies a client certificate only when ClientAuth is set, so neutralise both
  // client-oriented verify toggles Snapshot derived from it - their value must not trip the
  // composer's mode-vs-verify guard
  LOptions.VerifyPeer := True;
  LOptions.InsecureSkipVerify := False;
  Result := TTlsConfigComposer.ResolveServerConfig(LOptions, FServerConfigMemo, 'ServerConfig');
end;

function TTlsLibSocketHandler.DriveHandshake(AIsClient: Boolean;
  const AHost: string): Boolean;
var
  LClientConfig: ITlsClientConfig;
  LServerConfig: ITlsServerConfig;
  LEffectiveMs: Integer;
  LTransport: TFclNetSocketTransport;
  LTimed: ITlsTimedTransport;
  LAllowed: Boolean;
begin
  Result := False;
  BeginCall;
  try
    // a reused handler drops any prior session so we rebuild cleanly on the new socket instead of
    // leaking the previous stream over a stale engine
    FConnection.Free;
    FConnection := nil;
    FSocketTransport := nil;
    InterlockedExchange(FClosing, 0);
    // attach the role-correct resolver: a client parks on the server's chain, a server (client
    // auth) on the mTLS client's chain - the two bind different EKUs
    if AIsClient then
    begin
      LClientConfig := BuildClientConfig(AHost);
      LTransport := TFclNetSocketTransport.Create(Socket.Handle);
      LTimed := LTransport;
      FConnection := TTlsConnection.CreateClient(LClientConfig, AHost, LTimed, FVerdictResolver,
        FVerdictDeadlineMs);
    end
    else
    begin
      LServerConfig := BuildServerConfig;
      LTransport := TFclNetSocketTransport.Create(Socket.Handle);
      LTimed := LTransport;
      FConnection := TTlsConnection.CreateServer(LServerConfig, LTimed, FServerVerdictResolver,
        FServerVerdictDeadlineMs);
    end;
    FSocketTransport := LTransport;
    // the handshake read cap: the property when set, else the socket's IOTimeout, else the core
    // connection's one default
    LEffectiveMs := FHandshakeTimeoutMs;
    if LEffectiveMs <= 0 then
      LEffectiveMs := Socket.IOTimeout;
    if LEffectiveMs <= 0 then
      LEffectiveMs := TTlsConnection.DefaultHandshakeTimeoutMs;
    FConnection.Handshake(LEffectiveMs);
    // fcl-net's native OnVerifyCertificate hook runs after our pipeline accepts the chain and can
    // only additionally reject (augment-only, fail-closed)
    LAllowed := False;
    try
      LAllowed := DoVerifyCert;
    finally
      // a hook that raises must reach the peer as a rejection, not an orderly close
      if not LAllowed then
        FConnection.SendAlert(TTlsAlertDescription.BadCertificate);
    end;
    if not LAllowed then
      raise ETlsStreamError.CreateRes(TTlsAlertDescription.BadCertificate,
        @SPeerVerifyRejected);
    SetSSLActive(True);
    Result := True;
  except
    on E: Exception do
    begin
      // a server's accept loop must outlive a callback that raises for one client
      if not RecordFailure(E, not AIsClient) then
        raise;
      if AIsClient and VerifyPeerCert and (not BaseVerifyPeerCert) and
        (FClientConfig = nil) then
        FLastErrorDesc := FLastErrorDesc + ' ' + SFclNetBaseVerifyIgnored;
    end;
  end;
end;

function TTlsLibSocketHandler.Connect: Boolean;
var
  LHost: string;
begin
  LHost := '';
  if Socket is TInetSocket then
    // the name we verify the certificate for, and the SNI unless SendHostAsSNI is False
    LHost := TInetSocket(Socket).Host;
  Result := DriveHandshake(True, LHost);
end;

function TTlsLibSocketHandler.Accept: Boolean;
begin
  Result := DriveHandshake(False, '');
end;

function TTlsLibSocketHandler.Shutdown(BiDirectional: Boolean): Boolean;
begin
  // best effort: flush close_notify, then optionally shut the transport write side. A peer that
  // already vanished must not turn a clean shutdown into an exception.
  if FConnection <> nil then
    FConnection.CloseNotifyQuietly;
  SetSSLActive(False);
  if BiDirectional and (Socket <> nil) then
    fpShutdown(Socket.Handle, 1);
  Result := True;
end;

function TTlsLibSocketHandler.Close: Boolean;
begin
  // fcl-net frees the handler next, so a blocked read is woken and must leave first
  if EndInFlight then
  begin
    Result := Shutdown(False);
    // a Recv that entered while this ran has seen the flag and leaves at once
    EndInFlight;
    Exit;
  end;
  SetSSLActive(False);
  Result := True;
end;

function TTlsLibSocketHandler.Send(const Buffer; Count: Integer): Integer;
begin
  BeginCall;
  // an expected failure becomes -1 and the recorded state; anything else propagates
  try
    if FConnection = nil then
      raise ETlsStreamError.CreateRes(@SFclNetNoSession);
    FConnection.Write(PByte(@Buffer)^, Count);
    Result := Count;
  except
    on E: Exception do
    begin
      if not RecordFailure(E, False) then
        raise;
      Result := -1;
    end;
  end;
end;

function TTlsLibSocketHandler.Recv(const Buffer; Count: Integer): Integer;
begin
  FReaderThread := GetCurrentThreadId;
  InterlockedIncrement(FInFlight);
  try
    // a Close that began first has read the count as zero, so the engine is not entered
    if InterlockedCompareExchange(FClosing, 0, 0) <> 0 then
      Exit(0);
    BeginCall;
    try
      if FConnection = nil then
        raise ETlsStreamError.CreateRes(@SFclNetNoSession);
      // a clean close_notify surfaces as 0 (EOF, no error); an idle read ends retryably after
      // Socket.IOTimeout ms (0 blocks)
      Result := FConnection.Read(PByte(@Buffer)^, Count, Socket.IOTimeout);
    except
      on E: Exception do
      begin
        if not RecordFailure(E, False) then
          raise;
        Result := -1;
      end;
    end;
  finally
    InterlockedDecrement(FInFlight);
  end;
end;

function TTlsLibSocketHandler.BytesAvailable: Integer;
begin
  if FConnection <> nil then
    Result := FConnection.PendingReadBytes
  else
    Result := 0;
end;

{$IF DECLARED(TSocketStates)}
function TTlsLibSocketHandler.Select(ACheck: TSocketStates; ATimeOut: Integer): TSocketStates;
begin
  // plaintext we already decrypted is readable though the socket stays quiet
  if (sosCanRead in ACheck) and (BytesAvailable > 0) then
  begin
    Result := [sosCanRead];
    if ACheck - [sosCanRead] <> [] then
      Result := Result + inherited Select(ACheck - [sosCanRead], 0);
  end
  else
    Result := inherited Select(ACheck, ATimeOut);
end;
{$IFEND}

{$IF sslbase.StrDataCount >= 3}
function TTlsLibSocketHandler.GetSelectedALPNProtocol: string;
begin
  Result := NegotiatedAlpn;
end;
{$IFEND}

function TTlsLibSocketHandler.NegotiatedVersion: TTlsVersion;
begin
  Result := TTlsConnection.InfoOf(FConnection).NegotiatedVersion;
end;

function TTlsLibSocketHandler.NegotiatedCipherSuite: UInt16;
begin
  Result := TTlsConnection.InfoOf(FConnection).CipherSuite;
end;

function TTlsLibSocketHandler.NegotiatedGroup: UInt16;
begin
  Result := TTlsConnection.InfoOf(FConnection).NamedGroup;
end;

function TTlsLibSocketHandler.PeerServerName: string;
begin
  Result := TTlsConnection.InfoOf(FConnection).ServerName;
end;

function TTlsLibSocketHandler.EchStatus: TEchStatus;
begin
  Result := TTlsConnection.InfoOf(FConnection).EchStatus;
end;

function TTlsLibSocketHandler.Resumed: Boolean;
begin
  Result := TTlsConnection.InfoOf(FConnection).Resumed;
end;

function TTlsLibSocketHandler.NegotiatedAlpn: string;
begin
  if not TAlpnProtocols.TryToText(TTlsConnection.InfoOf(FConnection).AlpnProtocol, Result) then
    Result := '';
end;

{ TFclNetVerifyPeerCertHelper }

function TFclNetVerifyPeerCertHelper.BaseVerifyPeerCert: Boolean;
begin
  Result := inherited VerifyPeerCert;
end;

function TFclNetVerifyPeerCertHelper.GetVerifyPeerCert: Boolean;
begin
  if Self is TTlsLibSocketHandler then
    Result := TTlsLibSocketHandler(Self).VerifyPeerCert
  else
    Result := BaseVerifyPeerCert;
end;

procedure TFclNetVerifyPeerCertHelper.SetVerifyPeerCert(AValue: Boolean);
begin
  if Self is TTlsLibSocketHandler then
    TTlsLibSocketHandler(Self).VerifyPeerCert := AValue;
  inherited VerifyPeerCert := AValue;
end;

procedure FlushTlsLibFclNetConfigCache;
begin
  TTlsLibSocketHandler.FServerConfigMemo.Clear;
  TTlsLibSocketHandler.FClientConfigMemo.Clear;
end;

initialization
  TlsLibFclNetTrustDefaults.SessionResumption := True;
  TSSLSocketHandler.SetDefaultHandlerClass(TTlsLibSocketHandler);

end.
