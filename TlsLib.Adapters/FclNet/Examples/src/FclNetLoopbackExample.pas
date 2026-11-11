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
/// A real loopback over fcl-net's TSSLSocketHandler seam on 127.0.0.1: the server is a fcl-net
/// TInetServer whose accepted connections carry our TTlsLibSocketHandler (supplied through
/// OnCreateClientSocketHandler); the client is a fcl-net TInetSocket driven with the same handler
/// class. The server runs on a background thread, the client on the caller's thread. It asserts a
/// full TLS 1.3 handshake, a round-tripped line and a read bounded by IOTimeout when the peer
/// stalls mid-record - proving the fcl-net adapter end to end. Further checks cover a client
/// identity (mutual TLS), an early-closing client, VerifyPeerCert (a False written by fcl-web's
/// compiled code is ignored, one written by code that uses the adapter is honoured), a self-signed
/// leaf trusted as its own anchor, a hashed certificate directory (TrustedCertsDir), ALPN from
/// AlpnProtocols or CertificateData.ALPNProtocols and buffered
/// plaintext (BytesAvailable, Select and CanRead), the recorded failure per family, memory faults
/// that propagate, a server that outlives a raising certificate hook, and a socket closed or a
/// handler freed while another thread is blocked in Recv.
/// </summary>
unit FclNetLoopbackExample;

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

interface

uses
  TlpTlsVersion;

type
  TFclNetLoopbackExample = class sealed(TObject)
  strict private
    class function VersionText(const AVersion: TTlsVersion): string; static;
  public
    /// <summary>Runs the loopback; returns 0 on success, 1 on failure.</summary>
    class function Run: Integer; static;
  end;

implementation

uses
  SysUtils,
  Classes,
  SyncObjs,
  DateUtils,
  TypInfo,
  ssockets,
{$IFDEF UNIX}
  BaseUnix,
{$ENDIF}
{$IF FPC_FULLVERSION >= 30301}
  fpsockets,
{$IFEND}
  sslbase,
  sslsockets,
  Sockets,
  TlpDataEncoding,
  TlpPem,
  TlpTrustTypes,
  TlpIIssuerLookup,
  TlpNegotiationTypes,
  TlpTlsCredential,
  TlpICryptoProvider,
  TlpIPkixProvider,
  TlpDefaultCryptoProvider,
  TlpDefaultPkixProvider,
  TlpITlsConfig,
  TlpITlsConfigBuilder,
  TlpCertificateVerifierSource,
  TlpTlsPresets,
  TlpNetSocket,
  FclNetFclWebMimic,
  TlsLibFclNetTls;

const
  PORT = 28446;
  MUTUAL_PORT = 28456;
  EARLY_CLOSE_PORT = 28457;
  VERIFY_PORT = 28458;
  VERIFY_SELF_PORT = 28459;
  BUFFERED_PORT = 28460;
  CERTS_DIR_PORT = 28461;
  CERTS_DIR_SERVER_PORT = 28462;
  ALPN_PORT = 28463;
  CERTS_DIR_CHAIN_PORT = 28464;
  NO_HASHED_FILES = 'holds no hashed certificate files';
  SKIPPED_HINT = 'cannot be read is skipped';
  BASE_WRITE_HINT = 'that write is ignored';
  UNTRUSTED_CHAIN = 'chain was not trusted'; // the one message any certificate rejection carries
  EARLY_CLOSE_LIMIT_MS = 2000;
  STALL_HOLD_MS = 4000; // how long the server stays silent after the partial record
  READ_CAP_MS = 800;
  ACCEPT_POLL_MS = 100;
  SETTLE_LIMIT_MS = 5000;
  ACCEPT_ERROR_LIMIT = 20; // clients that leave before they are accepted, per server
  ALERT_BAD_CERTIFICATE = 42;
  STALL_LIMIT_MS = 3000; // the socket timeout must end the wait well before the server's silence does
  PING = 'ping from the fclnet client';
  RECV_CYCLES = 50;
  LONG_IO_TIMEOUT_MS = 10000;
  TEARDOWN_LIMIT_MS = 6000; // ending a read must not wait for the read timeout, which is longer
  PADDED_FILE_BYTES = 1048577;
  PARK_MS = 100; // time for the worker to reach its blocking call after it announces itself
  WATCHDOG_MS = 5000;
  DESTROY_GRACE_MS = 300;
  FAULT_BYTES = 16;

type
{$IF FPC_FULLVERSION < 30301}
  TFPSocket = Longint;
{$IFEND}

  TVectorLocator = class sealed(TObject)
  strict private
    class function SearchFrom(const AStart: string): string; static;
    class var FVector: string;
  public
    class procedure Locate; static;
    class function FieldHex(const AName: string): string; static;
    /// <summary>A field of another vector file in the same folder as the main one.</summary>
    class function FieldHexFrom(const AFile, AName: string): string; static;
    class function WriteDer(const AName, AHex: string): string; static;
    /// <summary>Writes the bytes of AHex to the file APath.</summary>
    class procedure WriteDerTo(const APath, AHex: string); static;
    /// <summary>Writes the certificates of AHexes to the file APath, one PEM block labelled
    /// ALabel each, and returns the size of the file.</summary>
    class function WritePemTo(const APath, ALabel: string;
      const AHexes: array of string): Integer; static;
    /// <summary>Appends line feeds to the file APath until it is ASize bytes long.</summary>
    class procedure PadTo(const APath: string; ASize: Integer); static;
  end;

  /// <summary>CertificateData with the slots newer fcl-net adds published here, so the adapter
  /// finds them by name on any fcl-net.</summary>
  TTestCertificateData = class(TCertificateData)
  strict private
  var
    FTrustedCertsDir: string;
    FALPNProtocols: string;
  published
    property TrustedCertsDir: string read FTrustedCertsDir write FTrustedCertsDir;
    property ALPNProtocols: string read FALPNProtocols write FALPNProtocols;
  end;

  TTestCertificateDataHandler = class(TTlsLibSocketHandler)
  public
    function CreateCertificateData: TCertificateData; override;
  end;

  /// <summary>A fcl-net server on 127.0.0.1 that is bound and listening on the caller's thread
  /// before its accept loop starts on its own, so a client that connects once StartListening has
  /// returned always finds the listener.</summary>
  TLoopbackServerBase = class abstract(TThread)
  strict private
  var
    FServer: TInetServer;
    FPort, FConnectionLimit, FAcceptErrors, FIdleTicks: Integer;
  strict protected
  var
    FError: string;
    procedure MakeHandler(Sender: TObject; out AHandler: TSocketHandler); virtual; abstract;
    procedure HandleConnect(Sender: TObject; AStream: TSocketStream); virtual; abstract;
    /// <summary>Ends the accept loop once the thread is terminated.</summary>
    procedure HandleIdle(Sender: TObject); virtual;
    /// <summary>Keeps listening when a few clients left before they were accepted; any other
    /// accept error, or a persistent one, ends the loop and is reported.</summary>
    procedure HandleAcceptError(Sender: TObject; ASocket: TFPSocket; E: Exception;
      var AAction: TAcceptErrorAction);
    procedure Execute; override;
  public
    /// <summary>A server for APort that stops accepting after AConnectionLimit connections; 0
    /// takes them until stopped.</summary>
    constructor Create(APort, AConnectionLimit: Integer);
    destructor Destroy; override;
    /// <summary>Binds and listens, then starts the accept loop; raises why when it
    /// cannot.</summary>
    procedure StartListening;
    /// <summary>Returns once the accept loop has gone idle after the connections made so far,
    /// and raises when it does not.</summary>
    procedure WaitSettled;
    property Error: string read FError;
  end;

  /// <summary>The loopback server: binds 127.0.0.1:PORT, hands each accepted connection a fcl-net
  /// TTlsLibSocketHandler carrying the leaf cert/key, echoes the one line the client sends, then
  /// sends part of a record and goes silent.</summary>
  TServerThread = class(TLoopbackServerBase)
  strict private
  var
    FPeerServerName: string;
    FPfx: TBytes;
    // the accepted connection's handler; the stream owns it and frees it with the stream
    FAccepted: TTlsLibSocketHandler;
  strict protected
    procedure MakeHandler(Sender: TObject; out AHandler: TSocketHandler); override;
    procedure HandleConnect(Sender: TObject; AStream: TSocketStream); override;
  public
    constructor Create(const APfx: TBytes);
    /// <summary>The SNI host_name the client sent, as the server saw it.</summary>
    property PeerServerName: string read FPeerServerName;
  end;

  /// <summary>A server that requires a client certificate and serves one connection, counting the
  /// ones that reached it. A client turned away in the handshake is not an accepted connection, so
  /// the loop ends after the first one that authenticates.</summary>
  TMutualServerThread = class(TLoopbackServerBase)
  strict private
  var
    FPfx: TBytes;
    FRootFile, FCertsDir: string;
    FServed, FAttempts: Integer;
    FHookFault: ExceptClass;
    procedure VerifyHook(Sender: TObject; var AAllow: Boolean);
  strict protected
    procedure MakeHandler(Sender: TObject; out AHandler: TSocketHandler); override;
    procedure HandleConnect(Sender: TObject; AStream: TSocketStream); override;
  public
    constructor Create(const APfx: TBytes; const ARootFile: string);
    /// <summary>Set before StartListening: a TrustedCertsDir that vouches for clients in place of
    /// the root file.</summary>
    property CertsDir: string read FCertsDir write FCertsDir;
    /// <summary>Set before StartListening: the handler's OnVerifyCertificate raises this class
    /// for the first connection and allows the others.</summary>
    property HookFault: ExceptClass read FHookFault write FHookFault;
    property Served: Integer read FServed;
    /// <summary>Connections that reached the server, so a missing one is not read as a
    /// rejection.</summary>
    property Attempts: Integer read FAttempts;
  end;

  /// <summary>A server that records how long its TLS accept takes to give up on a client that
  /// connects and closes before sending a ClientHello.</summary>
  TEarlyCloseServerThread = class(TLoopbackServerBase)
  strict private
  var
    FPfx: TBytes;
    FSettled: TEvent;
    FAttemptAt: TDateTime;
    FSettledMs: Int64;
  strict protected
    procedure MakeHandler(Sender: TObject; out AHandler: TSocketHandler); override;
    procedure HandleConnect(Sender: TObject; AStream: TSocketStream); override;
    procedure HandleIdle(Sender: TObject); override;
  public
    constructor Create(const APfx: TBytes; ASettled: TEvent);
    /// <summary>From the connection reaching the server to its accept loop being idle again.</summary>
    property SettledMs: Int64 read FSettledMs;
  end;

  /// <summary>A server presenting one certificate and key, which echoes the line each client
  /// sends, or with a Greeting writes it in one go and holds the connection open instead; it
  /// takes every connection until stopped.</summary>
  TVerifyServerThread = class(TLoopbackServerBase)
  strict private
  var
    FCertificate, FPrivateKey, FGreeting: TBytes;
    FCertsDir, FAlpnSlot: string;
    FAlpnList: TArray<string>;
  strict protected
    procedure MakeHandler(Sender: TObject; out AHandler: TSocketHandler); override;
    procedure HandleConnect(Sender: TObject; AStream: TSocketStream); override;
  public
    constructor Create(const ACertificate, APrivateKey: TBytes; APort: Integer);
    /// <summary>Set before StartListening: bytes written to each client in one write, which the
    /// server then holds open without reading.</summary>
    property Greeting: TBytes read FGreeting write FGreeting;
    /// <summary>Set before StartListening: a TrustedCertsDir the server's handler names, which a
    /// server requesting no client certificate does not read.</summary>
    property CertsDir: string read FCertsDir write FCertsDir;
    /// <summary>Set before StartListening: the server's CertificateData.ALPNProtocols.</summary>
    property AlpnSlot: string read FAlpnSlot write FAlpnSlot;
    /// <summary>Set before StartListening: the server's AlpnProtocols.</summary>
    property AlpnList: TArray<string> read FAlpnList write FAlpnList;
  end;

  TVerifyClient = class sealed(TObject)
  public
    /// <summary>Connects the handler (which the socket then owns) to the server on APort, sends a
    /// line and returns the echo; AError carries why when the connection or the echo fails.</summary>
    class function Echo(const AHandler: TTlsLibSocketHandler; APort: Integer;
      out AError: string): string; static;
  end;

  /// <summary>A user handler class registered as fcl-net's default class.</summary>
  TVerifySubclassHandler = class(TTlsLibSocketHandler)
  end;

  /// <summary>A handler class that is none of ours, only to hold a switch.</summary>
  TVerifyStockHandler = class(TSSLSocketHandler)
{$IF FPC_FULLVERSION >= 30203}
  protected
    function GetLastSSLErrorString: string; override;
    function GetLastSSLErrorCode: Integer; override;
{$IFEND}
  public
    function CreateCertGenerator: TX509Certificate; override;
  end;

  TVerifyIgnoredCheck = class sealed(TObject)
  public
    /// <summary>A VerifyPeerCert False written by code that does not use this adapter, as fcl-web
    /// clients do, does not switch verification off, and the refusal says so.</summary>
    class procedure Run; static;
  end;

  TVerifyHonouredCheck = class sealed(TObject)
  public
    /// <summary>A VerifyPeerCert False written by code that uses this adapter skips verification,
    /// by property, by name and through the generic type, and an untouched handler verifies.</summary>
    class procedure Run; static;
  end;

  TSelfSignedLeafCheck = class sealed(TObject)
  public
    /// <summary>A self-signed leaf named in TrustedCertificate or CertCA is trusted as its own
    /// anchor, for the host name it carries.</summary>
    class procedure Run; static;
  end;

  TEarlyCloseCheck = class sealed(TObject)
  public
    /// <summary>The server's accept of a client that closes before its ClientHello returns
    /// promptly, not after the handshake cap.</summary>
    class procedure Run; static;
  end;

  TMutualTlsCheck = class sealed(TObject)
  strict private
    /// <summary>Whether a PFX beside a Certificate is refused with both properties named.</summary>
    class function RefusesTwoSources(const APfx: TBytes; const ARootFile: string): Boolean; static;
    /// <summary>AError says the server turned the client away with an alert; a reset, a timeout
    /// or a refused connection fails.</summary>
    class procedure ExpectAlertRefusal(const AWhat, AError: string); static;
  public
    /// <summary>Connects to the mutual server trusting ARootFile, with the PKCS#12 identity when
    /// asked, and returns the echo; AError carries why when there is none and AAlert the alert
    /// byte recorded for it. A client that does not write leaves nothing unread at the server,
    /// so its refusal cannot turn into a reset.</summary>
    class function Echo(const APfx: TBytes; const ARootFile: string;
      AWithIdentity, AWrite: Boolean; out AError: string; out AAlert: Integer): string; static;
    /// <summary>A client that presents the PKCS#12 identity authenticates to a server requiring a
    /// certificate, and one that presents none is turned away.</summary>
    class procedure Run; static;
    /// <summary>A certificate hook that raises while a server accepts one client costs that client
    /// only, with an alert, not the server's accept loop.</summary>
    class procedure RunHookFault; static;
    /// <summary>A memory, stack or privilege fault from the hook stops the server's accept
    /// loop instead of being turned into a failed connection.</summary>
    class procedure RunHookMemoryFault; static;
  end;

  TBufferedPlaintextCheck = class sealed(TObject)
  public
    /// <summary>A server that writes AGreeting in one write and holds the connection open; with
    /// no greeting it echoes what a client sends.</summary>
    class function Serve(const AGreeting: TBytes): TVerifyServerThread; static;
    /// <summary>Connects a handler (which the returned socket owns) that trusts the test
    /// root.</summary>
    class function Open(out AHandler: TTlsLibSocketHandler): TInetSocket; static;
    /// <summary>Plaintext decrypted ahead of a read is counted by BytesAvailable and the quiet
    /// socket does not show it.</summary>
    class procedure RunPending; static;
{$IF DECLARED(TSocketStates)}
    /// <summary>The socket's Select and CanRead report the buffered plaintext as
    /// readable.</summary>
    class procedure RunSelect; static;
    /// <summary>A record larger than one read leaves the rest readable.</summary>
    class procedure RunLargeRecord; static;
{$IFEND}
  end;

  /// <summary>The subject-name hash against names whose hashes the openssl tool printed, names
  /// that must have none, random names that differ only in case, spacing and string type, and
  /// random corruptions of a name.</summary>
  TNameHashCheck = class sealed(TObject)
  strict private
    class function NextRandom(var AState: UInt32): UInt32; static;
    /// <summary>A name of one common name, ASCII AText held in a string of
    /// AStringType.</summary>
    class function CommonName(AStringType: Byte; const AText: string): TBytes; static;
    class procedure RunVectors(const ACrypto: ICryptoProvider); static;
    class procedure RunMalformed(const ACrypto: ICryptoProvider); static;
    /// <summary>Names that differ in case, in spacing and in string type share a hash.</summary>
    class procedure RunEquivalent(const ACrypto: ICryptoProvider); static;
    /// <summary>A corruption never raises, and some but not all corrupted names still
    /// hash.</summary>
    class procedure RunCorruptions(const ACrypto: ICryptoProvider); static;
  public
    class procedure Run(const ACrypto: ICryptoProvider); static;
  end;

  /// <summary>The verdicts the checks that connect a client and compare what came back
  /// share.</summary>
  TConnectCheckBase = class abstract(TObject)
  strict protected
    /// <summary>AGot is what AWanted names; AError says why not.</summary>
    class procedure ExpectEquals(const ATest, AWanted, AGot, AError: string); static;
    /// <summary>The connection is refused, and the reason carries AReason.</summary>
    class procedure ExpectRefused(const ATest, AGot, AError, AReason: string); static;
  end;

  TTrustedCertsDirCheck = class sealed(TConnectCheckBase)
  strict private
  const
    // the subject hashes of the test roots as the openssl tool prints them
    RootHash = '9e452842';
    OtherHash = '3cb0a192';
    ClientAuthRootHash = '8f672146';
    // the subject hashes of the reissued root, its issuer and the leaf below it
    ChainRootHash = '8a26f184';
    ChainIssuerHash = '1d54645b';
    ChainLeafHash = 'ce275665';
    // a self-signed root with the subject of root_cert and a key of its own
    LookalikeRootHex =
      '3082018230820128a0030201020214793a5194ee53d879814ad64345bcebab21' +
      '62ef7f300a06082a8648ce3d040302301e311c301a06035504030c13546c734c' +
      '6962205465737420526f6f742043413020170d3236313130393139333935355a' +
      '180f32313236313031363139333935355a301e311c301a06035504030c13546c' +
      '734c6962205465737420526f6f742043413059301306072a8648ce3d02010608' +
      '2a8648ce3d03010703420004a1f30adcd2cf3e13885a0653de7c7e1d361d698d' +
      'b8534aa3eef6de9625f68339e302e5911692f6c560816ff279f1a0b02857036f' +
      'b95821d5a681a4310404388ea3423040300f0603551d130101ff040530030101' +
      'ff300e0603551d0f0101ff040403020106301d0603551d0e041604141d21b3b7' +
      'a22b83d9c44a0c59467362ef1fbec212300a06082a8648ce3d04030203480030' +
      '45022100e15cffc60910294dea2947dc9d0fce3ceef3c173d36420176ca782a6' +
      'c59578400220780cc61f915c61f0b7fecdcd98810caed266ff7bbc1fb4d877bb' +
      '3fdea9f21bba';
    class function Echo(const ADirs, ACertCA: string; out AError: string): string; static;
    /// <summary>Connects to the chain server with the directory list ADirs, the CA file ACertCA
    /// when set and bundle rule ARule; the server presents a leaf alone, issued by an
    /// intermediate below a root.</summary>
    class function EchoChain(const ADirs, ACertCA: string; ARule: TBundleAnchorRule;
      out AError: string): string; static;
    /// <summary>Makes the empty directory BaseDir/AName and returns its path.</summary>
    class function NewDir(const ABase, AName: string): string; static;
    class procedure RemoveTree(const ADir: string); static;
    /// <summary>A server reads TrustedCertsDir only to verify a client certificate.</summary>
    class procedure RunServerRole(const ABase: string); static;
    /// <summary>A certificate is an anchor only from a PEM file named by its subject
    /// hash.</summary>
    class procedure RunNaming(const ABase, ARootHex, AOtherHex: string;
      AServer: TLoopbackServerBase); static;
    /// <summary>A file that cannot be used is skipped and the numbers after it are still
    /// read.</summary>
    class procedure RunSkipped(const ABase, ARootHex, ALookalikeHex: string); static;
    /// <summary>A link is followed, and one with nothing at its end is skipped; a file system
    /// without links has nothing to check.</summary>
    class procedure RunLinks(const ABase, ARootHex: string); static;
    /// <summary>A file the process may not read is skipped; checked where the file system keeps
    /// modes and the process is not privileged.</summary>
    class procedure RunPermissions(const ABase, ARootHex, ALookalikeHex: string); static;
    /// <summary>A directory anchors only the self-signed certificates it holds, unless the bundle
    /// rule says every certificate.</summary>
    class procedure RunIssuers(const ABase: string); static;
    /// <summary>The lookup's identity names the directories and what they hold, from an absolute
    /// path.</summary>
    class procedure RunIdentity(const ABase: string); static;
  public
    /// <summary>TrustedCertsDir trusts exactly the certificates a hashed certificate directory
    /// lookup finds when a verification asks, sees the directory as it is at each connection,
    /// and skips what it cannot read.</summary>
    class procedure Run; static;
  end;

  TAlpnCheck = class sealed(TConnectCheckBase)
  strict private
    /// <summary>Connects a client with the ALPN slot AClientSlot and list AClientList (and
    /// AClientConfig when set) to a server with the slot AServerSlot and list AServerList. Returns
    /// the protocol the client negotiated; ASelected is what the base handler type reports for
    /// it (empty where that type has no such member) and AError why the connection was
    /// refused.</summary>
    class function Negotiate(const AServerSlot: string; const AServerList: TArray<string>;
      const AClientSlot: string; const AClientList: TArray<string>;
      AClientConfig: ITlsClientConfig; out ASelected, AError: string;
      out AAlert: Integer): string; static;
  public
    /// <summary>ALPN comes from AlpnProtocols or CertificateData.ALPNProtocols, trimmed and
    /// without empty names; the server's order decides; two lists that differ, a list beside a
    /// supplied config and a client offering nothing the server has are refused.</summary>
    class procedure Run; static;
  end;

  /// <summary>What a teardown handler and the test that frees it compare: calls entered and left,
  /// and whether a call was still inside when destruction began and when the base had finished
  /// with it.</summary>
  TTeardownProbe = class sealed(TObject)
  public
  var
    Entered, Left: LongInt;
    InsideAtDestroy, InsideAfterBase: Boolean;
  end;

  /// <summary>A handler that counts its Recv calls into a probe from outside the base's own
  /// guard, and on destruction notes whether a call is still inside.</summary>
  TTeardownProbeHandler = class sealed(TTlsLibSocketHandler)
  strict private
  var
    FProbe: TTeardownProbe;
    /// <summary>Whether a call is inside, given a short time to leave.</summary>
    function CallInside: Boolean;
  public
    constructor Create(AProbe: TTeardownProbe); reintroduce;
    destructor Destroy; override;
    function Recv(const Buffer; Count: Integer): Integer; override;
  end;

  /// <summary>Reads once from a connected socket on its own thread.</summary>
  TTeardownWorker = class(TThread)
  strict private
  var
    FSock: TInetSocket;
    FDone: TEvent;
    FFailure: string;
  protected
    procedure Execute; override;
  public
    constructor Create(ASock: TInetSocket);
    destructor Destroy; override;
    property Done: TEvent read FDone;
    property Failure: string read FFailure;
  end;

  /// <summary>How a teardown cycle ends the read: the socket's Close, as fcl-net does before it
  /// frees the handler, or the handler freed directly.</summary>
  TTeardownHow = (TeardownClose, TeardownFree);

  /// <summary>Ends a read the way AHow says on its own thread, so a teardown that hangs shows as
  /// a missed deadline.</summary>
  TTeardownCloser = class(TThread)
  strict private
  var
    FSock: TInetSocket;
    FHandler: TTeardownProbeHandler;
    FHow: TTeardownHow;
    FDone: TEvent;
    FFailure: string;
  protected
    procedure Execute; override;
  public
    constructor Create(ASock: TInetSocket; AHandler: TTeardownProbeHandler;
      AHow: TTeardownHow);
    destructor Destroy; override;
    property Done: TEvent read FDone;
    /// <summary>The socket, nil once the closer freed it.</summary>
    property Sock: TInetSocket read FSock;
    property Failure: string read FFailure;
  end;

  TTeardownCheck = class sealed(TObject)
  strict private
    /// <summary>Reports AMessage as the failure and ends the process.</summary>
    class procedure Stuck(const AMessage: string); static;
    /// <summary>Ends a read that waits on a silent peer with an application read timeout of
    /// AIoTimeoutMs, the way AHow says, and expects the read to end without the handler having
    /// been destroyed under it.</summary>
    class procedure Cycle(const ARoot: string; AIoTimeoutMs: Integer; AHow: TTeardownHow); static;
  public
    /// <summary>Closing a socket, or freeing its handler, while another thread waits in Recv on a
    /// peer that stays silent ends that wait before the handler is freed, with or without a read
    /// timeout.</summary>
    class procedure Run; static;
    /// <summary>A Recv that starts once Close has begun ends as a closed connection without
    /// entering the engine.</summary>
    class procedure RunClosed; static;
  end;

  /// <summary>Raises a memory fault from the certificate hook of a handshake.</summary>
  TFaultingVerifier = class sealed(TObject)
  public
    procedure Verify(Sender: TObject; var AAllow: Boolean);
  end;

  /// <summary>A handler that shuts the socket before it starts the handshake.</summary>
  TShutSocketHandler = class sealed(TTlsLibSocketHandler)
  public
    function Connect: Boolean; override;
  end;

  /// <summary>What kind of failure a handler is expected to have recorded.</summary>
  TFailureFamily = (FamilyStream, FamilyAlert, FamilySocket);

  TFailureCheck = class sealed(TObject)
  strict private
    /// <summary>The handler recorded a failure of the family AFamily.</summary>
    class procedure ExpectFailed(const ATest: string; AHandler: TTlsLibSocketHandler;
      AFamily: TFailureFamily); static;
    /// <summary>Connecting AHandler (which the socket then owns) fails and records
    /// AFamily.</summary>
    class procedure ConnectRefused(const ATest: string; AHandler: TTlsLibSocketHandler;
      AFamily: TFailureFamily); static;
  public
    /// <summary>A memory fault inside Send is not turned into an error code.</summary>
    class procedure RunSendFault; static;
    /// <summary>A memory fault inside Recv is not turned into an error code.</summary>
    class procedure RunRecvFault; static;
    /// <summary>A memory fault inside the handshake is not turned into a failed Connect.</summary>
    class procedure RunConnectFault; static;
    /// <summary>Connect, Send and Recv report the failures a TLS stream, a socket and a file
    /// raise as an error code and the recorded state, with the socket's own error number when
    /// it has one.</summary>
    class procedure RunFamilies; static;
  end;

{ TVectorLocator }

class function TVectorLocator.SearchFrom(const AStart: string): string;
const
  REL = 'TlsLib.Tests' + PathDelim + 'Data' + PathDelim + 'Certs' + PathDelim +
    'EcP256Chain.txt';
var
  LDir, LTry: string;
  LI: Integer;
begin
  Result := '';
  LDir := AStart;
  for LI := 0 to 8 do
  begin
    LTry := IncludeTrailingPathDelimiter(LDir) + REL;
    if FileExists(LTry) then
      Exit(LTry);
    LDir := ExtractFileDir(ExcludeTrailingPathDelimiter(LDir));
    if LDir = '' then
      Break;
  end;
end;

class procedure TVectorLocator.Locate;
begin
  FVector := SearchFrom(ExtractFilePath(ParamStr(0)));
  if FVector = '' then
    FVector := SearchFrom(GetCurrentDir);
  if FVector = '' then
    raise Exception.Create('EcP256Chain.txt vector not found (searched up from the exe and cwd)');
end;

class function TVectorLocator.FieldHex(const AName: string): string;
begin
  Result := FieldHexFrom(ExtractFileName(FVector), AName);
end;

class function TVectorLocator.FieldHexFrom(const AFile, AName: string): string;
var
  LLines: TStringList;
  LI: Integer;
  LPrefix: string;
begin
  Result := '';
  LPrefix := AName + '=';
  LLines := TStringList.Create;
  try
    LLines.LoadFromFile(ExtractFilePath(FVector) + AFile);
    for LI := 0 to LLines.Count - 1 do
      if Pos(LPrefix, LLines[LI]) = 1 then
        Exit(Copy(LLines[LI], System.Length(LPrefix) + 1, MaxInt));
  finally
    LLines.Free;
  end;
end;

class function TVectorLocator.WriteDer(const AName, AHex: string): string;
begin
  Result := IncludeTrailingPathDelimiter(GetTempDir) + 'tlslib_fcl_' + AName + '.der';
  WriteDerTo(Result, AHex);
end;

class procedure TVectorLocator.WriteDerTo(const APath, AHex: string);
var
  LBytes: TBytes;
  LFile: TFileStream;
begin
  LBytes := TDataEncoding.HexDecode(AHex);
  LFile := TFileStream.Create(APath, fmCreate);
  try
    if System.Length(LBytes) > 0 then
      LFile.WriteBuffer(LBytes[0], System.Length(LBytes));
  finally
    LFile.Free;
  end;
end;

class function TVectorLocator.WritePemTo(const APath, ALabel: string;
  const AHexes: array of string): Integer;
var
  LBlocks: TArray<TPemBlock>;
  LPem: TBytes;
  LI: Integer;
begin
  SetLength(LBlocks, System.Length(AHexes));
  for LI := 0 to System.High(AHexes) do
  begin
    LBlocks[LI].PemType := ALabel;
    LBlocks[LI].Content := TDataEncoding.HexDecode(AHexes[LI]);
  end;
  LPem := TPem.WriteBlocks(LBlocks);
  WriteDerTo(APath, TDataEncoding.HexEncode(LPem));
  Result := System.Length(LPem);
end;

class procedure TVectorLocator.PadTo(const APath: string; ASize: Integer);
var
  LFile: TFileStream;
  LFill: TBytes;
begin
  LFile := TFileStream.Create(APath, fmOpenReadWrite);
  try
    SetLength(LFill, ASize - LFile.Size);
    FillChar(LFill[0], System.Length(LFill), 10);
    LFile.Seek(0, soFromEnd);
    LFile.WriteBuffer(LFill[0], System.Length(LFill));
  finally
    LFile.Free;
  end;
end;

{ TLoopbackServerBase }

constructor TLoopbackServerBase.Create(APort, AConnectionLimit: Integer);
begin
  inherited Create(True);
  FreeOnTerminate := False;
  FPort := APort;
  FConnectionLimit := AConnectionLimit;
end;

destructor TLoopbackServerBase.Destroy;
begin
  inherited Destroy;
  FServer.Free;
end;

procedure TLoopbackServerBase.StartListening;
begin
  FServer := TInetServer.Create('127.0.0.1', FPort);
  try
    FServer.ReuseAddress := True;
    if FConnectionLimit > 0 then
      FServer.MaxConnections := FConnectionLimit;
    FServer.AcceptIdleTimeout := ACCEPT_POLL_MS;
    FServer.OnIdle := HandleIdle;
{$IF FPC_FULLVERSION >= 30301}
    FServer.OnAcceptSocketError := HandleAcceptError;
{$ELSE}
    FServer.OnAcceptError := HandleAcceptError;
{$IFEND}
    FServer.OnCreateClientSocketHandler := MakeHandler;
    FServer.OnConnect := HandleConnect;
    FServer.Listen;
  except
    FreeAndNil(FServer);
    raise;
  end;
  Start;
end;

procedure TLoopbackServerBase.HandleAcceptError(Sender: TObject; ASocket: TFPSocket;
  E: Exception; var AAction: TAcceptErrorAction);
begin
  if Terminated then
  begin
    AAction := aeaStop;
    Exit;
  end;
  if FAcceptErrors >= ACCEPT_ERROR_LIMIT then
    Exit;
  if (E is ESocketError) and (ESocketError(E).Code = seAcceptFailed) then
  begin
    Inc(FAcceptErrors);
    AAction := aeaIgnore;
  end;
end;

procedure TLoopbackServerBase.WaitSettled;
var
  LTicks: Integer;
  LStart: TDateTime;
begin
  // an idle tick means no connection was waiting, so the earlier ones are all disposed of
  LTicks := FIdleTicks;
  LStart := Now;
  while FIdleTicks = LTicks do
  begin
    if MilliSecondsBetween(Now, LStart) > SETTLE_LIMIT_MS then
      raise Exception.Create('the server did not finish with the refused connection');
    Sleep(1);
  end;
end;

procedure TLoopbackServerBase.HandleIdle(Sender: TObject);
begin
  InterlockedIncrement(FIdleTicks);
  if Terminated then
    FServer.StopAccepting(False);
end;

procedure TLoopbackServerBase.Execute;
begin
  // a thread whose listener never came up is only resumed to be freed
  if FServer = nil then
    Exit;
  try
    try
      FServer.StartAccepting;
    except
      on E: Exception do
        FError := 'server: ' + E.ClassName + ': ' + E.Message;
    end;
  finally
    FreeAndNil(FServer);
  end;
end;

{ TServerThread }

constructor TServerThread.Create(const APfx: TBytes);
begin
  inherited Create(PORT, 1);
  FPfx := APfx;
end;

procedure TServerThread.MakeHandler(Sender: TObject; out AHandler: TSocketHandler);
var
  LHandler: TTlsLibSocketHandler;
begin
  // fcl-net asks the server for a handler per accepted connection: hand it a configured one
  // carrying the server credential as an in-memory PKCS#12 (its Accept runs our server handshake
  // automatically)
  LHandler := TTlsLibSocketHandler.Create;
  LHandler.CertificateData.PFX.Value := FPfx;
  LHandler.CertificateData.KeyPassword := 'tlslib';
  FAccepted := LHandler;
  AHandler := LHandler;
end;

procedure TServerThread.HandleConnect(Sender: TObject; AStream: TSocketStream);
var
  LBuf: TBytes;
  LN: Integer;
begin
  // the handshake already ran during accept; move one line of plaintext through our records
  try
    FPeerServerName := FAccepted.PeerServerName;
    SetLength(LBuf, 1024);
    LN := AStream.Read(LBuf[0], System.Length(LBuf));
    if LN > 0 then
      AStream.Write(LBuf[0], LN); // echo it back
    // then the first bytes of a TLS record straight on the socket, and silence: the client's
    // socket timeout, not this thread's exit, must be what ends its wait
    SetLength(LBuf, 3);
    LBuf[0] := $17; LBuf[1] := $03; LBuf[2] := $03;
    fpSend(AStream.Handle, @LBuf[0], 3, 0);
    Sleep(STALL_HOLD_MS);
  except
    on E: Exception do
      FError := 'server connection: ' + E.ClassName + ': ' + E.Message;
  end;
  // we own the accepted stream in OnConnect: freeing it flushes close_notify then closes the socket
  AStream.Free;
end;

{ TMutualServerThread }

constructor TMutualServerThread.Create(const APfx: TBytes; const ARootFile: string);
begin
  inherited Create(MUTUAL_PORT, 1);
  FPfx := APfx;
  FRootFile := ARootFile;
end;

procedure TMutualServerThread.VerifyHook(Sender: TObject; var AAllow: Boolean);
begin
  if FAttempts <> 1 then
    Exit;
  raise FHookFault.Create('injected certificate hook failure');
end;

procedure TMutualServerThread.MakeHandler(Sender: TObject; out AHandler: TSocketHandler);
var
  LHandler: TTlsLibSocketHandler;
begin
  Inc(FAttempts);
  if FCertsDir <> '' then
  begin
    LHandler := TTestCertificateDataHandler.Create;
    (LHandler.CertificateData as TTestCertificateData).TrustedCertsDir := FCertsDir;
  end
  else
  begin
    LHandler := TTlsLibSocketHandler.Create;
    LHandler.CertificateData.CertCA.FileName := FRootFile;
  end;
  LHandler.CertificateData.PFX.Value := FPfx;
  LHandler.CertificateData.KeyPassword := 'tlslib';
  // the test root vouches for clients, and a certificate is required
  LHandler.ClientAuth := TClientAuthMode.Required;
  if FHookFault <> nil then
    LHandler.OnVerifyCertificate := VerifyHook;
  AHandler := LHandler;
end;

procedure TMutualServerThread.HandleConnect(Sender: TObject; AStream: TSocketStream);
var
  LBuf: TBytes;
  LN: Integer;
begin
  try
    SetLength(LBuf, 64);
    LN := AStream.Read(LBuf[0], System.Length(LBuf));
    if LN > 0 then
    begin
      AStream.Write(LBuf[0], LN);
      Inc(FServed);
    end;
  except
    // a client turned away mid-handshake is the expected outcome for the no-certificate leg
  end;
  AStream.Free;
end;

{ TEarlyCloseServerThread }

constructor TEarlyCloseServerThread.Create(const APfx: TBytes; ASettled: TEvent);
begin
  inherited Create(EARLY_CLOSE_PORT, 0);
  FPfx := APfx;
  FSettled := ASettled;
  FSettledMs := -1;
end;

procedure TEarlyCloseServerThread.MakeHandler(Sender: TObject; out AHandler: TSocketHandler);
var
  LHandler: TTlsLibSocketHandler;
begin
  FAttemptAt := Now;
  LHandler := TTlsLibSocketHandler.Create;
  LHandler.CertificateData.PFX.Value := FPfx;
  LHandler.CertificateData.KeyPassword := 'tlslib';
  AHandler := LHandler;
end;

procedure TEarlyCloseServerThread.HandleConnect(Sender: TObject; AStream: TSocketStream);
begin
  AStream.Free;
end;

procedure TEarlyCloseServerThread.HandleIdle(Sender: TObject);
begin
  if (FAttemptAt <> 0) and (FSettledMs < 0) then
  begin
    FSettledMs := MilliSecondsBetween(Now, FAttemptAt);
    FSettled.SetEvent;
  end;
  inherited HandleIdle(Sender);
end;

{ TVerifyServerThread }

constructor TVerifyServerThread.Create(const ACertificate, APrivateKey: TBytes; APort: Integer);
begin
  inherited Create(APort, 0);
  FCertificate := ACertificate;
  FPrivateKey := APrivateKey;
end;

procedure TVerifyServerThread.MakeHandler(Sender: TObject; out AHandler: TSocketHandler);
var
  LHandler: TTlsLibSocketHandler;
begin
  if (FCertsDir <> '') or (FAlpnSlot <> '') then
  begin
    LHandler := TTestCertificateDataHandler.Create;
    (LHandler.CertificateData as TTestCertificateData).TrustedCertsDir := FCertsDir;
    (LHandler.CertificateData as TTestCertificateData).ALPNProtocols := FAlpnSlot;
  end
  else
    LHandler := TTlsLibSocketHandler.Create;
  LHandler.AlpnProtocols := FAlpnList;
  LHandler.CertificateData.Certificate.Value := FCertificate;
  LHandler.CertificateData.PrivateKey.Value := FPrivateKey;
  AHandler := LHandler;
end;

procedure TVerifyServerThread.HandleConnect(Sender: TObject; AStream: TSocketStream);
var
  LBuf: TBytes;
  LN: Integer;
begin
  try
    if System.Length(FGreeting) > 0 then
    begin
      AStream.Write(FGreeting[0], System.Length(FGreeting));
      while not Terminated do
        Sleep(ACCEPT_POLL_MS);
    end
    else
    begin
      SetLength(LBuf, 64);
      LN := AStream.Read(LBuf[0], System.Length(LBuf));
      if LN > 0 then
        AStream.Write(LBuf[0], LN);
    end;
  except
    // a client that left mid-exchange is not this server's failure
  end;
  AStream.Free;
end;

{ TVerifyStockHandler }

{$IF FPC_FULLVERSION >= 30203}
function TVerifyStockHandler.GetLastSSLErrorString: string;
begin
  Result := '';
end;

function TVerifyStockHandler.GetLastSSLErrorCode: Integer;
begin
  Result := 0;
end;
{$IFEND}

function TVerifyStockHandler.CreateCertGenerator: TX509Certificate;
begin
  Result := TFclNetNoCertGenerator.Create;
end;

{ TVerifyClient }

class function TVerifyClient.Echo(const AHandler: TTlsLibSocketHandler; APort: Integer;
  out AError: string): string;
var
  LSock: TInetSocket;
  LBuf: TBytes;
  LN: Integer;
begin
  Result := '';
  AError := '';
  LSock := TInetSocket.Create('localhost', APort, AHandler);
  try
    try
      LSock.Connect;
      LSock.IOTimeout := 2000;
      LBuf := TBytes.Create(Ord('v'), Ord('e'), Ord('r'), Ord('i'), Ord('f'), Ord('y'));
      LSock.Write(LBuf[0], System.Length(LBuf));
      SetLength(LBuf, 64);
      LN := LSock.Read(LBuf[0], System.Length(LBuf));
      if LN > 0 then
        SetString(Result, PAnsiChar(@LBuf[0]), LN);
    except
      on E: Exception do
        AError := E.Message + ' ' + AHandler.LastErrorDesc;
    end;
    // a failed read reports through the handler rather than raising
    if AError = '' then
      AError := AHandler.LastErrorDesc;
  finally
    LSock.Free;
  end;
end;

class procedure TVerifyIgnoredCheck.Run;
var
  LServer: TVerifyServerThread;
  LBase: TSSLSocketHandler;
  LHandler: TTlsLibSocketHandler;
  LPreviousClass: TSSLSocketHandlerClass;
  LCrypto: ICryptoProvider;
  LPkix: IPkixProvider;
  LRootDer, LWrongRootDer: TBytes;
  LRoot, LWrongRoot, LError: string;
begin
  LRoot := TVectorLocator.WriteDer('verify_root', TVectorLocator.FieldHex('root_cert'));
  LWrongRoot := TVectorLocator.WriteDer('verify_wrong_root', TVectorLocator.FieldHex('root2_cert'));
  LRootDer := TDataEncoding.HexDecode(TVectorLocator.FieldHex('root_cert'));
  LWrongRootDer := TDataEncoding.HexDecode(TVectorLocator.FieldHex('root2_cert'));
  LCrypto := TDefaultCryptoProvider.Create as ICryptoProvider;
  LPkix := TDefaultPkixProvider.Create as IPkixProvider;
  LServer := TVerifyServerThread.Create(
    TDataEncoding.HexDecode(TVectorLocator.FieldHex('leaf_cert')),
    TDataEncoding.HexDecode(TVectorLocator.FieldHex('leaf_key')), VERIFY_PORT);
  try
    LServer.StartListening;

    // what fcl-web clients do, from code compiled without this adapter in scope
    LBase := TFclNetFclWebMimic.NewDefaultHandler(False, '');
    if not LBase.VerifyPeerCert then
      raise Exception.Create('the switch read through the generic type does not show ours');
    if TVerifyClient.Echo(LBase as TTlsLibSocketHandler, VERIFY_PORT, LError) <> '' then
      raise Exception.Create('an untrusted server was served after a base-typed False');
    if Pos('no trust source was named', LError) = 0 then
      raise Exception.Create('the refusal does not say no trust source was named: ' + LError);
    if Pos(BASE_WRITE_HINT, LError) = 0 then
      raise Exception.Create('the refusal does not carry the base-write hint: ' + LError);
    LServer.WaitSettled;

    LBase := TFclNetFclWebMimic.NewDefaultHandler(False, LWrongRoot);
    if TVerifyClient.Echo(LBase as TTlsLibSocketHandler, VERIFY_PORT, LError) <> '' then
      raise Exception.Create('a server outside the pinned root was served after a base-typed False');
    if Pos(UNTRUSTED_CHAIN, LError) = 0 then
      raise Exception.Create('the refusal is not a chain failure: ' + LError);
    if Pos(BASE_WRITE_HINT, LError) = 0 then
      raise Exception.Create('the chain refusal does not carry the base-write hint: ' + LError);

    LBase := TFclNetFclWebMimic.NewDefaultHandler(False, LRoot);
    if TVerifyClient.Echo(LBase as TTlsLibSocketHandler, VERIFY_PORT, LError) <> 'verify' then
      raise Exception.Create('a server under the pinned root was not served: ' + LError);

    // a user class registered as the default is reached the same way
    LPreviousClass := TSSLSocketHandler.GetDefaultHandlerClass;
    TSSLSocketHandler.SetDefaultHandlerClass(TVerifySubclassHandler);
    try
      LBase := TFclNetFclWebMimic.NewDefaultHandler(False, '');
      if TVerifyClient.Echo(LBase as TTlsLibSocketHandler, VERIFY_PORT, LError) <> '' then
        raise Exception.Create('an untrusted server was served to a registered subclass');
      if Pos('no trust source was named', LError) = 0 then
        raise Exception.Create('the subclass refusal does not say no trust source was named: ' +
          LError);
    finally
      TSSLSocketHandler.SetDefaultHandlerClass(LPreviousClass);
    end;
    LServer.WaitSettled;

    // a config supplied on the default handler is not in conflict with the base-typed False
    LBase := TFclNetFclWebMimic.NewDefaultHandler(False, '');
    (LBase as TTlsLibSocketHandler).ClientConfig := TTlsPresets.Compatible(LCrypto, LPkix).Client
      .WithServerVerification(TServerVerification.WebPki(LRootDer).Build).Build;
    if TVerifyClient.Echo(LBase as TTlsLibSocketHandler, VERIFY_PORT, LError) <> 'verify' then
      raise Exception.Create('a supplied client config was not served: ' + LError);

    // the config decides, so a refusal under it is not blamed on the base-typed write
    LBase := TFclNetFclWebMimic.NewDefaultHandler(False, '');
    (LBase as TTlsLibSocketHandler).ClientConfig := TTlsPresets.Compatible(LCrypto, LPkix).Client
      .WithServerVerification(TServerVerification.WebPki(LWrongRootDer).Build).Build;
    if TVerifyClient.Echo(LBase as TTlsLibSocketHandler, VERIFY_PORT, LError) <> '' then
      raise Exception.Create('a server outside the supplied config''s root was served');
    if (LError = '') or (Pos(BASE_WRITE_HINT, LError) > 0) then
      raise Exception.Create('the refusal under a supplied config is missing or carries the hint: ' +
        LError);

    // a failure unrelated to trust is not blamed on the base-typed write once the user set False
    LBase := TFclNetFclWebMimic.NewDefaultHandler(False, '');
    LHandler := LBase as TTlsLibSocketHandler;
    LHandler.VerifyPeerCert := False;
    LHandler.SSLType := stSSLv3;
    if TVerifyClient.Echo(LHandler, VERIFY_PORT, LError) <> '' then
      raise Exception.Create('a pinned unsupported protocol version was served');
    if (Pos('SSLType', LError) = 0) or (Pos(BASE_WRITE_HINT, LError) > 0) then
      raise Exception.Create('the version refusal is missing or carries the hint: ' + LError);
  finally
    LServer.Terminate;
    LServer.Free;
  end;
end;

{ TVerifyHonouredCheck }

class procedure TVerifyHonouredCheck.Run;
var
  LServer: TVerifyServerThread;
  LHandler: TTlsLibSocketHandler;
  LBase, LStock: TSSLSocketHandler;
  LError: string;
begin
  LServer := TVerifyServerThread.Create(
    TDataEncoding.HexDecode(TVectorLocator.FieldHex('leaf_cert')),
    TDataEncoding.HexDecode(TVectorLocator.FieldHex('leaf_key')), VERIFY_PORT);
  try
    LServer.StartListening;

    // the default handler is one of ours, and a False set through our type is the bypass
    LHandler := TSSLSocketHandler.GetDefaultHandler as TTlsLibSocketHandler;
    LHandler.VerifyPeerCert := False;
    if TVerifyClient.Echo(LHandler, VERIFY_PORT, LError) <> 'verify' then
      raise Exception.Create('the default handler did not skip under its own False: ' + LError);

    LHandler := TTlsLibSocketHandler.Create;
    LHandler.VerifyPeerCert := False;
    if TVerifyClient.Echo(LHandler, VERIFY_PORT, LError) <> 'verify' then
      raise Exception.Create('a handler with VerifyPeerCert False did not skip: ' + LError);

    // a handler nobody touched verifies, and its refusal is not blamed on a reset
    LHandler := TTlsLibSocketHandler.Create;
    if TVerifyClient.Echo(LHandler, VERIFY_PORT, LError) <> '' then
      raise Exception.Create('an untrusted server was served to an untouched handler');
    if Pos('no trust source was named', LError) = 0 then
      raise Exception.Create('the refusal does not say no trust source was named: ' + LError);
    if Pos(BASE_WRITE_HINT, LError) > 0 then
      raise Exception.Create('an untouched handler''s refusal carries the hint: ' + LError);
    LServer.WaitSettled;

    // the property is published, so a write by name reaches it
    LHandler := TTlsLibSocketHandler.Create;
    SetOrdProp(LHandler, 'VerifyPeerCert', 0);
    if TVerifyClient.Echo(LHandler, VERIFY_PORT, LError) <> 'verify' then
      raise Exception.Create('a write of VerifyPeerCert by name was not honoured: ' + LError);

    // code that uses this unit is honoured through the generic type too, and the last write wins
    LBase := TSSLSocketHandler.GetDefaultHandler;
    LBase.VerifyPeerCert := False;
    if TVerifyClient.Echo(LBase as TTlsLibSocketHandler, VERIFY_PORT, LError) <> 'verify' then
      raise Exception.Create('a base-typed False in scope of the adapter was not honoured: ' +
        LError);

    LBase := TSSLSocketHandler.GetDefaultHandler;
    LBase.VerifyPeerCert := False;
    LBase.VerifyPeerCert := True;
    if TVerifyClient.Echo(LBase as TTlsLibSocketHandler, VERIFY_PORT, LError) <> '' then
      raise Exception.Create('an untrusted server was served after a later base-typed True');
    if Pos('no trust source was named', LError) = 0 then
      raise Exception.Create('the refusal does not say no trust source was named: ' + LError);
    if Pos(BASE_WRITE_HINT, LError) > 0 then
      raise Exception.Create('a handler with both switches True carries the hint: ' + LError);
    LServer.WaitSettled;

    // a handler class that is none of ours keeps its own switch
    LStock := TVerifyStockHandler.Create;
    try
      LStock.VerifyPeerCert := True;
      if not LStock.VerifyPeerCert then
        raise Exception.Create('a stock handler lost a True written through the generic type');
      LStock.VerifyPeerCert := False;
      if LStock.VerifyPeerCert then
        raise Exception.Create('a stock handler lost a False written through the generic type');
    finally
      LStock.Free;
    end;
  finally
    LServer.Terminate;
    LServer.Free;
  end;
end;

{ TSelfSignedLeafCheck }

class procedure TSelfSignedLeafCheck.Run;
var
  LServer: TVerifyServerThread;
  LHandler: TTlsLibSocketHandler;
  LSelfLeaf, LError: string;
begin
  LSelfLeaf := TVectorLocator.WriteDer('verify_self_leaf',
    TVectorLocator.FieldHex('otherhost_cert'));
  LServer := TVerifyServerThread.Create(
    TDataEncoding.HexDecode(TVectorLocator.FieldHex('otherhost_cert')),
    TDataEncoding.HexDecode(TVectorLocator.FieldHex('otherhost_key')), VERIFY_SELF_PORT);
  try
    LServer.StartListening;

    // the two handlers differ in CheckHostName alone
    LHandler := TTlsLibSocketHandler.Create;
    LHandler.CertificateData.TrustedCertificate.FileName := LSelfLeaf;
    LHandler.CheckHostName := False;
    if TVerifyClient.Echo(LHandler, VERIFY_SELF_PORT, LError) <> 'verify' then
      raise Exception.Create('a trusted self-signed leaf was not served: ' + LError);

    // the CA slot an fcl-web client fills from CertCAFileName takes the leaf the same way
    LHandler := TTlsLibSocketHandler.Create;
    LHandler.CertificateData.CertCA.FileName := LSelfLeaf;
    LHandler.CheckHostName := False;
    if TVerifyClient.Echo(LHandler, VERIFY_SELF_PORT, LError) <> 'verify' then
      raise Exception.Create('a self-signed leaf in the CA slot was not served: ' + LError);

    LHandler := TTlsLibSocketHandler.Create;
    LHandler.CertificateData.TrustedCertificate.FileName := LSelfLeaf;
    if TVerifyClient.Echo(LHandler, VERIFY_SELF_PORT, LError) <> '' then
      raise Exception.Create('a trusted leaf was served under a host it does not name');
    // the core reports a rejected name as it reports any rejected certificate
    if Pos(UNTRUSTED_CHAIN, LError) = 0 then
      raise Exception.Create('the refusal of a leaf under a host it does not name does not say ' +
        'the chain was refused: ' + LError);
  finally
    LServer.Terminate;
    LServer.Free;
  end;
end;

{ TEarlyCloseCheck }

class procedure TEarlyCloseCheck.Run;
var
  LServer: TEarlyCloseServerThread;
  LSettled: TEvent;
  LSock: TInetSocket;
begin
  LSettled := TEvent.Create(nil, True, False, '');
  try
    LServer := TEarlyCloseServerThread.Create(
      TDataEncoding.HexDecode(TVectorLocator.FieldHex('leaf_pfx')), LSettled);
    try
      LServer.StartListening;
      LSock := TInetSocket.Create('127.0.0.1', EARLY_CLOSE_PORT);
      LSock.Free;
      if LSettled.WaitFor(10000) <> wrSignaled then
        raise Exception.Create('the server never finished its accept of an early-closed client ' +
          LServer.Error);
      if LServer.SettledMs > EARLY_CLOSE_LIMIT_MS then
        raise Exception.CreateFmt('the server took %d ms to give up on a client that closed ' +
          'before its ClientHello', [LServer.SettledMs]);
    finally
      LServer.Terminate;
      LServer.Free;
    end;
  finally
    LSettled.Free;
  end;
end;

{ TMutualTlsCheck }

class function TMutualTlsCheck.Echo(const APfx: TBytes; const ARootFile: string;
  AWithIdentity, AWrite: Boolean; out AError: string; out AAlert: Integer): string;
var
  LSock: TInetSocket;
  LHandler: TTlsLibSocketHandler;
  LBuf: TBytes;
  LN: Integer;
begin
  Result := '';
  AError := '';
  AAlert := 0;
  LHandler := TTlsLibSocketHandler.Create;
  LHandler.CertificateData.CertCA.FileName := ARootFile;
  if AWithIdentity then
  begin
    LHandler.CertificateData.PFX.Value := APfx;
    LHandler.CertificateData.KeyPassword := 'tlslib';
  end;
  LSock := TInetSocket.Create('localhost', MUTUAL_PORT, LHandler);
  try
    try
      LSock.Connect;
      LSock.IOTimeout := 2000;
      if AWrite then
      begin
        LBuf := TBytes.Create(Ord('m'), Ord('u'), Ord('t'), Ord('u'), Ord('a'), Ord('l'));
        LSock.Write(LBuf[0], System.Length(LBuf));
      end;
      SetLength(LBuf, 64);
      // TLS 1.3 lets the client finish before the server judges its certificate: the answer is
      // the echo, which a rejected client never gets
      LN := LSock.Read(LBuf[0], System.Length(LBuf));
      if LN > 0 then
        SetString(Result, PAnsiChar(@LBuf[0]), LN);
    except
      on E: Exception do
        AError := E.Message + ' ' + LHandler.LastErrorDesc;
    end;
    // a failed read reports through the handler rather than raising
    if AError = '' then
      AError := LHandler.LastErrorDesc;
{$IF FPC_FULLVERSION >= 30203}
    AAlert := LHandler.LastSSLErrorCode;
{$IFEND}
  finally
    LSock.Free;
  end;
end;

class function TMutualTlsCheck.RefusesTwoSources(const APfx: TBytes;
  const ARootFile: string): Boolean;
var
  LHandler: TTlsLibSocketHandler;
begin
  LHandler := TTlsLibSocketHandler.Create;
  try
    LHandler.CertificateData.CertCA.FileName := ARootFile;
    LHandler.CertificateData.PFX.Value := APfx;
    LHandler.CertificateData.Certificate.FileName := ARootFile;
    LHandler.Connect;
    Result := Pos('sets PFX together with Certificate', LHandler.LastErrorDesc) > 0;
  finally
    LHandler.Free;
  end;
end;

class procedure TMutualTlsCheck.ExpectAlertRefusal(const AWhat, AError: string);
begin
  if Pos('the peer sent a fatal alert', AError) = 0 then
    raise Exception.Create(AWhat + ' was refused for another reason: ' + AError);
end;

class procedure TMutualTlsCheck.Run;
var
  LServer: TMutualServerThread;
  LPfx: TBytes;
  LRoot, LError: string;
  LAlert: Integer;
begin
  LPfx := TDataEncoding.HexDecode(TVectorLocator.FieldHexFrom('ClientAuthChain.txt', 'leaf_pfx'));
  LRoot := TVectorLocator.WriteDer('mutual_root',
    TVectorLocator.FieldHexFrom('ClientAuthChain.txt', 'root_cert'));
  LServer := TMutualServerThread.Create(LPfx, LRoot);
  try
    LServer.StartListening;
    if not RefusesTwoSources(LPfx, LRoot) then
      raise Exception.Create('a PFX beside a Certificate was not refused naming both');
    if Echo(LPfx, LRoot, False, False, LError, LAlert) <> '' then
      raise Exception.Create('a client with no certificate was served');
    ExpectAlertRefusal('the client with no certificate', LError);
    if LServer.Attempts <> 1 then
      raise Exception.Create('the client with no certificate never reached the server');
    if Echo(LPfx, LRoot, True, True, LError, LAlert) <> 'mutual' then
      raise Exception.Create('a client presenting the PFX identity was not served: ' + LError);
    LServer.WaitFor;
    if LServer.Error <> '' then
      raise Exception.Create(LServer.Error);
    if LServer.Served <> 1 then
      raise Exception.CreateFmt('the server served %d clients, expected 1', [LServer.Served]);
    if LServer.Attempts <> 2 then
      raise Exception.CreateFmt('the server saw %d connections, expected 2', [LServer.Attempts]);
  finally
    LServer.Terminate;
    LServer.Free;
  end;
end;

class procedure TMutualTlsCheck.RunHookFault;
var
  LServer: TMutualServerThread;
  LPfx: TBytes;
  LRoot, LError: string;
  LAlert: Integer;
begin
  LPfx := TDataEncoding.HexDecode(TVectorLocator.FieldHexFrom('ClientAuthChain.txt', 'leaf_pfx'));
  LRoot := TVectorLocator.WriteDer('hook_root',
    TVectorLocator.FieldHexFrom('ClientAuthChain.txt', 'root_cert'));
  LServer := TMutualServerThread.Create(LPfx, LRoot);
  try
    LServer.HookFault := Exception;
    LServer.StartListening;
    if Echo(LPfx, LRoot, True, False, LError, LAlert) <> '' then
      raise Exception.Create('a client was served by a server whose certificate hook raised');
    ExpectAlertRefusal('the client of the raising hook', LError);
{$IF FPC_FULLVERSION >= 30203}
    if LAlert <> ALERT_BAD_CERTIFICATE then
      raise Exception.CreateFmt('the raising hook sent alert %d, not bad_certificate', [LAlert]);
{$IFEND}
    // the raising hook must cost that one client only, not the listener
    if Echo(LPfx, LRoot, True, True, LError, LAlert) <> 'mutual' then
      raise Exception.Create('the server stopped accepting after its certificate hook raised: ' +
        LError + ' ' + LServer.Error);
    LServer.WaitFor;
    if LServer.Error <> '' then
      raise Exception.Create(LServer.Error);
    if LServer.Attempts <> 2 then
      raise Exception.CreateFmt('the server saw %d connections, expected 2', [LServer.Attempts]);
  finally
    LServer.Terminate;
    LServer.Free;
  end;
end;

class procedure TMutualTlsCheck.RunHookMemoryFault;
const
  FAULTS: array[0..2] of ExceptClass = (EAccessViolation, EStackOverflow, EPrivilege);
var
  LServer: TMutualServerThread;
  LPfx: TBytes;
  LRoot, LError: string;
  LI, LAlert: Integer;
begin
  LPfx := TDataEncoding.HexDecode(TVectorLocator.FieldHexFrom('ClientAuthChain.txt', 'leaf_pfx'));
  LRoot := TVectorLocator.WriteDer('fault_root',
    TVectorLocator.FieldHexFrom('ClientAuthChain.txt', 'root_cert'));
  for LI := 0 to System.High(FAULTS) do
  begin
    LServer := TMutualServerThread.Create(LPfx, LRoot);
    try
      LServer.HookFault := FAULTS[LI];
      LServer.StartListening;
      Echo(LPfx, LRoot, True, True, LError, LAlert);
      // a server that survived the fault would keep accepting, so it is asked to stop
      LServer.Terminate;
      LServer.WaitFor;
      if Pos(FAULTS[LI].ClassName, LServer.Error) = 0 then
        raise Exception.Create('a ' + FAULTS[LI].ClassName +
          ' from the certificate hook was turned into a failed connection: ' + LServer.Error);
    finally
      LServer.Terminate;
      LServer.Free;
    end;
  end;
end;

{ TBufferedPlaintextCheck }

class function TBufferedPlaintextCheck.Serve(const AGreeting: TBytes): TVerifyServerThread;
begin
  Result := TVerifyServerThread.Create(
    TDataEncoding.HexDecode(TVectorLocator.FieldHex('leaf_cert')),
    TDataEncoding.HexDecode(TVectorLocator.FieldHex('leaf_key')), BUFFERED_PORT);
  try
    Result.Greeting := AGreeting;
    Result.StartListening;
  except
    Result.Free;
    raise;
  end;
end;

class function TBufferedPlaintextCheck.Open(out AHandler: TTlsLibSocketHandler): TInetSocket;
begin
  AHandler := TTlsLibSocketHandler.Create;
  AHandler.CertificateData.CertCA.FileName := TVectorLocator.WriteDer('buffered_root',
    TVectorLocator.FieldHex('root_cert'));
  Result := TInetSocket.Create('localhost', BUFFERED_PORT, AHandler);
  try
    Result.Connect;
    Result.IOTimeout := 2000;
  except
    Result.Free;
    raise;
  end;
end;

class procedure TBufferedPlaintextCheck.RunPending;
var
  LServer: TVerifyServerThread;
  LSock: TInetSocket;
  LHandler: TTlsLibSocketHandler;
  LBuf: TBytes;
begin
  LServer := Serve(TBytes.Create(Ord('A'), Ord('B')));
  try
    LSock := Open(LHandler);
    try
      SetLength(LBuf, 1);
      if (LSock.Read(LBuf[0], 1) <> 1) or (LBuf[0] <> Ord('A')) then
        raise Exception.Create('the first byte of the record was not read');
      if LHandler.BytesAvailable <> 1 then
        raise Exception.CreateFmt('BytesAvailable is %d after reading 1 of 2 bytes of one record',
          [LHandler.BytesAvailable]);
      if TNetOs.Wait(TNetHandle(LSock.Handle), TNetWait.Readable, 200) then
        raise Exception.Create('the socket shows readable though the second byte is decrypted');
      if (LSock.Read(LBuf[0], 1) <> 1) or (LBuf[0] <> Ord('B')) then
        raise Exception.Create('the buffered second byte was not read');
    finally
      LSock.Free;
    end;
  finally
    LServer.Terminate;
    LServer.Free;
  end;
end;

{$IF DECLARED(TSocketStates)}
class procedure TBufferedPlaintextCheck.RunSelect;
var
  LServer: TVerifyServerThread;
  LSock: TInetSocket;
  LHandler: TTlsLibSocketHandler;
  LBuf: TBytes;
begin
  LServer := Serve(TBytes.Create(Ord('A'), Ord('B')));
  try
    LSock := Open(LHandler);
    try
      SetLength(LBuf, 1);
      if (LSock.Read(LBuf[0], 1) <> 1) or (LBuf[0] <> Ord('A')) then
        raise Exception.Create('the first byte of the record was not read');
      if not LSock.CanRead(0) then
        raise Exception.Create('CanRead is False with a byte buffered');
      if LSock.Select([sosCanRead, sosCanWrite], 0) <> [sosCanRead, sosCanWrite] then
        raise Exception.Create('Select did not report both read and write with a byte buffered');
      if (LSock.Read(LBuf[0], 1) <> 1) or (LBuf[0] <> Ord('B')) then
        raise Exception.Create('the buffered second byte was not read');
      if LSock.CanRead(150) then
        raise Exception.Create('CanRead is True with nothing buffered and a quiet socket');
    finally
      LSock.Free;
    end;
  finally
    LServer.Terminate;
    LServer.Free;
  end;
end;

class procedure TBufferedPlaintextCheck.RunLargeRecord;
const
  RECORD_SIZE = 5000;
  READ_SIZE = 4096;
var
  LServer: TVerifyServerThread;
  LSock: TInetSocket;
  LHandler: TTlsLibSocketHandler;
  LGreeting, LBuf: TBytes;
begin
  SetLength(LGreeting, RECORD_SIZE);
  FillChar(LGreeting[0], RECORD_SIZE, Ord('x'));
  LServer := Serve(LGreeting);
  try
    LSock := Open(LHandler);
    try
      SetLength(LBuf, RECORD_SIZE);
      if LSock.Read(LBuf[0], READ_SIZE) <> READ_SIZE then
        raise Exception.Create('the first read of the large record was short');
      if not LSock.CanRead(1000) then
        raise Exception.Create('CanRead is False with the rest of a record buffered');
      if LSock.Read(LBuf[0], RECORD_SIZE) <> RECORD_SIZE - READ_SIZE then
        raise Exception.Create('the rest of the large record was not read');
    finally
      LSock.Free;
    end;
  finally
    LServer.Terminate;
    LServer.Free;
  end;
end;
{$IFEND}

{ TTeardownProbeHandler }

constructor TTeardownProbeHandler.Create(AProbe: TTeardownProbe);
begin
  inherited Create;
  FProbe := AProbe;
end;

function TTeardownProbeHandler.CallInside: Boolean;
var
  LStart: TDateTime;
begin
  LStart := Now;
  while (FProbe.Left < FProbe.Entered) and (MilliSecondsBetween(Now, LStart) < DESTROY_GRACE_MS) do
    Sleep(1);
  Result := FProbe.Left < FProbe.Entered;
end;

destructor TTeardownProbeHandler.Destroy;
begin
  // a call still inside now is running in a handler that is about to be freed
  FProbe.InsideAtDestroy := CallInside;
  inherited Destroy;
  FProbe.InsideAfterBase := CallInside;
end;

function TTeardownProbeHandler.Recv(const Buffer; Count: Integer): Integer;
var
  LProbe: TTeardownProbe;
begin
  LProbe := FProbe;
  InterlockedIncrement(LProbe.Entered);
  Result := inherited Recv(Buffer, Count);
  InterlockedIncrement(LProbe.Left);
end;

{ TTeardownWorker }

constructor TTeardownWorker.Create(ASock: TInetSocket);
begin
  inherited Create(True);
  FreeOnTerminate := False;
  FSock := ASock;
  FDone := TEvent.Create(nil, True, False, '');
  Start;
end;

destructor TTeardownWorker.Destroy;
begin
  inherited Destroy;
  FDone.Free;
end;

procedure TTeardownWorker.Execute;
var
  LBuf: TBytes;
begin
  try
    SetLength(LBuf, 64);
    if FSock.Read(LBuf[0], System.Length(LBuf)) > 0 then
      FFailure := 'the read returned data from a silent peer';
  except
    on E: Exception do
      FFailure := E.ClassName + ': ' + E.Message;
  end;
  FDone.SetEvent;
end;

{ TTeardownCloser }

constructor TTeardownCloser.Create(ASock: TInetSocket; AHandler: TTeardownProbeHandler;
  AHow: TTeardownHow);
begin
  inherited Create(True);
  FreeOnTerminate := False;
  FSock := ASock;
  FHandler := AHandler;
  FHow := AHow;
  FDone := TEvent.Create(nil, True, False, '');
  Start;
end;

destructor TTeardownCloser.Destroy;
begin
  inherited Destroy;
  FDone.Free;
end;

procedure TTeardownCloser.Execute;
begin
  try
    if FHow = TeardownFree then
      FreeAndNil(FHandler)
    else
{$IF DECLARED(TSocketStates)}
      FSock.Close;
{$ELSE}
      // an fcl-net without a public Close frees the handler in the stream's destructor
      FreeAndNil(FSock);
{$IFEND}
  except
    on E: Exception do
      FFailure := E.ClassName + ': ' + E.Message;
  end;
  FDone.SetEvent;
end;

{ TTeardownCheck }

class procedure TTeardownCheck.Stuck(const AMessage: string);
begin
  // the stuck call holds its peer's connection open, so unwinding to free the server would hang
  WriteLn('FclNet loopback FAIL: ', AMessage);
  Halt(1);
end;

class procedure TTeardownCheck.Cycle(const ARoot: string; AIoTimeoutMs: Integer;
  AHow: TTeardownHow);
var
  LProbe: TTeardownProbe;
  LHandler: TTeardownProbeHandler;
  LSock: TInetSocket;
  LWorker: TTeardownWorker;
  LCloser: TTeardownCloser;
  LServer: TVerifyServerThread;
  LGreeting: TBytes;
  LWaitedMs, LBefore: Integer;
begin
  // the server never answers a close_notify, so only the socket can end the read; a failed check
  // leaves its worker and socket unfreed, as freeing them could hang on the read
  LServer := TBufferedPlaintextCheck.Serve(TBytes.Create(Ord('g')));
  LProbe := TTeardownProbe.Create;
  LHandler := TTeardownProbeHandler.Create(LProbe);
  LHandler.CertificateData.CertCA.FileName := ARoot;
  LSock := TInetSocket.Create('localhost', BUFFERED_PORT, LHandler);
  LSock.Connect;
  SetLength(LGreeting, 1);
  if LSock.Read(LGreeting[0], 1) <> 1 then
    raise Exception.Create('the greeting was not read');
  LBefore := LProbe.Entered;
  LSock.IOTimeout := AIoTimeoutMs;
  LWorker := TTeardownWorker.Create(LSock);
  LWaitedMs := 0;
  while (LProbe.Entered = LBefore) and (LWaitedMs < WATCHDOG_MS) do
  begin
    Sleep(1);
    Inc(LWaitedMs);
  end;
  if LProbe.Entered = LBefore then
    Stuck('the worker never reached Recv');
  Sleep(PARK_MS);
  LCloser := TTeardownCloser.Create(LSock, LHandler, AHow);
  if LCloser.Done.WaitFor(TEARDOWN_LIMIT_MS) <> wrSignaled then
    Stuck(Format('ending a read with a timeout of %d ms took over %d ms (%s)',
      [AIoTimeoutMs, TEARDOWN_LIMIT_MS, GetEnumName(TypeInfo(TTeardownHow), Ord(AHow))]));
  if LCloser.Failure <> '' then
    raise Exception.Create('ending the read failed: ' + LCloser.Failure);
  LSock := LCloser.Sock;
  LCloser.WaitFor;
  LCloser.Free;
{$IF NOT DECLARED(TSocketStates)}
  // only here is the handler destroyed on the closer's thread, where a Recv may still be inside
  if (AHow = TeardownClose) and LProbe.InsideAtDestroy then
    Stuck('the handler was destroyed while a Recv was still inside it');
{$IFEND}
  if LProbe.InsideAfterBase then
    Stuck('a Recv was still inside the handler after it was freed');
  if LWorker.Done.WaitFor(WATCHDOG_MS) <> wrSignaled then
    Stuck('the read did not return after the socket was closed');
  if LWorker.Failure <> '' then
    raise Exception.Create('the read that was woken failed: ' + LWorker.Failure);
  LWorker.WaitFor;
  LWorker.Free;
  // a handler freed directly leaves its socket stream pointing at it: the stream is not freed
  if AHow = TeardownClose then
    LSock.Free;
  LProbe.Free;
  LServer.Terminate;
  LServer.Free;
end;

class procedure TTeardownCheck.Run;
var
  LRoot: string;
  LI: Integer;
begin
  LRoot := TVectorLocator.WriteDer('teardown_root', TVectorLocator.FieldHex('root_cert'));
  for LI := 1 to RECV_CYCLES do
    Cycle(LRoot, 0, TeardownClose);
  // a read timeout far beyond any wait the guard may take
  for LI := 1 to RECV_CYCLES div 5 do
    Cycle(LRoot, LONG_IO_TIMEOUT_MS, TeardownClose);
  for LI := 1 to RECV_CYCLES div 5 do
    Cycle(LRoot, 0, TeardownFree);
end;

class procedure TTeardownCheck.RunClosed;
var
  LServer: TVerifyServerThread;
  LSock: TInetSocket;
  LHandler: TTlsLibSocketHandler;
  LBuf: TBytes;
begin
  LServer := TBufferedPlaintextCheck.Serve(TBytes.Create(Ord('g')));
  try
    LSock := TBufferedPlaintextCheck.Open(LHandler);
    try
      SetLength(LBuf, 1);
      if LSock.Read(LBuf[0], 1) <> 1 then
        raise Exception.Create('the greeting was not read');
      LSock.IOTimeout := READ_CAP_MS;
      LHandler.Close;
      if LHandler.Recv(LBuf[0], 1) <> 0 then
        raise Exception.Create('a Recv after Close did not end as a closed connection');
      if LHandler.LastError <> 0 then
        raise Exception.Create('a Recv after Close recorded a failure: ' + LHandler.LastErrorDesc);
    finally
      LSock.Free;
    end;
  finally
    LServer.Terminate;
    LServer.Free;
  end;
end;

{ TFaultingVerifier }

procedure TFaultingVerifier.Verify(Sender: TObject; var AAllow: Boolean);
begin
  raise EAccessViolation.Create('injected memory fault');
end;

{ TShutSocketHandler }

function TShutSocketHandler.Connect: Boolean;
begin
  fpShutdown(Socket.Handle, 2);
  Result := inherited Connect;
end;

{ TFailureCheck }

class procedure TFailureCheck.ExpectFailed(const ATest: string; AHandler: TTlsLibSocketHandler;
  AFamily: TFailureFamily);
begin
  if AHandler.LastErrorDesc = '' then
    raise Exception.Create(ATest + ': no description was recorded');
  if (AFamily = FamilySocket) and (AHandler.LastError <= 1) then
    raise Exception.CreateFmt('%s: the socket error number was not recorded (%d)',
      [ATest, AHandler.LastError]);
  if (AFamily <> FamilySocket) and (AHandler.LastError <> 1) then
    raise Exception.CreateFmt('%s: the error code is %d, not 1', [ATest, AHandler.LastError]);
{$IF FPC_FULLVERSION >= 30203}
  if (AFamily = FamilyAlert) and (AHandler.LastSSLErrorCode = 0) then
    raise Exception.Create(ATest + ': the alert was not recorded as the SSL error code');
  if (AFamily <> FamilyAlert) and (AHandler.LastSSLErrorCode <> 0) then
    raise Exception.CreateFmt('%s: an SSL error code %d was recorded though no alert was involved',
      [ATest, AHandler.LastSSLErrorCode]);
{$IFEND}
end;

class procedure TFailureCheck.ConnectRefused(const ATest: string; AHandler: TTlsLibSocketHandler;
  AFamily: TFailureFamily);
var
  LSock: TInetSocket;
begin
  LSock := TInetSocket.Create('localhost', BUFFERED_PORT, AHandler);
  try
    try
      LSock.Connect;
      raise Exception.Create(ATest + ': the connection was not refused');
    except
      // TInetSocket raises a generic connect error when the handshake refuses
      on ESocketError do
        ExpectFailed(ATest, AHandler, AFamily);
    end;
  finally
    LSock.Free;
  end;
end;

class procedure TFailureCheck.RunSendFault;
var
  LServer: TVerifyServerThread;
  LSock: TInetSocket;
  LHandler: TTlsLibSocketHandler;
  LNil: PByte;
  LRaised: Boolean;
begin
  LServer := TBufferedPlaintextCheck.Serve(nil);
  try
    LSock := TBufferedPlaintextCheck.Open(LHandler);
    try
      LNil := nil;
      LRaised := False;
      try
        LHandler.Send(LNil^, FAULT_BYTES);
      except
        on EAccessViolation do
          LRaised := True;
      end;
      if not LRaised then
        raise Exception.Create('a memory fault inside Send was turned into an error code');
    finally
      LSock.Free;
    end;
  finally
    LServer.Terminate;
    LServer.Free;
  end;
end;

class procedure TFailureCheck.RunRecvFault;
var
  LServer: TVerifyServerThread;
  LSock: TInetSocket;
  LHandler: TTlsLibSocketHandler;
  LNil: PByte;
  LRaised: Boolean;
begin
  LServer := TBufferedPlaintextCheck.Serve(TBytes.Create(Ord('g')));
  try
    LSock := TBufferedPlaintextCheck.Open(LHandler);
    try
      LNil := nil;
      LRaised := False;
      try
        LHandler.Recv(LNil^, 1);
      except
        on EAccessViolation do
          LRaised := True;
      end;
      if not LRaised then
        raise Exception.Create('a memory fault inside Recv was turned into an error code');
    finally
      LSock.Free;
    end;
  finally
    LServer.Terminate;
    LServer.Free;
  end;
end;

class procedure TFailureCheck.RunConnectFault;
var
  LServer: TVerifyServerThread;
  LSock: TInetSocket;
  LHandler: TTlsLibSocketHandler;
  LVerifier: TFaultingVerifier;
  LRaised: Boolean;
begin
  LServer := TBufferedPlaintextCheck.Serve(nil);
  try
    LVerifier := TFaultingVerifier.Create;
    try
      LHandler := TTlsLibSocketHandler.Create;
      LHandler.CertificateData.CertCA.FileName := TVectorLocator.WriteDer('fault_root',
        TVectorLocator.FieldHex('root_cert'));
      LHandler.OnVerifyCertificate := LVerifier.Verify;
      LSock := TInetSocket.Create('localhost', BUFFERED_PORT, LHandler);
      try
        LRaised := False;
        try
          LSock.Connect;
        except
          on EAccessViolation do
            LRaised := True;
        end;
        if not LRaised then
          raise Exception.Create(
            'a memory fault inside the handshake was turned into a failed Connect');
      finally
        LSock.Free;
      end;
    finally
      LVerifier.Free;
    end;
  finally
    LServer.Terminate;
    LServer.Free;
  end;
end;

class procedure TFailureCheck.RunFamilies;
var
  LServer: TVerifyServerThread;
  LSock: TInetSocket;
  LHandler: TTlsLibSocketHandler;
  LBuf: TBytes;
begin
  LBuf := TBytes.Create(Ord('x'), Ord('y'));
  LServer := TBufferedPlaintextCheck.Serve(nil);
  try
    // Connect: a chain refusal carries the engine's alert
    LHandler := TTlsLibSocketHandler.Create;
    LHandler.CertificateData.CertCA.FileName := TVectorLocator.WriteDer('families_wrong_root',
      TVectorLocator.FieldHex('root2_cert'));
    ConnectRefused('a chain refusal', LHandler, FamilyAlert);
    // Connect: a trust file that cannot be opened
    LHandler := TTlsLibSocketHandler.Create;
    LHandler.CertificateData.CertCA.FileName := IncludeTrailingPathDelimiter(GetTempDir) +
      'tlslib_fcl_no_such_root.der';
    ConnectRefused('an unreadable trust file', LHandler, FamilyStream);
    // Connect: a socket that cannot carry the ClientHello
    LHandler := TShutSocketHandler.Create;
    LHandler.CertificateData.CertCA.FileName := TVectorLocator.WriteDer('families_root',
      TVectorLocator.FieldHex('root_cert'));
    ConnectRefused('a shut socket', LHandler, FamilySocket);

    // Send and Recv: a handler with no session yet
    LHandler := TTlsLibSocketHandler.Create;
    try
      if LHandler.Send(LBuf[0], System.Length(LBuf)) <> -1 then
        raise Exception.Create('Send with no session did not fail');
      ExpectFailed('Send with no session', LHandler, FamilyStream);
      if LHandler.Recv(LBuf[0], System.Length(LBuf)) <> -1 then
        raise Exception.Create('Recv with no session did not fail');
      ExpectFailed('Recv with no session', LHandler, FamilyStream);
    finally
      LHandler.Free;
    end;

    // Send: a socket whose write side is shut
    LSock := TBufferedPlaintextCheck.Open(LHandler);
    try
      fpShutdown(LSock.Handle, 1);
      if LHandler.Send(LBuf[0], System.Length(LBuf)) <> -1 then
        raise Exception.Create('Send on a shut socket did not fail');
      ExpectFailed('Send on a shut socket', LHandler, FamilySocket);
    finally
      LSock.Free;
    end;
    // Send: a stream whose write side was closed
    LSock := TBufferedPlaintextCheck.Open(LHandler);
    try
      LHandler.Shutdown(False);
      if LHandler.Send(LBuf[0], System.Length(LBuf)) <> -1 then
        raise Exception.Create('Send after Shutdown did not fail');
      ExpectFailed('Send after Shutdown', LHandler, FamilyStream);
    finally
      LSock.Free;
    end;

    // Recv: an idle read that times out, then a call that succeeds clears the record
    LSock := TBufferedPlaintextCheck.Open(LHandler);
    try
      LSock.IOTimeout := READ_CAP_MS;
      if LHandler.Recv(LBuf[0], System.Length(LBuf)) <> -1 then
        raise Exception.Create('Recv on a quiet connection did not time out');
      ExpectFailed('Recv timing out', LHandler, FamilyStream);
      if LHandler.Send(LBuf[0], System.Length(LBuf)) <> System.Length(LBuf) then
        raise Exception.Create('Send after a timed-out Recv failed');
      if (LHandler.LastError <> 0) or (LHandler.LastErrorDesc <> '') then
        raise Exception.Create('a successful call did not clear the recorded failure');
    finally
      LSock.Free;
    end;
  finally
    LServer.Terminate;
    LServer.Free;
  end;
end;

{ TTestCertificateDataHandler }

function TTestCertificateDataHandler.CreateCertificateData: TCertificateData;
begin
  Result := TTestCertificateData.Create;
end;

{ TNameHashCheck }

type
  TNameVector = record
    Id, NameHex, Hash: string;
  end;

const
  NameVectors: array[0..22] of TNameVector = (
    (Id: 'V01'; NameHex: '303a310b300906035504061302555331143012060355040a0c0b4578616d706c65' +
      '204f72673115301306035504030c0c5465737420526f6f74204341'; Hash: '9e441091'),
    (Id: 'V02b'; NameHex: '3044310b3009060355040613027573311b3019060355040a0c122020455841' +
      '4d504c45202020206f72672020311830160603550403140f5445535409524f4f5420206361200d';
      Hash: '9e441091'),
    (Id: 'V03'; NameHex: '3069310b3009060355040613025553311f301d060355040a1e16004500780061006d' +
      '0070006c00650020004f007200673139303706035504031c300000005400000065000000730000007400' +
      '000020000000520000006f0000006f00000074000000200000004300000041'; Hash: '9e441091'),
    (Id: 'V04'; NameHex: '30173115301306035504030c0c5ac3bc7269636820526f6f74'; Hash: 'd7587034'),
    (Id: 'V05'; NameHex: '3021311f301d06035504031e16005a00dc005200490043004800200052004f004f0054';
      Hash: '618f6b86'),
    (Id: 'V06'; NameHex: '3021311f301d06035504031e16005a00fc005200490043004800200052004f004f0054';
      Hash: 'd7587034'),
    (Id: 'V07'; NameHex: '30123110300e06035504031407434146e9204341'; Hash: 'aefaca7d'),
    (Id: 'V08'; NameHex: '30133111300f06035504030c08436166c3a9206361'; Hash: 'aefaca7d'),
    (Id: 'V09'; NameHex: '302631123010060355040512092030303132202033343110300e06035504030c07' +
      '4e756d65726963'; Hash: '8f121613'),
    (Id: 'V10'; NameHex: '302631123010060355040513092030303132202033343110300e06035504030c07' +
      '4e756d65726963'; Hash: '83108283'),
    (Id: 'V11'; NameHex: '30163114300806035504030c014230080603550403130161'; Hash: '3881cc6b'),
    (Id: 'V12'; NameHex: '30163114300806035504030c0161300806035504030c0162'; Hash: '3881cc6b'),
    (Id: 'V13'; NameHex: '3000'; Hash: 'eea339da'),
    (Id: 'V14'; NameHex: '303a3120301e06092a864886f70d010901161141646d696e404558414d504c452e' +
      '636f6d311630140603550403160d0b20524f4f540c0d094361200b'; Hash: 'eb7f80fd'),
    (Id: 'V15'; NameHex: '30133111300f06035504030c08526f6f74c2a04341'; Hash: 'ac0d448f'),
    (Id: 'V16'; NameHex: '300e310c300a06035504030c03202020'; Hash: '5da78770'),
    (Id: 'V17'; NameHex: '30153113301106035504031a0a56697369626c65204341'; Hash: ''),
    (Id: 'V18'; NameHex: '30153113301106035504031b0a47656e6572616c204341'; Hash: ''),
    (Id: 'V19'; NameHex: '30123110300e06035504030c07726f6f74206361'; Hash: '8489a545'),
    // characters outside the Windows-1252 code page, in the string types that carry them
    (Id: 'BMP'; NameHex: '30153113301106035504031e0a4e2d6587002000430041'; Hash: '2dcc6b02'),
    (Id: 'BMP2'; NameHex: '30153113301106035504031e0a0046015100740061006e'; Hash: '1bb44642'),
    (Id: 'T61'; NameHex: '3010310e300c060355040314056e656c8578'; Hash: '3e17d610'),
    // a noncharacter is well-formed UTF-8
    (Id: 'FFFE'; NameHex: '3010310e300c06035504030c0561efbfbe62'; Hash: '8ebba88d'));

  // one name in different string types: their hashes are equal
  NameTwins: array[0..2, 0..1] of string = (
    ('30143112301006035504030c09e4b8ade69687204341',
      '30153113301106035504031e0a4e2d6587002000430041'),
    ('30143112301006035504030c09e4b8ade69687204341',
      '301f311d301b06035504031c1400004e2d00006587000000200000004300000041'),
    ('300f310d300b06035504030c04f09f9880', '300f310d300b06035504031c040001f600'));

  // names that do not parse as a subject, or hold a string that does not convert
  MalformedNames: array[0..18, 0..1] of string = (
    ('truncated', '303a310b300906035504061302555331143012060355040a0c0b4578616d706c65204f72673115' +
      '301306035504030c0c5465737420526f6f7420'),
    ('over-long', '303b310b300906035504061302555331143012060355040a0c0b4578616d706c65204f72673115' +
      '301306035504030c0c5465737420526f6f74204341'),
    ('trailing byte', '303a310b300906035504061302555331143012060355040a0c0b4578616d706c65204f7267' +
      '3115301306035504030c0c5465737420526f6f7420434100'),
    ('empty SET', '30023100'),
    ('invalid UTF-8', '300d310b300906035504030c02c328'),
    ('UTF-8 overlong', '300d310b300906035504030c02c0af'),
    ('UTF-8 surrogate', '300e310c300a06035504030c03eda080'),
    ('UTF-8 truncated at end', '300d310b300906035504030c0241c3'),
    ('UTF-8 above 10FFFF', '300f310d300b06035504030c04f4908080'),
    ('UTF-8 FF', '300c310a300806035504030c01ff'),
    ('UTF-8 lone continuation', '300c310a300806035504030c0180'),
    ('BMP surrogate pair', '300f310d300b06035504031e04d83dde00'),
    ('BMP surrogate', '300d310b300906035504031e02d800'),
    ('odd BMP', '300c310a300806035504031e0141'),
    ('UniversalString above 10FFFF', '300f310d300b06035504031c0400110000'),
    ('UniversalString surrogate', '300f310d300b06035504031c040000d800'),
    ('UniversalString of 3 bytes', '300e310c300a06035504031c03000041'),
    ('not a SEQUENCE', '310d310b300906035504030c02c328'),
    ('empty', ''));

class procedure TNameHashCheck.RunVectors(const ACrypto: ICryptoProvider);
var
  LI: Integer;
  LGot: string;
begin
  for LI := 0 to System.High(NameVectors) do
  begin
    LGot := TOpenSslNameHash.OfName(ACrypto, TDataEncoding.HexDecode(NameVectors[LI].NameHex));
    if LGot <> NameVectors[LI].Hash then
      raise Exception.CreateFmt('name hash %s is "%s", not "%s"',
        [NameVectors[LI].Id, LGot, NameVectors[LI].Hash]);
  end;
  for LI := 0 to System.High(NameTwins) do
  begin
    LGot := TOpenSslNameHash.OfName(ACrypto, TDataEncoding.HexDecode(NameTwins[LI, 0]));
    if (LGot = '') or
      (LGot <> TOpenSslNameHash.OfName(ACrypto, TDataEncoding.HexDecode(NameTwins[LI, 1]))) then
      raise Exception.CreateFmt('the twin names %d do not share a hash', [LI]);
  end;
end;

class procedure TNameHashCheck.RunMalformed(const ACrypto: ICryptoProvider);
var
  LI: Integer;
begin
  for LI := 0 to System.High(MalformedNames) do
    if TOpenSslNameHash.OfName(ACrypto, TDataEncoding.HexDecode(MalformedNames[LI, 1])) <> ''
    then
      raise Exception.Create('the malformed name "' + MalformedNames[LI, 0] + '" got a hash');
end;

class function TNameHashCheck.NextRandom(var AState: UInt32): UInt32;
begin
  AState := UInt32((UInt64(AState) * 1664525 + 1013904223) and $FFFFFFFF);
  Result := AState;
end;

class function TNameHashCheck.CommonName(AStringType: Byte; const AText: string): TBytes;
var
  LValue: TBytes;
  LCharBytes, LI: Integer;
begin
  // short length forms only: the text stays below 40 characters
  LCharBytes := 1;
  if AStringType = $1E then
    LCharBytes := 2;
  SetLength(LValue, System.Length(AText) * LCharBytes);
  for LI := 0 to System.Length(AText) - 1 do
    LValue[(LI + 1) * LCharBytes - 1] := Byte(AText[LI + 1]);
  Result := nil;
  SetLength(Result, 13 + System.Length(LValue));
  Result[0] := $30;
  Result[1] := Byte(System.Length(LValue) + 11);
  Result[2] := $31;
  Result[3] := Byte(System.Length(LValue) + 9);
  Result[4] := $30;
  Result[5] := Byte(System.Length(LValue) + 7);
  // the commonName attribute
  Result[6] := $06;
  Result[7] := 3;
  Result[8] := $55;
  Result[9] := $04;
  Result[10] := $03;
  Result[11] := AStringType;
  Result[12] := Byte(System.Length(LValue));
  Move(LValue[0], Result[13], System.Length(LValue));
end;

class procedure TNameHashCheck.RunEquivalent(const ACrypto: ICryptoProvider);
const
  ROUNDS = 20000;
  LETTERS = 'abcdefghijklmnopqrstuvwxyz0123456789';
  STRING_TYPES: array[0..2] of Byte = ($0C, $1E, $13);
var
  LState: UInt32;
  LI, LWord, LChar, LWords, LWordLength: Integer;
  LPlain, LLoud, LText: string;
  LPlainHash, LLoudHash: string;
begin
  LState := 20231102;
  for LI := 1 to ROUNDS do
  begin
    LPlain := '';
    LLoud := StringOfChar(' ', Integer(NextRandom(LState) mod 3));
    LWords := 1 + Integer(NextRandom(LState) mod 3);
    for LWord := 1 to LWords do
    begin
      if LWord > 1 then
      begin
        LPlain := LPlain + ' ';
        LLoud := LLoud + StringOfChar(' ', 1 + Integer(NextRandom(LState) mod 3));
      end;
      LWordLength := 1 + Integer(NextRandom(LState) mod 6);
      LText := '';
      for LChar := 1 to LWordLength do
        LText := LText +
          LETTERS[1 + Integer(NextRandom(LState) mod UInt32(System.Length(LETTERS)))];
      LPlain := LPlain + LText;
      LLoud := LLoud + UpperCase(LText);
    end;
    LLoud := LLoud + StringOfChar(' ', Integer(NextRandom(LState) mod 3));
    LPlainHash := TOpenSslNameHash.OfName(ACrypto, CommonName($0C, LPlain));
    LLoudHash := TOpenSslNameHash.OfName(ACrypto,
      CommonName(STRING_TYPES[NextRandom(LState) mod 3], LLoud));
    if (LPlainHash = '') or (LPlainHash <> LLoudHash) then
      raise Exception.CreateFmt('the names "%s" and "%s" hash as "%s" and "%s"',
        [LPlain, LLoud, LPlainHash, LLoudHash]);
  end;
end;

class procedure TNameHashCheck.RunCorruptions(const ACrypto: ICryptoProvider);
const
  ROUNDS = 100000;
var
  LBase, LMutant: TBytes;
  LState: UInt32;
  LI, LJ, LHashed: Integer;
begin
  LBase := TDataEncoding.HexDecode(NameVectors[0].NameHex);
  LState := 20231101;
  LHashed := 0;
  for LI := 1 to ROUNDS do
  begin
    LMutant := System.Copy(LBase, 0, System.Length(LBase));
    for LJ := 0 to Integer((NextRandom(LState) shr 28) mod 3) do
    begin
      NextRandom(LState);
      LMutant[(LState shr 8) mod UInt32(System.Length(LMutant))] := Byte(LState shr 24);
    end;
    if (LState and 7) = 0 then
      SetLength(LMutant, (LState shr 8) mod UInt32(System.Length(LMutant)));
    if TOpenSslNameHash.OfName(ACrypto, LMutant) <> '' then
      Inc(LHashed);
  end;
  // a corruption inside a string still hashes, one inside the structure does not
  if (LHashed = 0) or (LHashed = ROUNDS) then
    raise Exception.CreateFmt('%d of %d corrupted names were hashed', [LHashed, ROUNDS]);
end;

class procedure TNameHashCheck.Run(const ACrypto: ICryptoProvider);
begin
  RunVectors(ACrypto);
  RunMalformed(ACrypto);
  RunEquivalent(ACrypto);
  RunCorruptions(ACrypto);
end;

{ TConnectCheckBase }

class procedure TConnectCheckBase.ExpectEquals(const ATest, AWanted, AGot, AError: string);
begin
  if AGot <> AWanted then
    raise Exception.Create(ATest + ' gave "' + AGot + '", not "' + AWanted + '": ' + AError);
end;

class procedure TConnectCheckBase.ExpectRefused(const ATest, AGot, AError, AReason: string);
begin
  if AGot <> '' then
    raise Exception.Create(ATest + ' was served "' + AGot + '"');
  if Pos(AReason, AError) = 0 then
    raise Exception.Create(ATest + ' was not refused for "' + AReason + '": ' + AError);
end;

{ TTrustedCertsDirCheck }

class function TTrustedCertsDirCheck.Echo(const ADirs, ACertCA: string;
  out AError: string): string;
var
  LHandler: TTestCertificateDataHandler;
begin
  LHandler := TTestCertificateDataHandler.Create;
  (LHandler.CertificateData as TTestCertificateData).TrustedCertsDir := ADirs;
  if ACertCA <> '' then
    LHandler.CertificateData.CertCA.FileName := ACertCA;
  Result := TVerifyClient.Echo(LHandler, CERTS_DIR_PORT, AError);
end;

class function TTrustedCertsDirCheck.EchoChain(const ADirs, ACertCA: string;
  ARule: TBundleAnchorRule; out AError: string): string;
var
  LHandler: TTestCertificateDataHandler;
begin
  LHandler := TTestCertificateDataHandler.Create;
  (LHandler.CertificateData as TTestCertificateData).TrustedCertsDir := ADirs;
  if ACertCA <> '' then
    LHandler.CertificateData.CertCA.FileName := ACertCA;
  LHandler.BundleAnchors := ARule;
  Result := TVerifyClient.Echo(LHandler, CERTS_DIR_CHAIN_PORT, AError);
end;

class function TTrustedCertsDirCheck.NewDir(const ABase, AName: string): string;
begin
  Result := IncludeTrailingPathDelimiter(ABase) + AName;
  if not ForceDirectories(Result) then
    raise Exception.Create('cannot create the directory ' + Result);
end;

class procedure TTrustedCertsDirCheck.RemoveTree(const ADir: string);
var
  LFind: TSearchRec;
  LDir: string;
begin
  LDir := IncludeTrailingPathDelimiter(ADir);
  if FindFirst(LDir + '*', faAnyFile or faSymLink, LFind) = 0 then
    try
      repeat
        if (LFind.Name = '.') or (LFind.Name = '..') then
          Continue;
        // a link is removed itself, never walked into
        if (LFind.Attr and faSymLink) <> 0 then
        begin
          if not DeleteFile(LDir + LFind.Name) then
            RemoveDir(LDir + LFind.Name);
        end
        else if (LFind.Attr and faDirectory) <> 0 then
          RemoveTree(LDir + LFind.Name)
        else
          DeleteFile(LDir + LFind.Name);
      until FindNext(LFind) <> 0;
    finally
      FindClose(LFind);
    end;
  RemoveDir(ADir);
end;

class procedure TTrustedCertsDirCheck.RunNaming(const ABase, ARootHex, AOtherHex: string;
  AServer: TLoopbackServerBase);
var
  LDir, LHashed, LEcho, LError, LRootName, LOtherName: string;
begin
  LRootName := PathDelim + RootHash;
  LOtherName := PathDelim + OtherHash;

  // a root is found only under the hash of its own subject
  LDir := NewDir(ABase, 'misnamed');
  TVectorLocator.WritePemTo(LDir + PathDelim + '00000000.0', 'CERTIFICATE', [ARootHex]);
  LEcho := Echo(LDir, '', LError);
  ExpectRefused('a root in a file named for no hash', LEcho, LError, UNTRUSTED_CHAIN);
  AServer.WaitSettled;

  // and does not vouch for the root beside a sound file
  LDir := NewDir(ABase, 'misnamedbeside');
  TVectorLocator.WritePemTo(LDir + PathDelim + '00000000.0', 'CERTIFICATE', [ARootHex]);
  TVectorLocator.WritePemTo(LDir + LOtherName + '.0', 'CERTIFICATE', [AOtherHex]);
  LEcho := Echo(LDir, '', LError);
  ExpectRefused('a root in a file named for no hash beside a sound file', LEcho, LError,
    UNTRUSTED_CHAIN);

  // each certificate of a file is named on its own: the root keeps the hash of its subject
  LDir := NewDir(ABase, 'otherfile');
  TVectorLocator.WritePemTo(LDir + LOtherName + '.0', 'CERTIFICATE', [AOtherHex, ARootHex]);
  LEcho := Echo(LDir, '', LError);
  ExpectRefused('a root in the file of another root', LEcho, LError, UNTRUSTED_CHAIN);

  // a file holds more than one certificate and each of them counts
  LDir := NewDir(ABase, 'multi');
  TVectorLocator.WritePemTo(LDir + LRootName + '.0', 'CERTIFICATE', [LookalikeRootHex, ARootHex]);
  LEcho := Echo(LDir, '', LError);
  ExpectEquals('a root after another certificate of its hash in one file', 'verify', LEcho, LError);

  // only PEM is read: the same certificate as DER, or under another PEM label, trusts nothing
  LDir := NewDir(ABase, 'der');
  LHashed := LDir + LRootName + '.0';
  TVectorLocator.WriteDerTo(LHashed, ARootHex);
  LEcho := Echo(LDir, '', LError);
  ExpectRefused('a root as DER in its hashed file', LEcho, LError, UNTRUSTED_CHAIN);
  AServer.WaitSettled;

  LDir := NewDir(ABase, 'trusted');
  LHashed := LDir + LRootName + '.0';
  TVectorLocator.WritePemTo(LHashed, 'TRUSTED CERTIFICATE', [ARootHex]);
  LEcho := Echo(LDir, '', LError);
  ExpectRefused('a root as a TRUSTED CERTIFICATE block', LEcho, LError, UNTRUSTED_CHAIN);
  AServer.WaitSettled;

  LDir := NewDir(ABase, 'pkcs7');
  LHashed := LDir + LRootName + '.0';
  TVectorLocator.WritePemTo(LHashed, 'PKCS7', [ARootHex]);
  LEcho := Echo(LDir, '', LError);
  ExpectRefused('a root in a PKCS7 block', LEcho, LError, UNTRUSTED_CHAIN);
  AServer.WaitSettled;

  LDir := NewDir(ABase, 'unterminated');
  LHashed := LDir + LRootName + '.0';
  TVectorLocator.WriteDerTo(LHashed, TDataEncoding.HexEncode(
    TEncoding.ASCII.GetBytes('-----BEGIN CERTIFICATE-----' + #10 + 'MIIB' + #10)));
  LEcho := Echo(LDir, '', LError);
  ExpectRefused('a PEM block without its end', LEcho, LError, UNTRUSTED_CHAIN);
  AServer.WaitSettled;

  // a certificate whose subject is not the asked name is not the issuer, whatever file it is in
  LDir := NewDir(ABase, 'unnamed');
  LHashed := LDir + LRootName + '.0';
  TVectorLocator.WritePemTo(LHashed, 'CERTIFICATE',
    [StringReplace(LookalikeRootHex, '06035504030c13', '06035504031a13', [rfReplaceAll])]);
  LEcho := Echo(LDir, '', LError);
  ExpectRefused('a certificate of another subject under the hash of the root', LEcho, LError,
    UNTRUSTED_CHAIN);
  AServer.WaitSettled;

  LDir := NewDir(ABase, 'emptyfile');
  LHashed := LDir + LRootName + '.0';
  TVectorLocator.WriteDerTo(LHashed, '');
  LEcho := Echo(LDir, '', LError);
  ExpectRefused('an empty hashed file', LEcho, LError, UNTRUSTED_CHAIN);
  AServer.WaitSettled;

  LDir := NewDir(ABase, 'padded');
  LHashed := LDir + LRootName + '.0';
  TVectorLocator.WritePemTo(LHashed, 'CERTIFICATE', [ARootHex]);
  TVectorLocator.PadTo(LHashed, PADDED_FILE_BYTES);
  LEcho := Echo(LDir, '', LError);
  ExpectEquals('a hashed file larger than a megabyte', 'verify', LEcho, LError);
end;

class procedure TTrustedCertsDirCheck.RunSkipped(const ABase, ARootHex,
  ALookalikeHex: string);
var
  LDir, LRootName, LEcho, LError: string;
  LLocked: TFileStream;
begin
  LRootName := PathDelim + RootHash;

  // a file with no certificate does not end the numbers
  LDir := NewDir(ABase, 'skipgarbage');
  TVectorLocator.WriteDerTo(LDir + LRootName + '.0', '0001020304');
  TVectorLocator.WritePemTo(LDir + LRootName + '.1', 'CERTIFICATE', [ARootHex]);
  LEcho := Echo(LDir, '', LError);
  ExpectEquals('a root after a file holding no certificate', 'verify', LEcho, LError);

  // nor does a PEM block that cannot be framed
  LDir := NewDir(ABase, 'skipunterminated');
  TVectorLocator.WriteDerTo(LDir + LRootName + '.0', TDataEncoding.HexEncode(
    TEncoding.ASCII.GetBytes('-----BEGIN CERTIFICATE-----' + #10 + 'MIIB' + #10)));
  TVectorLocator.WritePemTo(LDir + LRootName + '.1', 'CERTIFICATE', [ARootHex]);
  LEcho := Echo(LDir, '', LError);
  ExpectEquals('a root after a PEM block without its end', 'verify', LEcho, LError);

  // nor does a file that cannot be opened, where the file system keeps an open file from a reader
  LDir := NewDir(ABase, 'skiplocked');
  TVectorLocator.WritePemTo(LDir + LRootName + '.0', 'CERTIFICATE', [ALookalikeHex]);
  TVectorLocator.WritePemTo(LDir + LRootName + '.1', 'CERTIFICATE', [ARootHex]);
  LLocked := TFileStream.Create(LDir + LRootName + '.0', fmOpenRead or fmShareExclusive);
  try
    LEcho := Echo(LDir, '', LError);
  finally
    LLocked.Free;
  end;
  ExpectEquals('a root after a file that cannot be opened', 'verify', LEcho, LError);

  // nor does a PEM block whose body is not base64, whatever the decoder raises for it
  LDir := NewDir(ABase, 'skipbadbody');
  TVectorLocator.WriteDerTo(LDir + LRootName + '.0', TDataEncoding.HexEncode(
    TEncoding.ASCII.GetBytes('-----BEGIN CERTIFICATE-----' + #10 + '!!%%not base64%%!!' + #10 +
    '-----END CERTIFICATE-----' + #10)));
  TVectorLocator.WritePemTo(LDir + LRootName + '.1', 'CERTIFICATE', [ARootHex]);
  LEcho := Echo(LDir, '', LError);
  ExpectEquals('a root after a PEM block that is not base64', 'verify', LEcho, LError);
end;

class procedure TTrustedCertsDirCheck.RunPermissions(const ABase, ARootHex,
  ALookalikeHex: string);
{$IFDEF UNIX}
var
  LDir, LDenied, LEcho, LError: string;
{$ENDIF}
begin
{$IFDEF UNIX}
  // a file the process may not read is skipped like any file that cannot be used; root reads it anyway
  if fpGetUid = 0 then
    Exit;
  LDir := NewDir(ABase, 'skipdenied');
  LDenied := LDir + PathDelim + RootHash + '.0';
  TVectorLocator.WritePemTo(LDenied, 'CERTIFICATE', [ALookalikeHex]);
  TVectorLocator.WritePemTo(LDir + PathDelim + RootHash + '.1', 'CERTIFICATE', [ARootHex]);
  if fpChmod(PChar(LDenied), 0) <> 0 then
    raise Exception.Create('cannot change the mode of ' + LDenied);
  LEcho := Echo(LDir, '', LError);
  ExpectEquals('a root after a file that may not be read', 'verify', LEcho, LError);
{$ENDIF}
end;

class procedure TTrustedCertsDirCheck.RunLinks(const ABase, ARootHex: string);
{$IFDEF UNIX}
var
  LDir, LTarget, LEcho, LError: string;
{$ENDIF}
begin
{$IFDEF UNIX}
  // a link with nothing at its end is skipped like any file that cannot be used
  LDir := NewDir(ABase, 'skipbroken');
  TVectorLocator.WritePemTo(LDir + PathDelim + RootHash + '.1', 'CERTIFICATE', [ARootHex]);
  if fpSymlink(PChar(LDir + PathDelim + 'absent.pem'),
    PChar(LDir + PathDelim + RootHash + '.0')) <> 0 then
    raise Exception.Create('cannot create a link in ' + LDir);
  LEcho := Echo(LDir, '', LError);
  ExpectEquals('a root after a broken link', 'verify', LEcho, LError);

  // and a link to a certificate is followed
  LTarget := NewDir(ABase, 'linktarget') + PathDelim + 'root.pem';
  TVectorLocator.WritePemTo(LTarget, 'CERTIFICATE', [ARootHex]);
  LDir := NewDir(ABase, 'followed');
  if fpSymlink(PChar(LTarget), PChar(LDir + PathDelim + RootHash + '.0')) <> 0 then
    raise Exception.Create('cannot create a link in ' + LDir);
  LEcho := Echo(LDir, '', LError);
  ExpectEquals('a root behind a link', 'verify', LEcho, LError);
{$ENDIF}
end;

class procedure TTrustedCertsDirCheck.RunIssuers(const ABase: string);
var
  LServer: TVerifyServerThread;
  LRootHex, LIssuerHex, LWrongRoot, LDir, LEcho, LError: string;
begin
  LRootHex := TVectorLocator.FieldHexFrom('ReissuedRoot.txt', 'root_cert');
  LIssuerHex := TVectorLocator.FieldHexFrom('ReissuedRoot.txt', 'issuer_cert');
  LWrongRoot := NewDir(ABase, 'chainwrong') + PathDelim + 'root.der';
  TVectorLocator.WriteDerTo(LWrongRoot, TVectorLocator.FieldHexFrom('ReissuedRoot.txt',
    'root2_cert'));
  LServer := TVerifyServerThread.Create(
    TDataEncoding.HexDecode(TVectorLocator.FieldHexFrom('ReissuedRoot.txt', 'leaf_cert')),
    TDataEncoding.HexDecode(TVectorLocator.FieldHexFrom('ReissuedRoot.txt', 'leaf_key')),
    CERTS_DIR_CHAIN_PORT);
  try
    LServer.StartListening;

    // an intermediate alone is chain material and anchors nothing
    LDir := NewDir(ABase, 'issuer');
    TVectorLocator.WritePemTo(LDir + PathDelim + ChainIssuerHash + '.0', 'CERTIFICATE',
      [LIssuerHex]);
    LEcho := EchoChain(LDir, '', TBundleAnchorRule.SelfSignedOnly, LError);
    ExpectRefused('an intermediate alone in the directory', LEcho, LError, UNTRUSTED_CHAIN);
    ExpectRefused('the refusal of an intermediate alone in the directory', LEcho, LError,
      SKIPPED_HINT);
    LServer.WaitSettled;

    // the hint belongs to a directory
    LEcho := EchoChain('', LWrongRoot, TBundleAnchorRule.SelfSignedOnly, LError);
    ExpectRefused('a wrong root in CertCA', LEcho, LError, UNTRUSTED_CHAIN);
    if Pos(SKIPPED_HINT, LError) > 0 then
      raise Exception.Create('a wrong root in CertCA was refused with the hint of a directory: ' +
        LError);
    LServer.WaitSettled;

    // with its root beside it the intermediate completes a chain that sends the leaf alone
    TVectorLocator.WritePemTo(LDir + PathDelim + ChainRootHash + '.0', 'CERTIFICATE', [LRootHex]);
    LEcho := EchoChain(LDir, '', TBundleAnchorRule.SelfSignedOnly, LError);
    ExpectEquals('an intermediate beside its root', 'verify', LEcho, LError);

    // and under AnyCertificate it anchors by itself
    LDir := NewDir(ABase, 'issueranchor');
    TVectorLocator.WritePemTo(LDir + PathDelim + ChainIssuerHash + '.0', 'CERTIFICATE',
      [LIssuerHex]);
    LEcho := EchoChain(LDir, '', TBundleAnchorRule.AnyCertificate, LError);
    ExpectEquals('an intermediate alone under AnyCertificate', 'verify', LEcho, LError);
  finally
    LServer.Terminate;
    LServer.Free;
  end;
end;

class procedure TTrustedCertsDirCheck.RunIdentity(const ABase: string);
var
  LCrypto: ICryptoProvider;
  LLookup, LRespelled, LOther, LMissing, LRelativeLookup: IIssuerLookup;
  LDir, LUnchanged, LAbsent, LExtra, LCurrent, LRelative, LBefore: string;
  LStamp, LLater: LongInt;
begin
  LCrypto := TDefaultCryptoProvider.Create as ICryptoProvider;
  LDir := NewDir(ABase, 'identity');
  LStamp := DateTimeToFileDate(EncodeDate(2024, 1, 1));
  LLater := DateTimeToFileDate(EncodeDate(2025, 1, 1));
  if FileSetDate(LDir, LStamp) <> 0 then
    raise Exception.Create('cannot set the time of the directory ' + LDir);
  LLookup := TOpenSslHashedDirLookup.Create(LCrypto, LDir) as IIssuerLookup;
  LUnchanged := LLookup.Identity;

  // the same directories spelled with empty entries, a trailing delimiter and a repeat
  LRespelled := TOpenSslHashedDirLookup.Create(LCrypto,
    PathSeparator + LDir + PathDelim + PathSeparator + LDir) as IIssuerLookup;
  ExpectEquals('a directory spelled another way', LUnchanged, LRespelled.Identity,
    'the identity names the spelling');

  LOther := TOpenSslHashedDirLookup.Create(LCrypto, NewDir(ABase, 'identityother'))
    as IIssuerLookup;
  if LOther.Identity = LUnchanged then
    raise Exception.Create('two directories share the identity "' + LUnchanged + '"');

  // a directory that changed names another lookup, and one set back names the first again
  if FileSetDate(LDir, LLater) <> 0 then
    raise Exception.Create('cannot set the time of the directory ' + LDir);
  if LLookup.Identity = LUnchanged then
    raise Exception.Create('the identity of ' + LDir + ' ignores its time');
  if FileSetDate(LDir, LStamp) <> 0 then
    raise Exception.Create('cannot set the time of the directory ' + LDir);
  ExpectEquals('a directory with its time set back', LUnchanged, LLookup.Identity,
    'the identity holds more than the directory and its time');

  // a change inside the resolution of the file system's time still names another lookup
  LExtra := LDir + PathDelim + 'extra';
  TVectorLocator.WriteDerTo(LExtra, '00');
  if FileSetDate(LDir, LStamp) <> 0 then
    raise Exception.Create('cannot set the time of the directory ' + LDir);
  if LLookup.Identity = LUnchanged then
    raise Exception.Create('the identity of ' + LDir + ' ignores a file added within its time');
  DeleteFile(LExtra);
  if FileSetDate(LDir, LStamp) <> 0 then
    raise Exception.Create('cannot set the time of the directory ' + LDir);
  ExpectEquals('a directory that lost the file again', LUnchanged, LLookup.Identity,
    'the identity holds more than the directory and its entries');

  // a relative spelling keeps naming the directory it named when it was given
  LCurrent := GetCurrentDir;
  LRelative := ExtractRelativePath(IncludeTrailingPathDelimiter(LCurrent), LDir);
  LRelativeLookup := TOpenSslHashedDirLookup.Create(LCrypto, LRelative) as IIssuerLookup;
  if not SetCurrentDir(ABase) then
    raise Exception.Create('cannot change to ' + ABase);
  try
    ExpectEquals('a relative directory after the working directory moved', LUnchanged,
      LRelativeLookup.Identity, 'the identity follows the working directory');
  finally
    SetCurrentDir(LCurrent);
  end;

  // a directory that is not there keeps one identity until it appears
  LAbsent := ABase + PathDelim + 'identityabsent';
  LMissing := TOpenSslHashedDirLookup.Create(LCrypto, LAbsent) as IIssuerLookup;
  LBefore := LMissing.Identity;
  ExpectEquals('a missing directory', LBefore, LMissing.Identity,
    'the identity of a missing directory moves');
  if LBefore = LUnchanged then
    raise Exception.Create('a missing directory shares the identity of one that is there');
  NewDir(ABase, 'identityabsent');
  if LMissing.Identity = LBefore then
    raise Exception.Create('a directory that appeared keeps the identity it had when missing');
end;

class procedure TTrustedCertsDirCheck.Run;
var
  LServer: TVerifyServerThread;
  LHandler: TTestCertificateDataHandler;
  LCrypto: ICryptoProvider;
  LPkix: IPkixProvider;
  LConfig: ITlsClientConfig;
  LBase, LDir, LOther, LHashed, LRootHex, LOtherHex, LRootFile, LEcho, LError: string;
  LRootName, LOtherName, LUpperName: string;
  LFixed: LongInt;
  LSize: Integer;
begin
  LRootHex := TVectorLocator.FieldHex('root_cert');
  LOtherHex := TVectorLocator.FieldHex('root2_cert');
  LRootName := PathDelim + RootHash;
  LOtherName := PathDelim + OtherHash;
  LUpperName := PathDelim + UpperCase(RootHash);
  LBase := IncludeTrailingPathDelimiter(GetTempDir) + 'tlslib_fcl_certsdir_' +
    IntToStr(GetProcessID);
  RemoveTree(LBase);
  LRootFile := NewDir(LBase, 'rootfile') + PathDelim + 'root.der';
  TVectorLocator.WriteDerTo(LRootFile, LRootHex);
  try
    LServer := TVerifyServerThread.Create(
      TDataEncoding.HexDecode(TVectorLocator.FieldHex('leaf_cert')),
      TDataEncoding.HexDecode(TVectorLocator.FieldHex('leaf_key')), CERTS_DIR_PORT);
    try
      LServer.StartListening;
      // the directory is given without a trailing delimiter
      LDir := NewDir(LBase, 'plain');
      TVectorLocator.WritePemTo(LDir + LRootName + '.0', 'CERTIFICATE', [LRootHex]);
      LEcho := Echo(LDir, '', LError);
      ExpectEquals('a root in a hashed file', 'verify', LEcho, LError);

      // only a hashed name is opened, so the root under a plain name is not an anchor
      LDir := NewDir(LBase, 'plainname');
      TVectorLocator.WritePemTo(LDir + PathDelim + 'root.pem', 'CERTIFICATE', [LRootHex]);
      TVectorLocator.WritePemTo(LDir + LOtherName + '.0', 'CERTIFICATE', [LOtherHex]);
      LEcho := Echo(LDir, '', LError);
      ExpectRefused('a root under a plain name', LEcho, LError, UNTRUSTED_CHAIN);

      // a name that is not eight hex digits is no hashed file, whatever the file holds
      LDir := NewDir(LBase, 'nothex');
      TVectorLocator.WriteDerTo(LDir + PathDelim + 'ghijklmn.0', '0001020304');
      TVectorLocator.WritePemTo(LDir + LRootName + '.0', 'CERTIFICATE', [LRootHex]);
      LEcho := Echo(LDir, '', LError);
      ExpectEquals('a root beside a file not named by hex digits', 'verify', LEcho, LError);

      // the numbers must run from 0 without a gap
      LDir := NewDir(LBase, 'gap');
      TVectorLocator.WritePemTo(LDir + LRootName + '.1', 'CERTIFICATE', [LRootHex]);
      LEcho := Echo(LDir, '', LError);
      ExpectRefused('a root after a gap', LEcho, LError, NO_HASHED_FILES);
      LServer.WaitSettled;

      // the number is plain decimal
      LDir := NewDir(LBase, 'zeros');
      TVectorLocator.WritePemTo(LDir + LRootName + '.00', 'CERTIFICATE', [LRootHex]);
      LEcho := Echo(LDir, '', LError);
      ExpectRefused('a root in a file numbered 00', LEcho, LError, NO_HASHED_FILES);
      LServer.WaitSettled;

      // the file system decides whether an uppercase name is the hashed one
      LDir := NewDir(LBase, 'case');
      TVectorLocator.WritePemTo(LDir + LUpperName + '.0', 'CERTIFICATE', [LRootHex]);
      LEcho := Echo(LDir, '', LError);
      if FileExists(LDir + LRootName + '.0') then
        ExpectEquals('a root in an uppercase name the file system folds', 'verify', LEcho, LError)
      else
        ExpectRefused('a root in an uppercase name the file system keeps apart', LEcho, LError,
          NO_HASHED_FILES);
      LServer.WaitSettled;

      // a name the file system does not fold ends the numbers, as a missing file does
      LDir := NewDir(LBase, 'casegap');
      TVectorLocator.WritePemTo(LDir + LUpperName + '.0', 'CERTIFICATE', [LookalikeRootHex]);
      TVectorLocator.WritePemTo(LDir + LRootName + '.1', 'CERTIFICATE', [LRootHex]);
      LEcho := Echo(LDir, '', LError);
      if FileExists(LDir + LRootName + '.0') then
        ExpectEquals('a root after an uppercase name the file system folds', 'verify', LEcho,
          LError)
      else
        ExpectRefused('a root after an uppercase name the file system keeps apart', LEcho,
          LError, NO_HASHED_FILES);
      LServer.WaitSettled;

      // every number of a prefix is probed, not only the first
      LDir := NewDir(LBase, 'second');
      TVectorLocator.WritePemTo(LDir + LRootName + '.0', 'CERTIFICATE', [LookalikeRootHex]);
      TVectorLocator.WritePemTo(LDir + LRootName + '.1', 'CERTIFICATE', [LRootHex]);
      LEcho := Echo(LDir, '', LError);
      ExpectEquals('a root in the second numbered file', 'verify', LEcho, LError);

      // an entry that is not a regular file is skipped and the probe goes on
      LDir := NewDir(LBase, 'slot');
      NewDir(LDir, RootHash + '.0');
      TVectorLocator.WritePemTo(LDir + LRootName + '.1', 'CERTIFICATE', [LRootHex]);
      LEcho := Echo(LDir, '', LError);
      ExpectEquals('a root after a directory in the numbered slot', 'verify', LEcho, LError);

      // a hashed file that is no certificate trusts nothing, and the refusal says it is skipped
      LDir := NewDir(LBase, 'garbage');
      LHashed := LDir + LRootName + '.0';
      TVectorLocator.WriteDerTo(LHashed, '0001020304');
      LEcho := Echo(LDir, '', LError);
      ExpectRefused('a hashed file holding no certificate', LEcho, LError, UNTRUSTED_CHAIN);
      ExpectRefused('the refusal beside a hashed file holding no certificate', LEcho, LError,
        SKIPPED_HINT);
      LServer.WaitSettled;

      LDir := NewDir(LBase, 'empty');
      LEcho := Echo(LDir, '', LError);
      ExpectRefused('an empty directory', LEcho, LError, NO_HASHED_FILES);
      LServer.WaitSettled;

      LEcho := Echo(LDir + PathDelim + 'absent', '', LError);
      ExpectRefused('a missing directory', LEcho, LError, 'which is not a directory');
      LServer.WaitSettled;

      // the separator alone names no directory, and a quote is part of a name
      LEcho := Echo(PathSeparator + PathSeparator, '', LError);
      ExpectRefused('a list of separators', LEcho, LError, 'names no directory');
      LServer.WaitSettled;
      LEcho := Echo('"' + LDir + '"', '', LError);
      ExpectRefused('a quoted directory', LEcho, LError, 'which is not a directory');
      LServer.WaitSettled;

      // an unset directory leaves the other sources alone
      LEcho := Echo('', LRootFile, LError);
      ExpectEquals('a root in CertCA beside an unset directory', 'verify', LEcho, LError);

      // the directory unions with CertCA
      LEcho := Echo(NewDir(LBase, 'union'), LRootFile, LError);
      ExpectRefused('an empty directory beside CertCA', LEcho, LError, NO_HASHED_FILES);
      LServer.WaitSettled;
      LDir := NewDir(LBase, 'unionother');
      TVectorLocator.WritePemTo(LDir + LOtherName + '.0', 'CERTIFICATE', [LOtherHex]);
      LEcho := Echo(LDir, LRootFile, LError);
      ExpectEquals('a root in CertCA beside a directory holding another root', 'verify', LEcho,
        LError);

      // a list takes each directory in turn
      LDir := NewDir(LBase, 'first');
      TVectorLocator.WritePemTo(LDir + LOtherName + '.0', 'CERTIFICATE', [LOtherHex]);
      LOther := NewDir(LBase, 'last');
      TVectorLocator.WritePemTo(LOther + LRootName + '.0', 'CERTIFICATE', [LRootHex]);
      LEcho := Echo(LDir + PathSeparator + LOther, '', LError);
      ExpectEquals('a root in the second directory of a list', 'verify', LEcho, LError);

      // a directory named twice is read once
      LEcho := Echo(LOther + PathSeparator + LOther + PathDelim, '', LError);
      ExpectEquals('a directory named twice', 'verify', LEcho, LError);

      // every directory is searched, so a root that was renewed in the later one still counts
      LDir := NewDir(LBase, 'stale');
      TVectorLocator.WritePemTo(LDir + LRootName + '.0', 'CERTIFICATE', [LookalikeRootHex]);
      LOther := NewDir(LBase, 'renewed');
      TVectorLocator.WritePemTo(LOther + LRootName + '.0', 'CERTIFICATE', [LRootHex]);
      LEcho := Echo(LDir + PathSeparator + LOther, '', LError);
      ExpectEquals('a root renewed in the later directory', 'verify', LEcho, LError);
      LEcho := Echo(LOther + PathSeparator + LDir, '', LError);
      ExpectEquals('a root renewed in the earlier directory', 'verify', LEcho, LError);

      // a file added after a refusal is found by the next connection
      LDir := NewDir(LBase, 'added');
      TVectorLocator.WritePemTo(LDir + LOtherName + '.0', 'CERTIFICATE', [LOtherHex]);
      LEcho := Echo(LDir, '', LError);
      ExpectRefused('a directory before its root is added', LEcho, LError, UNTRUSTED_CHAIN);
      LServer.WaitSettled;
      TVectorLocator.WritePemTo(LDir + LRootName + '.0', 'CERTIFICATE', [LRootHex]);
      LEcho := Echo(LDir, '', LError);
      ExpectEquals('a directory after its root is added', 'verify', LEcho, LError);

      // each connection sees the directory as it is then: a removed file stops being an anchor
      LDir := NewDir(LBase, 'removed');
      LHashed := LDir + LRootName + '.0';
      TVectorLocator.WritePemTo(LDir + LOtherName + '.0', 'CERTIFICATE', [LOtherHex]);
      TVectorLocator.WritePemTo(LHashed, 'CERTIFICATE', [LRootHex]);
      LEcho := Echo(LDir, '', LError);
      ExpectEquals('a root before its file is removed', 'verify', LEcho, LError);
      DeleteFile(LHashed);
      LEcho := Echo(LDir, '', LError);
      ExpectRefused('a root after its file is removed', LEcho, LError, UNTRUSTED_CHAIN);

      // and a file rewritten in place
      LDir := NewDir(LBase, 'rewritten');
      LHashed := LDir + LRootName + '.0';
      TVectorLocator.WritePemTo(LHashed, 'CERTIFICATE', [LRootHex]);
      LEcho := Echo(LDir, '', LError);
      ExpectEquals('a root before its file is rewritten', 'verify', LEcho, LError);
      TVectorLocator.WritePemTo(LHashed, 'CERTIFICATE', [LookalikeRootHex]);
      LEcho := Echo(LDir, '', LError);
      ExpectRefused('a root after its file is rewritten', LEcho, LError, UNTRUSTED_CHAIN);

      // a rewrite that keeps the size and the time is seen too: the contents are what count
      LDir := NewDir(LBase, 'samestamp');
      LHashed := LDir + LRootName + '.0';
      LFixed := DateTimeToFileDate(EncodeDate(2024, 1, 1));
      LSize := TVectorLocator.WritePemTo(LHashed, 'CERTIFICATE', [LRootHex]);
      FileSetDate(LHashed, LFixed);
      LEcho := Echo(LDir, '', LError);
      ExpectEquals('a root before its file is overwritten in place', 'verify', LEcho, LError);
      TVectorLocator.WriteDerTo(LHashed, StringOfChar('0', 2 * LSize));
      FileSetDate(LHashed, LFixed);
      LEcho := Echo(LDir, '', LError);
      ExpectRefused('a file overwritten with the same size and time', LEcho, LError,
        UNTRUSTED_CHAIN);
      LServer.WaitSettled;

      // a directory beside a fully built config is a conflict
      LCrypto := TDefaultCryptoProvider.Create as ICryptoProvider;
      LPkix := TDefaultPkixProvider.Create as IPkixProvider;
      LConfig := TTlsPresets.Compatible(LCrypto, LPkix).Client
        .WithServerVerification(TServerVerification.WebPki(TDataEncoding.HexDecode(LRootHex))
        .Build).Build;
      LHandler := TTestCertificateDataHandler.Create;
      (LHandler.CertificateData as TTestCertificateData).TrustedCertsDir := LOther;
      LHandler.ClientConfig := LConfig;
      LEcho := TVerifyClient.Echo(LHandler, CERTS_DIR_PORT, LError);
      ExpectRefused('a directory beside a ClientConfig', LEcho, LError, 'is set together with');
      LServer.WaitSettled;

      // the conflict is reported before the directory is read
      LHandler := TTestCertificateDataHandler.Create;
      (LHandler.CertificateData as TTestCertificateData).TrustedCertsDir :=
        LBase + PathDelim + 'absent';
      LHandler.ClientConfig := LConfig;
      LEcho := TVerifyClient.Echo(LHandler, CERTS_DIR_PORT, LError);
      ExpectRefused('a missing directory beside a ClientConfig', LEcho, LError,
        'is set together with');
      LServer.WaitSettled;

      RunNaming(LBase, LRootHex, LOtherHex, LServer);
      RunSkipped(LBase, LRootHex, LookalikeRootHex);
      RunLinks(LBase, LRootHex);
      RunPermissions(LBase, LRootHex, LookalikeRootHex);
    finally
      LServer.Terminate;
      LServer.Free;
    end;
    RunIssuers(LBase);
    RunIdentity(LBase);
    RunServerRole(LBase);
  finally
    RemoveTree(LBase);
  end;
end;

class procedure TTrustedCertsDirCheck.RunServerRole(const ABase: string);
var
  LMutual: TMutualServerThread;
  LPlain: TVerifyServerThread;
  LHandler: TTlsLibSocketHandler;
  LPfx: TBytes;
  LRootHex, LRoot, LDir, LEcho, LError: string;
  LAlert: Integer;
begin
  LPfx := TDataEncoding.HexDecode(TVectorLocator.FieldHexFrom('ClientAuthChain.txt', 'leaf_pfx'));
  LRootHex := TVectorLocator.FieldHexFrom('ClientAuthChain.txt', 'root_cert');
  LRoot := NewDir(ABase, 'serverroot') + PathDelim + 'root.der';
  TVectorLocator.WriteDerTo(LRoot, LRootHex);
  LDir := NewDir(ABase, 'clientca');
  TVectorLocator.WritePemTo(LDir + PathDelim + ClientAuthRootHash + '.0', 'CERTIFICATE',
    [LRootHex]);
  // the directory vouches for the clients of a server that requires a certificate
  LMutual := TMutualServerThread.Create(LPfx, LRoot);
  try
    LMutual.CertsDir := LDir;
    LMutual.StartListening;
    LEcho := TMutualTlsCheck.Echo(LPfx, LRoot, True, True, LError, LAlert);
    if LEcho <> 'mutual' then
      raise Exception.Create('a client chained to the root in the server''s directory was not ' +
        'served: ' + LError);
  finally
    LMutual.Terminate;
    LMutual.Free;
  end;

  // a directory that is not there is the server's failure to build, not a served client
  LMutual := TMutualServerThread.Create(LPfx, LRoot);
  try
    LMutual.CertsDir := LDir + PathDelim + 'absent';
    LMutual.StartListening;
    LEcho := TMutualTlsCheck.Echo(LPfx, LRoot, True, True, LError, LAlert);
    if LEcho <> '' then
      raise Exception.Create('a client was served by a server whose directory is missing');
    if LMutual.Attempts <> 1 then
      raise Exception.Create('the client never reached the server whose directory is missing');
  finally
    LMutual.Terminate;
    LMutual.Free;
  end;

  // a server that requests no client certificate never opens the directory
  LPlain := TVerifyServerThread.Create(
    TDataEncoding.HexDecode(TVectorLocator.FieldHex('leaf_cert')),
    TDataEncoding.HexDecode(TVectorLocator.FieldHex('leaf_key')), CERTS_DIR_SERVER_PORT);
  try
    LPlain.CertsDir := LDir + PathDelim + 'absent';
    LPlain.StartListening;
    LRoot := NewDir(ABase, 'plainroot') + PathDelim + 'root.der';
    TVectorLocator.WriteDerTo(LRoot, TVectorLocator.FieldHex('root_cert'));
    LHandler := TTlsLibSocketHandler.Create;
    LHandler.CertificateData.CertCA.FileName := LRoot;
    LEcho := TVerifyClient.Echo(LHandler, CERTS_DIR_SERVER_PORT, LError);
    ExpectEquals('a server with no client authentication and a missing directory', 'verify',
      LEcho, LError);
  finally
    LPlain.Terminate;
    LPlain.Free;
  end;
end;

{ TAlpnCheck }

class function TAlpnCheck.Negotiate(const AServerSlot: string; const AServerList: TArray<string>;
  const AClientSlot: string; const AClientList: TArray<string>;
  AClientConfig: ITlsClientConfig; out ASelected, AError: string; out AAlert: Integer): string;
var
  LServer: TVerifyServerThread;
  LHandler: TTestCertificateDataHandler;
  LSock: TInetSocket;
begin
  Result := '';
  ASelected := '';
  AError := '';
  AAlert := 0;
  LServer := TVerifyServerThread.Create(
    TDataEncoding.HexDecode(TVectorLocator.FieldHex('leaf_cert')),
    TDataEncoding.HexDecode(TVectorLocator.FieldHex('leaf_key')), ALPN_PORT);
  try
    LServer.AlpnSlot := AServerSlot;
    LServer.AlpnList := AServerList;
    LServer.StartListening;
    LHandler := TTestCertificateDataHandler.Create;
    (LHandler.CertificateData as TTestCertificateData).ALPNProtocols := AClientSlot;
    LHandler.AlpnProtocols := AClientList;
    LHandler.ClientConfig := AClientConfig;
    if AClientConfig = nil then
      LHandler.CertificateData.CertCA.FileName := TVectorLocator.WriteDer('alpn_root',
        TVectorLocator.FieldHex('root_cert'));
    LSock := TInetSocket.Create('localhost', ALPN_PORT, LHandler);
    try
      try
        LSock.Connect;
        Result := LHandler.NegotiatedAlpn;
{$IF sslbase.StrDataCount >= 3}
        ASelected := TSSLSocketHandler(LHandler).GetSelectedALPNProtocol;
{$IFEND}
      except
        on E: ESocketError do
        begin
          AError := E.Message + ' ' + LHandler.LastErrorDesc;
{$IF FPC_FULLVERSION >= 30203}
          AAlert := LHandler.LastSSLErrorCode;
{$IFEND}
        end;
      end;
    finally
      LSock.Free;
    end;
  finally
    LServer.Terminate;
    LServer.Free;
  end;
end;

class procedure TAlpnCheck.Run;
var
  LCrypto: ICryptoProvider;
  LPkix: IPkixProvider;
  LConfig: ITlsClientConfig;
  LNegotiated, LSelected, LError: string;
  LAlert: Integer;
begin
  // the server's order decides, so a client listing http/1.1 first still gets h2
  LNegotiated := Negotiate(' h2 , ,http/1.1', nil, '', TArray<string>.Create('http/1.1', 'h2'), nil,
    LSelected, LError, LAlert);
  ExpectEquals('a server slot', 'h2', LNegotiated, LError);
{$IF sslbase.StrDataCount >= 3}
  if LSelected <> 'h2' then
    raise Exception.Create('the base handler type reported "' + LSelected + '", not "h2"');
{$IFEND}

  LNegotiated := Negotiate('h2,http/1.1', nil, 'h2', nil, nil, LSelected, LError, LAlert);
  ExpectEquals('a client slot', 'h2', LNegotiated, LError);

  LNegotiated := Negotiate('h2', nil, ' h2 , http/1.1', TArray<string>.Create('h2', 'http/1.1'),
    nil, LSelected, LError, LAlert);
  ExpectEquals('equal client lists', 'h2', LNegotiated, LError);

  LNegotiated := Negotiate('h2,http/1.1', TArray<string>.Create('h2', 'http/1.1'), '',
    TArray<string>.Create('h2'), nil, LSelected, LError, LAlert);
  ExpectEquals('equal server lists', 'h2', LNegotiated, LError);

  LNegotiated := Negotiate('h2', nil, 'http/1.1', TArray<string>.Create('h2'), nil, LSelected,
    LError, LAlert);
  ExpectRefused('a slot naming another protocol', LNegotiated, LError, 'disagree');

  LNegotiated := Negotiate('h2,http/1.1', nil, 'h2,http/1.1',
    TArray<string>.Create('http/1.1', 'h2'), nil, LSelected, LError, LAlert);
  ExpectRefused('a slot in another order', LNegotiated, LError, 'disagree');

  LNegotiated := Negotiate('h2,http/1.1', nil, 'h2', TArray<string>.Create('h2', 'http/1.1'), nil,
    LSelected, LError, LAlert);
  ExpectRefused('a slot naming fewer protocols', LNegotiated, LError, 'disagree');

  LNegotiated := Negotiate('h2', nil, '', TArray<string>.Create('h3'), nil, LSelected, LError,
    LAlert);
  ExpectRefused('a client offering nothing the server has', LNegotiated, LError,
    'the peer sent a fatal alert');
{$IF FPC_FULLVERSION >= 30203}
  // no_application_protocol (RFC 7301 section 3.2)
  if LAlert <> 120 then
    raise Exception.CreateFmt('a client offering nothing the server has got alert %d, not 120',
      [LAlert]);
{$IFEND}

  LCrypto := TDefaultCryptoProvider.Create as ICryptoProvider;
  LPkix := TDefaultPkixProvider.Create as IPkixProvider;
  LConfig := TTlsPresets.Compatible(LCrypto, LPkix).Client
    .WithServerVerification(TServerVerification.WebPki(
    TDataEncoding.HexDecode(TVectorLocator.FieldHex('root_cert'))).Build).Build;
  LNegotiated := Negotiate('h2', nil, 'h2', nil, LConfig, LSelected, LError, LAlert);
  ExpectRefused('a slot beside a ClientConfig', LNegotiated, LError, 'is set together with');
end;

{ TFclNetLoopbackExample }

class function TFclNetLoopbackExample.VersionText(const AVersion: TTlsVersion): string;
begin
  case AVersion.WireValue of
    TlsWireVersionTls13:
      Result := 'TLSv1.3';
    TlsWireVersionTls12:
      Result := 'TLSv1.2';
  else
    Result := 'unknown';
  end;
end;

class function TFclNetLoopbackExample.Run: Integer;
var
  LServer: TServerThread;
  LSock: TInetSocket;
  LHandler: TTlsLibSocketHandler;
  LRoot, LEcho, LVersion: string;
  LOut: AnsiString;
  LBuf: TBytes;
  LN: Integer;
  LStart: TDateTime;
  LStallMs: Int64;
begin
  Result := 1;
  LEcho := '';
  LVersion := '';
  TVectorLocator.Locate;
  try
    TNameHashCheck.Run(TDefaultCryptoProvider.Create as ICryptoProvider);
    LRoot := TVectorLocator.WriteDer('root', TVectorLocator.FieldHex('root_cert'));

    LServer := TServerThread.Create(TDataEncoding.HexDecode(TVectorLocator.FieldHex('leaf_pfx')));
    try
      LServer.StartListening;

      // the client: 'localhost' resolves to 127.0.0.1 (IPv4) and is also the name we verify the
      // leaf's SAN against; the pinned root is the trust source (fail-closed without one)
      LHandler := TTlsLibSocketHandler.Create;
      LHandler.CertificateData.CertCA.FileName := LRoot; // pinned root (verification is on by default)
      // no SNI on the wire, yet the leaf is still verified for 'localhost' (SendHostAsSNI is wire-only)
      LHandler.SendHostAsSNI := False;
      // the client offers one suite, so a negotiated AES-256 proves the list was honoured
      LHandler.CertificateData.CipherList := 'TLS_AES_256_GCM_SHA384';
      LSock := TInetSocket.Create('localhost', PORT, LHandler); // handler set => no auto-connect
      try
        try
          LSock.Connect; // TCP connect + our TLS handshake
        except
          // TInetSocket raises a generic connect error when our handshake refuses; surface why
          on E: ESocketError do
            raise Exception.Create('handshake failed: ' + LHandler.LastErrorDesc);
        end;
        LVersion := VersionText(LHandler.NegotiatedVersion); // read before LSock.Free drops the handler
        if LHandler.NegotiatedCipherSuite <> TCipherSuites13.Aes256GcmSha384 then
          raise Exception.CreateFmt('the CipherList was not honoured (suite $%.4x)',
            [LHandler.NegotiatedCipherSuite]);
        LOut := AnsiString(PING);
        LSock.Write(LOut[1], System.Length(LOut));
        SetLength(LBuf, 1024);
        LN := LSock.Read(LBuf[0], System.Length(LBuf));
        if LN > 0 then
          SetString(LEcho, PAnsiChar(@LBuf[0]), LN);
        // the server now sends part of a record and stalls: the socket timeout must bound the read
        LSock.IOTimeout := READ_CAP_MS;
        LStart := Now;
        LN := LSock.Read(LBuf[0], System.Length(LBuf));
        LStallMs := MilliSecondsBetween(Now, LStart);
        if (LN >= 0) or (LStallMs > STALL_LIMIT_MS) then
          raise Exception.CreateFmt('a stalled record was not bounded by IOTimeout (%d ms, read %d)',
            [LStallMs, LN]);
      finally
        LSock.Free; // frees the handler, flushes close_notify, closes the socket
      end;

      LServer.WaitFor;
      if LServer.Error <> '' then
        raise Exception.Create(LServer.Error);
      if LServer.PeerServerName <> '' then
        raise Exception.Create('the server saw an SNI though SendHostAsSNI was False: ' +
          LServer.PeerServerName);
      TMutualTlsCheck.Run;
      TMutualTlsCheck.RunHookFault;
      TMutualTlsCheck.RunHookMemoryFault;
      TEarlyCloseCheck.Run;
      TVerifyIgnoredCheck.Run;
      TVerifyHonouredCheck.Run;
      TSelfSignedLeafCheck.Run;
      TTrustedCertsDirCheck.Run;
      TAlpnCheck.Run;
      TBufferedPlaintextCheck.RunPending;
{$IF DECLARED(TSocketStates)}
      TBufferedPlaintextCheck.RunSelect;
      TBufferedPlaintextCheck.RunLargeRecord;
{$IFEND}
      TFailureCheck.RunSendFault;
      TFailureCheck.RunRecvFault;
      TFailureCheck.RunConnectFault;
      TFailureCheck.RunFamilies;
      TTeardownCheck.RunClosed;
      TTeardownCheck.Run;
    finally
      LServer.Terminate;
      LServer.Free;
    end;

    if LEcho = PING then
    begin
      WriteLn('FclNet loopback PASS: ', LVersion, ' handshake + echo + a stalled record bounded in ',
        LStallMs, ' ms + client PFX identity authenticated' +
        ' + a reset VerifyPeerCert still verifies' +
        ' + a hashed certificate directory looked up per verification and only by a verifying role' +
        ' with its name hashes checked against openssl''s' +
        ' + ALPN from the list or the slot' +
        ' + memory faults not hidden, failures recorded by family, and a socket closed under a' +
        ' blocked Recv without freeing the handler beneath it');
      Result := 0;
    end
    else
      WriteLn('FclNet loopback FAIL: echo="', LEcho, '"');
  except
    on E: Exception do
      WriteLn('FclNet loopback FAIL: ', E.ClassName, ': ', E.Message);
  end;
end;

end.
