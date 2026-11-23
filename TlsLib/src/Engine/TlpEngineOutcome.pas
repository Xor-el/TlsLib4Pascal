{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpEngineOutcome;

{$I ..\Include\TlsLib.inc}

interface

uses
  SysUtils,
  Generics.Collections,
  TlpTlsAlert,
  TlpTlsError,
  TlpTlsVersion,
  TlpTlsLibExceptions,
  TlpTrustPolicy,
  TlpEchConfig,
  TlpITlsEngine,
  TlpTlsConnectionInfo,
  TlpTlsEngineEvents,
  TlpIHandshakeMachine,
  TlpHandshakeEffect;

type
  /// <summary>
  /// What a handshake reports about itself, shared by the engines: the negotiated facts, the
  /// bounded event queue and the first failure. It takes the facts as data from the driver and
  /// answers with the event or error to surface, so an engine owns only what is particular to
  /// it (its record layer or its output queue). As a sink it serves an engine whose host is told
  /// of every failure rather than sent an alert; the record engine keeps its own failure state and
  /// uses the recording methods directly.
  /// </summary>
  TEngineOutcome = class sealed(TInterfacedObject, IHandshakeSink,
    IHandshakeLocalFailureSink, IHandshakeFailureCauseSink, IHandshakeVersionSink,
    IHandshakeVerdictSink, IHandshakeClientHelloSink, IHandshakeConnectionInfoSink,
    IEchStatusSink)
  strict private
  var
    FFacts: TTlsConnectionInfo;
    // the server name the parked ClientHello offered
    FOfferedServerName: string;
    FEvents: TQueue<ITlsEvent>;
    FTerminal: Boolean;
    FEstablished: Boolean;
    FLastError: TTlsError;
    // the cause the driver reported for the failure OnHandshakeFailed is about to record
    FPendingCause: TTlsErrorCause;
  public
    constructor Create;
    destructor Destroy; override;

    /// <summary>Queues AEvent; past the cap the informational kinds are dropped, while the
    /// terminal ones and a parked verdict or ClientHello (which the handshake cannot resume
    /// without) are kept.</summary>
    procedure Enqueue(const AEvent: ITlsEvent);
    function NextEvent(out AEvent: ITlsEvent): Boolean;
    /// <summary>The queued events, for the owner to count.</summary>
    property Events: TQueue<ITlsEvent> read FEvents;
    /// <summary>The negotiated version as the facts hold it right now, read without a snapshot.</summary>
    property NegotiatedVersion: TTlsVersion read FFacts.NegotiatedVersion;
    /// <summary>Whether early data was accepted; a record engine's server also sets it when it opens
    /// the early-data read window, which the handshake-only server never does, so there it turns
    /// True at the client Finished although the host holds the early read secret from the
    /// ServerHello.</summary>
    property EarlyDataAccepted: Boolean read FFacts.EarlyDataAccepted
      write FFacts.EarlyDataAccepted;
    /// <summary>A snapshot of the facts; the byte arrays are copies, the certificate, path and
    /// authority arrays shared read-only views.</summary>
    function Info: TTlsConnectionInfo;
    /// <summary>Records AError as the failure unless one is already recorded, and ends the
    /// connection.</summary>
    procedure Fail(const AError: TTlsError);
    property IsTerminal: Boolean read FTerminal;
    property IsEstablished: Boolean read FEstablished;
    property LastError: TTlsError read FLastError;
    /// <summary>The server name the ClientHello a server parked at offered.</summary>
    property OfferedServerName: string read FOfferedServerName;

    procedure OnHandshakeEvent(AEvent: TTlsEventKind);
    procedure OnAlpnSelected(const AProtocol: TBytes);
    procedure OnOcspStapleReceived(const AStaple: TBytes);
    procedure OnHandshakeEstablished;
    procedure OnHandshakeFailed(AAlert: TTlsAlertDescription; const AReason: string);
    procedure OnHandshakeFailedWithoutAlert(const AReason: string);
    procedure OnHandshakeFailureCause(ACause: TTlsErrorCause);
    procedure OnVersionNegotiated(const AVersion: TTlsVersion);
    procedure OnCertificateVerdictNeeded(const AChain, AValidatedPath: TArray<TBytes>;
      const AHostName: string; const AStaple: TBytes; APosture: TRevocationPosture);
    procedure OnClientHelloParked(const AServerName: string);
    procedure OnPeerCertificateChain(const AChain, AValidatedPath: TArray<TBytes>);
    procedure OnRequestedCertificateAuthorities(const AAuthorities: TArray<TBytes>;
      const ASchemes: TArray<UInt16>);
    procedure OnPskIdentity(const AIdentity: TBytes);
    procedure OnConnectionParams(ACipherSuite, ANamedGroup: UInt16;
      AResumed, AExtendedMasterSecret: Boolean; const AServerName: string;
      const AFacts: TNegotiationFacts);
    procedure OnEchAccepted;
    procedure OnEchGreased;
    procedure OnEchBackend;
    procedure OnEchServerRejected;
    /// <summary>Records the reject and its retry_configs and ends the connection with
    /// ech_required.</summary>
    procedure OnEchRejected(const ARetryConfigs: TBytes; AIsRetryAttempt: Boolean);
    /// <summary>Records the reject and its retry_configs without ending the connection.</summary>
    procedure RecordEchRejected(const ARetryConfigs: TBytes; AIsRetryAttempt: Boolean);
  end;

implementation

const
  // the most undrained events kept before the informational kinds are dropped: room for a
  // full handshake's worth plus a long run of post-handshake notices, while a caller that never
  // drains cannot grow the queue without bound
  MaxQueuedEvents = Int32(64);

{ TEngineOutcome }

constructor TEngineOutcome.Create;
begin
  inherited Create;
  FEvents := TQueue<ITlsEvent>.Create;
  FFacts.EchStatus := TEchStatus.NotOffered;
  // a zero wire code until an epoch's keys name the negotiated version
  FFacts.NegotiatedVersion := TTlsVersion.Create(0);
  FLastError := TTlsError.CreateFatal(TTlsAlertDescription.InternalError, '');
end;

destructor TEngineOutcome.Destroy;
begin
  FEvents.Free;
  inherited Destroy;
end;

procedure TEngineOutcome.Enqueue(const AEvent: ITlsEvent);
begin
  if (FEvents.Count >= MaxQueuedEvents) and
    not (AEvent.Kind in [TTlsEventKind.PeerAlert, TTlsEventKind.Closed,
    TTlsEventKind.CertificateReceived, TTlsEventKind.ClientHelloReceived]) then
    Exit;
  FEvents.Enqueue(AEvent);
end;

function TEngineOutcome.NextEvent(out AEvent: ITlsEvent): Boolean;
begin
  Result := FEvents.Count > 0;
  if Result then
    AEvent := FEvents.Dequeue
  else
    AEvent := nil;
end;

function TEngineOutcome.Info: TTlsConnectionInfo;
begin
  Result := FFacts;
  // copy retry_configs and the ALPN name so a caller cannot mutate the held bytes (the name
  // also rides a resumption ticket); the certificate, path, CA and staple arrays are shared
  // read-only views, not copies
  Result.EchRetryConfigs := System.Copy(FFacts.EchRetryConfigs);
  Result.AlpnProtocol := System.Copy(FFacts.AlpnProtocol);
  Result.PskIdentity := System.Copy(FFacts.PskIdentity);
end;

procedure TEngineOutcome.Fail(const AError: TTlsError);
begin
  if FTerminal then
    Exit;
  FTerminal := True;
  FLastError := AError;
end;

procedure TEngineOutcome.OnHandshakeEvent(AEvent: TTlsEventKind);
begin
  if AEvent = TTlsEventKind.EarlyDataAccepted then
    FFacts.EarlyDataAccepted := True;
  Enqueue(TTlsEvents.MakeSimple(AEvent));
end;

procedure TEngineOutcome.OnAlpnSelected(const AProtocol: TBytes);
begin
  FFacts.AlpnProtocol := AProtocol;
end;

procedure TEngineOutcome.OnOcspStapleReceived(const AStaple: TBytes);
begin
  FFacts.PeerOcspStaple := AStaple;
end;

procedure TEngineOutcome.OnHandshakeEstablished;
begin
  FEstablished := True;
end;

procedure TEngineOutcome.OnHandshakeFailed(AAlert: TTlsAlertDescription;
  const AReason: string);
begin
  Fail(TTlsError.CreateFatal(AAlert, AReason, TTlsErrorOrigin.Local, FPendingCause));
  FPendingCause := TTlsErrorCause.Unspecified;
end;

procedure TEngineOutcome.OnHandshakeFailureCause(ACause: TTlsErrorCause);
begin
  FPendingCause := ACause;
end;

procedure TEngineOutcome.OnHandshakeFailedWithoutAlert(const AReason: string);
begin
  Fail(TTlsError.CreateFatal(TTlsAlertDescription.InternalError, AReason,
    TTlsErrorOrigin.LocalWithoutAlert));
end;

procedure TEngineOutcome.OnVersionNegotiated(const AVersion: TTlsVersion);
begin
  FFacts.NegotiatedVersion := AVersion;
end;

procedure TEngineOutcome.OnCertificateVerdictNeeded(const AChain,
  AValidatedPath: TArray<TBytes>; const AHostName: string; const AStaple: TBytes;
  APosture: TRevocationPosture);
begin
  // the built-in pipeline has already accepted this chain; surface it so a host can decide
  // out-of-band (augment-only)
  Enqueue(TTlsEvents.MakeCertificateReceived(AChain, AValidatedPath, AHostName, AStaple,
    APosture));
end;

procedure TEngineOutcome.OnClientHelloParked(const AServerName: string);
begin
  FOfferedServerName := AServerName;
  Enqueue(TTlsEvents.MakeSimple(TTlsEventKind.ClientHelloReceived));
end;

procedure TEngineOutcome.OnPeerCertificateChain(const AChain,
  AValidatedPath: TArray<TBytes>);
begin
  FFacts.PeerCertificates := AChain;
  FFacts.ValidatedPath := AValidatedPath;
end;

procedure TEngineOutcome.OnRequestedCertificateAuthorities(
  const AAuthorities: TArray<TBytes>; const ASchemes: TArray<UInt16>);
begin
  FFacts.RequestedCertificateAuthorities := AAuthorities;
  FFacts.RequestedSignatureSchemes := ASchemes;
end;

procedure TEngineOutcome.OnPskIdentity(const AIdentity: TBytes);
begin
  FFacts.PskIdentity := AIdentity;
end;

procedure TEngineOutcome.OnConnectionParams(ACipherSuite, ANamedGroup: UInt16;
  AResumed, AExtendedMasterSecret: Boolean; const AServerName: string;
  const AFacts: TNegotiationFacts);
begin
  FFacts.PeerSignatureScheme := AFacts.PeerSignatureScheme;
  FFacts.HelloRetryRequest := AFacts.HelloRetryRequest;
  FFacts.EarlyDataReason := AFacts.EarlyDataReason;
  // both engines learn an accept here, whichever way each opens its early-data window
  if AFacts.EarlyDataReason = TEarlyDataReason.Accepted then
    FFacts.EarlyDataAccepted := True;
  FFacts.TicketAgeSkew := AFacts.TicketAgeSkew;
  FFacts.CipherSuite := ACipherSuite;
  FFacts.NamedGroup := ANamedGroup;
  FFacts.ServerName := AServerName;
  FFacts.Resumed := AResumed;
  FFacts.ExtendedMasterSecret := AExtendedMasterSecret;
end;

procedure TEngineOutcome.OnEchAccepted;
begin
  FFacts.EchStatus := TEchStatus.Accepted;
end;

procedure TEngineOutcome.OnEchGreased;
begin
  FFacts.EchStatus := TEchStatus.Greased;
end;

procedure TEngineOutcome.OnEchBackend;
begin
  FFacts.EchStatus := TEchStatus.Backend;
end;

procedure TEngineOutcome.OnEchServerRejected;
begin
  // the server rejected ECH and completed to the public_name; record it, do not abort
  FFacts.EchStatus := TEchStatus.Rejected;
end;

procedure TEngineOutcome.RecordEchRejected(const ARetryConfigs: TBytes;
  AIsRetryAttempt: Boolean);
begin
  // the abort with ech_required follows and is never a plaintext fall-back
  FFacts.EchStatus := TEchStatus.Rejected;
  FFacts.EchRetryConfigs := ARetryConfigs;
  FFacts.EchIsRetryAttempt := AIsRetryAttempt;
  FFacts.EchRejectAborted := True;
end;

procedure TEngineOutcome.OnEchRejected(const ARetryConfigs: TBytes;
  AIsRetryAttempt: Boolean);
begin
  RecordEchRejected(ARetryConfigs, AIsRetryAttempt);
  Fail(TTlsError.CreateFatal(TTlsAlertDescription.EchRequired, SEchRejected,
    TTlsErrorOrigin.Local));
end;

end.
