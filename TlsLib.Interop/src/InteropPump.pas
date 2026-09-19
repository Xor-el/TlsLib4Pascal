{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit InteropPump;

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

interface

uses
  SysUtils,
  TlpTlsAlert,
  TlpTlsAlertProtocol,
  TlpTrustPolicy,
  TlpITlsEngine,
  InteropSocket,
  InteropUtils;

const
  // one TLS record's plaintext never exceeds 2^14; a 16 KiB transport read comfortably
  // holds a framed record and lets the record layer reassemble across reads
  TransportChunk = 16384;
  // BoGo's application echo flips every plaintext byte; also used for the server's 0.5-RTT
  // early-data echo interleaved into the handshake
  EchoXorMask = $FF;

type
  /// <summary>How a pump step ended.</summary>
  TInteropStatus = (
    Ok,            // progressed; for AppData, Data holds this step's plaintext
    PeerClosed,    // peer sent close_notify (a clean shutdown)
    LocalAlert,    // our engine aborted; Alert carries what it sent
    PeerAlert,     // the peer sent a fatal alert; Alert carries it
    TransportEof); // the socket closed with the exchange unfinished

  /// <summary>The outcome of a pump step, with any alert and decrypted bytes.</summary>
  TInteropResult = record
    Status: TInteropStatus;
    Alert: TTlsAlertDescription;
    HasAlert: Boolean;
    Detail: string;
    Data: TBytes;
  end;

  /// <summary>
  /// Drives a sans-IO ITlsEngine over a blocking TInteropSocket: flush outbound,
  /// read inbound, repeat. It is the Tls13LoopbackTests pump with a socket in place
  /// of the peer engine. Mode-specific application exchange (the BoGo XOR echo, a
  /// plain request/echo) is composed on top from these primitives.
  /// </summary>
  TInteropPump = class sealed(TObject)
  strict private
    class function ResultOf(AStatus: TInteropStatus;
      const ADetail: string): TInteropResult; static;
    class function DrainEvents(const AEngine: ITlsEngine;
      var AResult: TInteropResult;
      out ACertEvent: ICertificateReceivedEvent): Boolean; static;
    class procedure ResolveVerdict(const AEngine: ITlsEngine;
      const ASocket: TInteropSocket; AAcceptVerdict: Boolean;
      const AResolver: TCertificateVerdictResolver;
      const ACertEvent: ICertificateReceivedEvent); static;
    class function DriveHandshakeCore(const AEngine: ITlsEngine;
      const ASocket: TInteropSocket; AAcceptVerdict, AHalfRttEcho: Boolean;
      const AResolver: TCertificateVerdictResolver): TInteropResult; static;
    class function ReadAppData(const AEngine: ITlsEngine): TBytes; static;
    class procedure EchoAvailable(const AEngine: ITlsEngine;
      const ASocket: TInteropSocket); static;
  public
    /// <summary>Sends every pending outbound byte to the socket.</summary>
    class procedure Flush(const AEngine: ITlsEngine;
      const ASocket: TInteropSocket); static;
    /// <summary>Runs the handshake to completion (Ok) or to a fatal/EOF result. When the engine
    /// parks on an async certificate verdict (config opt-in), it is resolved out-of-band with
    /// AAcceptVerdict - True continues, False rejects and aborts (fail-closed). With AHalfRttEcho
    /// (a server that accepted 0-RTT), the client's early application data is echoed as 0.5-RTT
    /// data the moment it surfaces mid-handshake, before the next Recv - the peer waits for that
    /// half-RTT response before it sends EndOfEarlyData, so deferring the echo would deadlock.</summary>
    class function DriveHandshake(const AEngine: ITlsEngine;
      const ASocket: TInteropSocket; AAcceptVerdict: Boolean = True;
      AHalfRttEcho: Boolean = False): TInteropResult; overload; static;
    /// <summary>As DriveHandshake, but resolves a parked verdict through AResolver (the peer chain
    /// + host + staple from the park event), so an OS-native live-revocation resolver decides it.
    /// A nil resolver fails the park closed.</summary>
    class function DriveHandshake(const AEngine: ITlsEngine;
      const ASocket: TInteropSocket;
      const AResolver: TCertificateVerdictResolver): TInteropResult; overload; static;
    /// <summary>One read/decrypt cycle; Data carries any plaintext produced.</summary>
    class function PumpAppData(const AEngine: ITlsEngine;
      const ASocket: TInteropSocket): TInteropResult; static;
    /// <summary>Encrypts and sends application data.</summary>
    class procedure WriteAppData(const AEngine: ITlsEngine;
      const ASocket: TInteropSocket; const AData: TBytes); static;
    /// <summary>Sends close_notify and flushes it.</summary>
    class procedure Close(const AEngine: ITlsEngine;
      const ASocket: TInteropSocket); static;
  end;

implementation

{ TInteropPump }

class function TInteropPump.ResultOf(AStatus: TInteropStatus;
  const ADetail: string): TInteropResult;
begin
  Result := Default(TInteropResult);
  Result.Status := AStatus;
  Result.Detail := ADetail;
end;

class procedure TInteropPump.Flush(const AEngine: ITlsEngine;
  const ASocket: TInteropSocket);
var
  LBuf: TBytes;
  LGot: Int32;
begin
  LBuf := nil;
  SetLength(LBuf, TransportChunk);
  repeat
    LGot := AEngine.TakeOutgoing(LBuf, 0);
    if LGot > 0 then
      ASocket.SendAll(LBuf, 0, LGot);
  until LGot = 0;
end;

class function TInteropPump.ReadAppData(const AEngine: ITlsEngine): TBytes;
var
  LBuf: TBytes;
  LGot: Int32;
begin
  Result := nil;
  LBuf := nil;
  SetLength(LBuf, TransportChunk);
  repeat
    LGot := AEngine.ReadAppData(LBuf, 0, TransportChunk);
    if LGot > 0 then
      Result := TInteropUtils.Concat(Result, System.Copy(LBuf, 0, LGot));
  until LGot = 0;
end;

class procedure TInteropPump.EchoAvailable(const AEngine: ITlsEngine;
  const ASocket: TInteropSocket);
var
  LData: TBytes;
  LI: Int32;
begin
  // read whatever plaintext has surfaced (0.5-RTT early data), flip every byte, and write it
  // straight back under the current write epoch (the server's application keys)
  LData := ReadAppData(AEngine);
  if System.Length(LData) = 0 then
    Exit;
  for LI := 0 to System.High(LData) do
    LData[LI] := LData[LI] xor EchoXorMask;
  WriteAppData(AEngine, ASocket, LData);
end;

class function TInteropPump.DrainEvents(const AEngine: ITlsEngine;
  var AResult: TInteropResult;
  out ACertEvent: ICertificateReceivedEvent): Boolean;
var
  LEvent: ITlsEvent;
  LAlertEvent: IPeerAlertEvent;
  LCertEvent: ICertificateReceivedEvent;
begin
  // reports the first terminal event (peer alert / close_notify); returns True then. Also
  // captures a parked-certificate event so a resolver can decide the verdict on the peer chain
  Result := False;
  ACertEvent := nil;
  while AEngine.NextEvent(LEvent) do
  begin
    case LEvent.Kind of
      TTlsEventKind.PeerAlert:
        if Supports(LEvent, IPeerAlertEvent, LAlertEvent) then
        begin
          AResult := ResultOf(TInteropStatus.PeerAlert, 'peer sent a fatal alert');
          AResult.HasAlert := LAlertEvent.Alert.HasKnownDescription;
          if AResult.HasAlert then
            AResult.Alert := LAlertEvent.Alert.Description;
          Exit(True);
        end;
      TTlsEventKind.Closed:
        begin
          AResult := ResultOf(TInteropStatus.PeerClosed, 'peer closed');
          Exit(True);
        end;
      TTlsEventKind.CertificateReceived:
        if Supports(LEvent, ICertificateReceivedEvent, LCertEvent) then
          ACertEvent := LCertEvent;
    end;
  end;
end;

class procedure TInteropPump.ResolveVerdict(const AEngine: ITlsEngine;
  const ASocket: TInteropSocket; AAcceptVerdict: Boolean;
  const AResolver: TCertificateVerdictResolver;
  const ACertEvent: ICertificateReceivedEvent);
var
  LAccept: Boolean;
  LAlert: TTlsAlertDescription;
  LCtx: TCertificateVerdictContext;
begin
  if Assigned(AResolver) then
  begin
    // fail-closed when the park carried no chain; else the resolver decides on it
    LAccept := False;
    LAlert := TTlsAlertDescription.CertificateUnknown;
    if ACertEvent <> nil then
    begin
      LCtx.Chain := ACertEvent.Chain;
      LCtx.HostName := ACertEvent.HostName;
      LCtx.OcspStaple := ACertEvent.OcspStaple;
      LAccept := AResolver(LCtx, LAlert);
    end;
    AEngine.SetCertificateVerdict(LAccept, LAlert);
  end
  else
    AEngine.SetCertificateVerdict(AAcceptVerdict);
end;

class function TInteropPump.DriveHandshake(const AEngine: ITlsEngine;
  const ASocket: TInteropSocket; AAcceptVerdict: Boolean;
  AHalfRttEcho: Boolean): TInteropResult;
begin
  Result := DriveHandshakeCore(AEngine, ASocket, AAcceptVerdict, AHalfRttEcho, nil);
end;

class function TInteropPump.DriveHandshake(const AEngine: ITlsEngine;
  const ASocket: TInteropSocket;
  const AResolver: TCertificateVerdictResolver): TInteropResult;
begin
  Result := DriveHandshakeCore(AEngine, ASocket, True, False, AResolver);
end;

class function TInteropPump.DriveHandshakeCore(const AEngine: ITlsEngine;
  const ASocket: TInteropSocket; AAcceptVerdict, AHalfRttEcho: Boolean;
  const AResolver: TCertificateVerdictResolver): TInteropResult;
var
  LBuf: TBytes;
  LGot: Int32;
  LOutcome: TTlsOutcome;
  LCertEvent: ICertificateReceivedEvent;

  function ReportFatal: TInteropResult;
  begin
    Result := ResultOf(TInteropStatus.LocalAlert, AEngine.LastError.Message);
    Result.HasAlert := True;
    Result.Alert := AEngine.LastError.Alert.Description;
  end;

begin
  LBuf := nil;
  SetLength(LBuf, TransportChunk);
  LCertEvent := nil;
  // flush the client's opening flight (the caller already called StartHandshake); a
  // server has nothing to send until it reads the ClientHello
  Flush(AEngine, ASocket);
  while AEngine.IsHandshaking do
  begin
    LGot := ASocket.Recv(LBuf, TransportChunk);
    if LGot = 0 then
      Exit(ResultOf(TInteropStatus.TransportEof, 'peer closed during handshake'));
    LOutcome := AEngine.ProcessInput(LBuf, 0, LGot);
    Flush(AEngine, ASocket);
    // a server that accepted 0-RTT echoes the client's early data as 0.5-RTT now (before the
    // next blocking Recv), so the peer receives it and proceeds to send EndOfEarlyData
    if AHalfRttEcho and AEngine.IsHandshaking and (AEngine.PendingAppData > 0) then
      EchoAvailable(AEngine, ASocket);
    // surface a peer close_notify / fatal alert only while the handshake is still in progress;
    // once the completing flight has installed, a close_notify coalesced with it belongs to the
    // application phase and is left queued for the caller (its IsInboundClosed / PendingAppData
    // reflect it), not reported here as a handshake failure. The parked-certificate event is
    // captured here so the resolver can decide on the peer chain.
    if AEngine.IsHandshaking and DrainEvents(AEngine, Result, LCertEvent) then
      Exit;
    if LOutcome = TTlsOutcome.Fatal then
      Exit(ReportFatal);
    // an async verdict parks the handshake after the pipeline accepts the peer chain; resolve
    // it out-of-band so the flight can complete (a reject makes the engine terminal). Resolving
    // before the next Recv is required - a parked engine sends nothing, so the peer sends nothing
    if AEngine.AwaitingCertificateVerdict then
    begin
      ResolveVerdict(AEngine, ASocket, AAcceptVerdict, AResolver, LCertEvent);
      LCertEvent := nil;
      Flush(AEngine, ASocket);
      if AEngine.IsTerminal then
        Exit(ReportFatal);
    end;
  end;
  Result := ResultOf(TInteropStatus.Ok, 'handshake complete');
end;

class function TInteropPump.PumpAppData(const AEngine: ITlsEngine;
  const ASocket: TInteropSocket): TInteropResult;
var
  LBuf: TBytes;
  LGot: Int32;
  LOutcome: TTlsOutcome;
  LCertEvent: ICertificateReceivedEvent; // unused post-handshake; a verdict parks only mid-handshake
begin
  // application data can arrive coalesced with the peer's final handshake flight in
  // one segment and sit framed in the engine after the handshake; surface anything
  // already buffered before blocking on the socket, or we would wait for bytes that
  // have already been received
  Result := ResultOf(TInteropStatus.Ok, '');
  Result.Data := ReadAppData(AEngine);
  DrainEvents(AEngine, Result, LCertEvent);
  if (System.Length(Result.Data) > 0) or (Result.Status <> TInteropStatus.Ok) then
    Exit;

  LBuf := nil;
  SetLength(LBuf, TransportChunk);
  LGot := ASocket.Recv(LBuf, TransportChunk);
  if LGot = 0 then
    Exit(ResultOf(TInteropStatus.TransportEof, 'peer closed the transport'));
  LOutcome := AEngine.ProcessInput(LBuf, 0, LGot);
  if LOutcome = TTlsOutcome.Fatal then
  begin
    // send the queued alert to the peer before reporting (as DriveHandshake does); the
    // engine has framed the alert record but the shim must flush it, else the peer sees EOF
    Flush(AEngine, ASocket);
    Result := ResultOf(TInteropStatus.LocalAlert, AEngine.LastError.Message);
    Result.HasAlert := True;
    Result.Alert := AEngine.LastError.Alert.Description;
    Exit;
  end;
  // carry any plaintext produced this cycle, even alongside a terminal event
  Result := ResultOf(TInteropStatus.Ok, '');
  Result.Data := ReadAppData(AEngine);
  DrainEvents(AEngine, Result, LCertEvent);
end;

class procedure TInteropPump.WriteAppData(const AEngine: ITlsEngine;
  const ASocket: TInteropSocket; const AData: TBytes);
begin
  AEngine.Write(AData, 0, System.Length(AData));
  Flush(AEngine, ASocket);
end;

class procedure TInteropPump.Close(const AEngine: ITlsEngine;
  const ASocket: TInteropSocket);
begin
  AEngine.SendClose;
  Flush(AEngine, ASocket);
  ASocket.ShutdownWrite;
end;

end.
