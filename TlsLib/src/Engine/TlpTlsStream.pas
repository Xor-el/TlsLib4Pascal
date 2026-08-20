{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpTlsStream;

{$I ..\Include\TlsLib.inc}

interface

uses
  SysUtils,
  Classes,
  TlpTlsLibExceptions,
  TlpTlsConnectionInfo,
  TlpITlsEngine,
  TlpITlsTransport,
  TlpTlsStreamPump;

type
  /// <summary>
  /// The Tier-2 convenience stream: a TStream over an ITlsTransport and a ready ITlsEngine
  /// (built by the caller from a frozen config). It handshakes on first IO (or explicitly),
  /// then Read/Write move application plaintext while the engine and the pump handle the
  /// record layer beneath. It is neutral - no host-library type appears here - so every
  /// adapter reuses it unchanged. The caller owns the engine, the transport, and the
  /// stream; freeing the stream does not close the transport (call CloseNotify first for a
  /// clean shutdown).
  /// </summary>
  TTlsStream = class(TStream)
  strict private
  var
    FTransport: ITlsTransport;
    FEngine: ITlsEngine;
    FIsClient: Boolean;
    FServerName: string;
    FHandshakeDone: Boolean;
    FReadClosed: Boolean;
    FWriteClosed: Boolean;
    FTruncated: Boolean;
    FReadChunk: TBytes;
    FVerdictResolver: TTlsVerdictResolver;
    procedure EnsureHandshake;
  public
    /// <summary>Wraps a ready engine and transport. AIsClient selects who opens the
    /// handshake (a client sends the first flight); AServerName is the host used for SNI /
    /// verification, surfaced back through ConnectionInfo.</summary>
    constructor Create(const ATransport: ITlsTransport; const AEngine: ITlsEngine;
      AIsClient: Boolean; const AServerName: string);

    /// <summary>Sets the out-of-band resolver for a parked peer-certificate verdict, used only
    /// when async certificate verdicts are enabled on the config. It runs after the built-in
    /// pipeline has already accepted the chain and can only additionally reject (augment-only).
    /// Must be set before the handshake; with none set an enabled async verdict fails closed.</summary>
    procedure SetCertificateVerdictResolver(const AResolver: TTlsVerdictResolver);
    /// <summary>Runs the handshake if it has not already run; a no-op afterwards. The first
    /// Read/Write performs it implicitly, so calling this is optional - it lets a caller
    /// front-load the handshake (and its errors) before any application byte.</summary>
    procedure Handshake;
    /// <summary>Whether the handshake has completed successfully.</summary>
    function IsHandshakeComplete: Boolean;
    /// <summary>The negotiated connection info; meaningful only after the handshake.</summary>
    function ConnectionInfo: TTlsConnectionInfo;
    /// <summary>Sends close_notify to shut the write side down cleanly (RFC 8446 6.1);
    /// idempotent. The transport itself is not closed - the caller owns it.</summary>
    procedure CloseNotify;
    /// <summary>Whether the peer closed the transport without a close_notify: a possible
    /// truncation. False after a clean close_notify shutdown.</summary>
    function TransportTruncated: Boolean;
    /// <summary>Decrypted application bytes already buffered and readable without touching
    /// the transport (for a host's ReceivePending / WaitingData).</summary>
    function PendingReadBytes: Int32;

    // TStream
    function Read(var ABuffer; ACount: Longint): Longint; override;
    function Write(const ABuffer; ACount: Longint): Longint; override;
    function Seek(const AOffset: Int64; AOrigin: TSeekOrigin): Int64; override;
  end;

implementation

resourcestring
  SNotSeekable = 'a TLS stream is a sequential conduit and cannot be sought';
  SReadTruncated = 'the transport closed without close_notify (possible truncation)';

{ TTlsStream }

constructor TTlsStream.Create(const ATransport: ITlsTransport;
  const AEngine: ITlsEngine; AIsClient: Boolean; const AServerName: string);
begin
  inherited Create;
  FTransport := ATransport;
  FEngine := AEngine;
  FIsClient := AIsClient;
  FServerName := AServerName;
  FHandshakeDone := False;
  FReadClosed := False;
  FWriteClosed := False;
  FTruncated := False;
end;

procedure TTlsStream.EnsureHandshake;
begin
  if FHandshakeDone then
    Exit;
  // a nil resolver is exactly the inline path; a set one decides a parked async verdict
  TTlsStreamPump.DriveHandshake(FEngine, FTransport, FIsClient, FVerdictResolver);
  FHandshakeDone := True;
end;

procedure TTlsStream.SetCertificateVerdictResolver(
  const AResolver: TTlsVerdictResolver);
begin
  FVerdictResolver := AResolver;
end;

procedure TTlsStream.Handshake;
begin
  EnsureHandshake;
end;

function TTlsStream.IsHandshakeComplete: Boolean;
begin
  Result := FHandshakeDone;
end;

function TTlsStream.ConnectionInfo: TTlsConnectionInfo;
begin
  Result := Default(TTlsConnectionInfo);
  Result.NegotiatedVersion := FEngine.NegotiatedVersion;
  Result.AlpnProtocol := FEngine.NegotiatedAlpnProtocol;
  // the client-side construction host, or (server side, where that is empty) the SNI the
  // client requested, as the handshake resolved it
  Result.ServerName := FServerName;
  if Result.ServerName = '' then
    Result.ServerName := FEngine.PeerServerName;
  Result.PeerOcspStaple := FEngine.PeerOcspStaple;
  Result.PeerCertificates := FEngine.PeerCertificates;
  Result.CipherSuite := FEngine.NegotiatedCipherSuite;
  Result.NamedGroup := FEngine.NegotiatedGroup;
  Result.Resumed := FEngine.IsResumed;
end;

procedure TTlsStream.CloseNotify;
begin
  if FWriteClosed then
    Exit;
  FWriteClosed := True;
  // a close before the handshake even ran has nothing to protect; only shut down a live one
  if FHandshakeDone then
    TTlsStreamPump.Close(FEngine, FTransport);
end;

function TTlsStream.TransportTruncated: Boolean;
begin
  Result := FTruncated;
end;

function TTlsStream.PendingReadBytes: Int32;
begin
  Result := FEngine.PendingAppData;
end;

function TTlsStream.Read(var ABuffer; ACount: Longint): Longint;
var
  LStatus: TTlsReadStatus;
  LGot: Int32;
begin
  if ACount <= 0 then
    Exit(0);
  EnsureHandshake;
  if FReadClosed then
    Exit(0);
  if System.Length(FReadChunk) < ACount then
    SetLength(FReadChunk, ACount);
  LGot := TTlsStreamPump.ReadApp(FEngine, FTransport, FReadChunk, ACount, LStatus);
  case LStatus of
    TTlsReadStatus.Data:
      Move(FReadChunk[0], ABuffer, LGot);
    TTlsReadStatus.CleanEof:
      FReadClosed := True;
    TTlsReadStatus.Truncated:
      begin
        // a stripped close_notify is a truncation, not a graceful EOF
        FReadClosed := True;
        FTruncated := True;
        raise ETlsTransportTruncated.Create(SReadTruncated);
      end;
  end;
  Result := LGot;
end;

function TTlsStream.Write(const ABuffer; ACount: Longint): Longint;
var
  LData: TBytes;
begin
  if ACount <= 0 then
    Exit(0);
  EnsureHandshake;
  LData := nil;
  SetLength(LData, ACount);
  Move(ABuffer, LData[0], ACount);
  TTlsStreamPump.WriteApp(FEngine, FTransport, LData, 0, ACount);
  Result := ACount;
end;

function TTlsStream.Seek(const AOffset: Int64; AOrigin: TSeekOrigin): Int64;
begin
  // tolerate the benign position query some TStream consumers make; refuse real movement
  if (AOffset = 0) and (AOrigin = TSeekOrigin.soCurrent) then
    Exit(0);
  raise ENotSupportedTlsLibException.CreateRes(@SNotSeekable);
end;

end.
