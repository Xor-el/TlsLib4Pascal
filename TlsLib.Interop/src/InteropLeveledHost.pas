{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit InteropLeveledHost;

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

interface

uses
  SysUtils,
  Math,
  TlpArrayUtilities,
  TlpSecureMemory,
  TlpTlsAlert,
  TlpTlsError,
  TlpISecretBuffer,
  TlpIKeySchedule,
  TlpITlsEngine,
  TlpITlsHandshakeEngine,
  TlpHandshakeOutput,
  InteropSocket,
  InteropUtils;

type
  /// <summary>How one host step ended: a record was handled, the transport ended at a record
  /// boundary, or the exchange failed (Detail says why).</summary>
  TInteropLeveledStatus = (Progressed, Closed, Failed);

  /// <summary>
  /// The host of a handshake-only engine over the reference runner's leveled record framing: each
  /// record is a type byte, a level byte, the cipher suite, a four-byte length and the level's
  /// traffic secret followed by the payload, so both sides check that they agree on the keys. The
  /// host owns the per-level secrets the engine hands out, writes the engine's handshake bytes at
  /// the level it names, feeds the engine what the peer sends at the level it arrived on, and
  /// carries application data. A local failure goes out as an alert record at the latest
  /// handshake or application write level, after any flight the engine produced before it.
  /// </summary>
  TInteropLeveledHost = class sealed(TObject)
  strict private
  type
    TLevelKey = record
      Installed: Boolean;
      Suite: UInt16;
      Secret: TBytes;
      class function From(const ASecret: ITrafficSecret): TLevelKey; static;
    end;
    TLevelKeys = array[TTlsEpoch] of TLevelKey;
    TReceive = (Received, EndOfStream, Truncated);
  var
    FEngine: ITlsHandshakeEngine;
    FSocket: TInteropSocket;
    FIsServer: Boolean;
    FRequireAlpn: Boolean;
    FAcceptVerdict: Boolean;
    FRead: TLevelKeys;
    FWrite: TLevelKeys;
    FAlertLevel: TTlsEpoch;
    FComplete: Boolean;
    FAlpnChecked: Boolean;
    FFlightSent: Boolean;
    FDetail: string;
    procedure WriteRecord(AType: Byte; ALevel: TTlsEpoch; const AData: TBytes);
    function ReceiveExact(ACount: Int32; AAtBoundary: Boolean; out AData: TBytes): TReceive;
    function ReadRecord(out AType: Byte; out ALevel: TTlsEpoch;
      out AData: TBytes): TInteropLeveledStatus;
    procedure SendAlert(AAlertByte: Byte);
    function Collect: TArray<THandshakeOutput>;
    procedure Transmit(const AOutputs: TArray<THandshakeOutput>);
    function EngineFailed(const AOutputs: TArray<THandshakeOutput>): TInteropLeveledStatus;
  public
    /// <summary>ARequireAlpn makes the host abort a connection that settles on no ALPN protocol,
    /// before it transmits what the engine produced at that step; AAcceptVerdict is the answer it
    /// gives when the engine parks on a certificate verdict.</summary>
    constructor Create(const AEngine: ITlsHandshakeEngine; const ASocket: TInteropSocket;
      AIsServer, ARequireAlpn, AAcceptVerdict: Boolean);
    destructor Destroy; override;
    /// <summary>Starts the handshake and sends what the engine produced.</summary>
    procedure Start;
    /// <summary>Writes application data at the application level, or, on a client whose
    /// handshake is not complete, at the early-data level; False when that level has no key
    /// and nothing was written.</summary>
    function WriteApplication(const AData: TBytes): Boolean;
    /// <summary>Handles the next record. AApp receives the payload of an application record.</summary>
    function Pump(out AApp: TBytes): TInteropLeveledStatus;
    property IsComplete: Boolean read FComplete;
    /// <summary>Whether a server has sent its whole first flight, its application write key
    /// included, which is when its half-RTT keying material is available.</summary>
    property FlightSent: Boolean read FFlightSent;
    property Detail: string read FDetail;
  end;

implementation

const
  RecordAlert = 21;
  RecordHandshake = 22;
  RecordApplication = 23;
  MaxRecordLength = 16 * 1024 * 1024;
  ReceiveChunk = 16384;
  NoApplicationProtocolAlert = 120;

resourcestring
  SBadRecordHeader = 'the record header names no known level';
  SKeysNotConfigured = 'a record arrived at a level whose keys are not installed';
  SSuiteMismatch = 'a record carries a cipher suite other than the level''s';
  SRecordTooShort = 'a record is too short to hold the level''s secret';
  SSecretMismatch = 'a record carries a secret other than the level''s';
  SRecordTooLong = 'a record is longer than the host accepts';
  SUnexpectedRecord = 'a record of an unexpected type arrived';
  SEarlyApplicationData = 'application data arrived before the handshake completed';
  SNoApplicationProtocol = 'the handshake settled on no application protocol';
  SPeerAlert = 'the peer sent an alert';
  STransportClosed = 'the transport closed';
  STransportTruncated = 'the transport ended inside a record';

class function TInteropLeveledHost.TLevelKey.From(const ASecret: ITrafficSecret): TLevelKey;
begin
  Result.Installed := True;
  Result.Suite := ASecret.CipherSuite;
  Result.Secret := ASecret.Secret.ToBytes;
end;

constructor TInteropLeveledHost.Create(const AEngine: ITlsHandshakeEngine;
  const ASocket: TInteropSocket; AIsServer, ARequireAlpn, AAcceptVerdict: Boolean);
begin
  inherited Create;
  FEngine := AEngine;
  FSocket := ASocket;
  FIsServer := AIsServer;
  FRequireAlpn := ARequireAlpn;
  FAcceptVerdict := AAcceptVerdict;
  FAlertLevel := TTlsEpoch.Plaintext;
end;

destructor TInteropLeveledHost.Destroy;
var
  LLevel: TTlsEpoch;
begin
  // the secrets are the host's copies: zero them before they go
  for LLevel := System.Low(TTlsEpoch) to System.High(TTlsEpoch) do
  begin
    TSecureMemory.WipeBytes(FRead[LLevel].Secret);
    TSecureMemory.WipeBytes(FWrite[LLevel].Secret);
  end;
  inherited Destroy;
end;

procedure TInteropLeveledHost.WriteRecord(AType: Byte; ALevel: TTlsEpoch; const AData: TBytes);
var
  LKey: TLevelKey;
  LFrame: TBytes;
  LLength: UInt32;
begin
  LKey := FWrite[ALevel];
  LLength := UInt32(System.Length(LKey.Secret) + System.Length(AData));
  LFrame := nil;
  SetLength(LFrame, 8 + System.Length(LKey.Secret) + System.Length(AData));
  LFrame[0] := AType;
  LFrame[1] := Byte(Ord(ALevel));
  LFrame[2] := Byte(LKey.Suite shr 8);
  LFrame[3] := Byte(LKey.Suite);
  LFrame[4] := Byte(LLength shr 24);
  LFrame[5] := Byte(LLength shr 16);
  LFrame[6] := Byte(LLength shr 8);
  LFrame[7] := Byte(LLength);
  if System.Length(LKey.Secret) > 0 then
    System.Move(LKey.Secret[0], LFrame[8], System.Length(LKey.Secret));
  if System.Length(AData) > 0 then
    System.Move(AData[0], LFrame[8 + System.Length(LKey.Secret)], System.Length(AData));
  FSocket.SendAll(LFrame, 0, System.Length(LFrame));
end;

function TInteropLeveledHost.ReceiveExact(ACount: Int32; AAtBoundary: Boolean;
  out AData: TBytes): TReceive;
var
  LChunk: TBytes;
  LGot, LPos: Int32;
begin
  AData := nil;
  SetLength(AData, ACount);
  LChunk := nil;
  SetLength(LChunk, ReceiveChunk);
  LPos := 0;
  Result := TReceive.Received;
  while LPos < ACount do
  begin
    try
      // never ask for more than the record still needs, so the next record stays on the socket
      LGot := FSocket.Recv(LChunk, Min(System.Length(LChunk), ACount - LPos));
    except
      on EInteropSocket do
        LGot := 0;
    end;
    if LGot = 0 then
    begin
      // an end at a record boundary is the peer finishing; anywhere else the record was cut
      if AAtBoundary and (LPos = 0) then
        Exit(TReceive.EndOfStream);
      Exit(TReceive.Truncated);
    end;
    System.Move(LChunk[0], AData[LPos], LGot);
    Inc(LPos, LGot);
  end;
end;

function TInteropLeveledHost.ReadRecord(out AType: Byte; out ALevel: TTlsEpoch;
  out AData: TBytes): TInteropLeveledStatus;
var
  LHeader, LBody, LSecret: TBytes;
  LLength: UInt32;
  LLevelId: Byte;
  LSuite: UInt16;
  LSecretLength: Int32;
  LKey: TLevelKey;
  LReceive: TReceive;
begin
  AData := nil;
  AType := 0;
  ALevel := TTlsEpoch.Plaintext;
  while True do
  begin
    LReceive := ReceiveExact(8, True, LHeader);
    if LReceive <> TReceive.Received then
    begin
      if LReceive = TReceive.EndOfStream then
      begin
        FDetail := STransportClosed;
        Exit(TInteropLeveledStatus.Closed);
      end;
      FDetail := STransportTruncated;
      Exit(TInteropLeveledStatus.Failed);
    end;
    AType := LHeader[0];
    LLevelId := LHeader[1];
    LSuite := UInt16((UInt16(LHeader[2]) shl 8) or LHeader[3]);
    LLength := (UInt32(LHeader[4]) shl 24) or (UInt32(LHeader[5]) shl 16) or
      (UInt32(LHeader[6]) shl 8) or LHeader[7];
    if LLevelId > Ord(System.High(TTlsEpoch)) then
    begin
      FDetail := SBadRecordHeader;
      Exit(TInteropLeveledStatus.Failed);
    end;
    if LLength > MaxRecordLength then
    begin
      FDetail := SRecordTooLong;
      Exit(TInteropLeveledStatus.Failed);
    end;
    ALevel := TTlsEpoch(LLevelId);
    LKey := FRead[ALevel];
    // a level the engine has not keyed: early data means it was refused, so the record is dropped
    if (ALevel <> TTlsEpoch.Plaintext) and (not LKey.Installed) then
    begin
      if ALevel <> TTlsEpoch.EarlyData then
      begin
        FDetail := SKeysNotConfigured;
        Exit(TInteropLeveledStatus.Failed);
      end;
      if ReceiveExact(Int32(LLength), False, LBody) <> TReceive.Received then
      begin
        FDetail := STransportTruncated;
        Exit(TInteropLeveledStatus.Failed);
      end;
      Continue;
    end;
    if LSuite <> LKey.Suite then
    begin
      FDetail := SSuiteMismatch;
      Exit(TInteropLeveledStatus.Failed);
    end;
    LSecretLength := System.Length(LKey.Secret);
    if Int32(LLength) < LSecretLength then
    begin
      FDetail := SRecordTooShort;
      Exit(TInteropLeveledStatus.Failed);
    end;
    if (ReceiveExact(LSecretLength, False, LSecret) <> TReceive.Received) or
      (ReceiveExact(Int32(LLength) - LSecretLength, False, AData) <> TReceive.Received) then
    begin
      FDetail := STransportTruncated;
      Exit(TInteropLeveledStatus.Failed);
    end;
    if not TInteropUtils.BytesEqual(LSecret, LKey.Secret) then
    begin
      FDetail := SSecretMismatch;
      Exit(TInteropLeveledStatus.Failed);
    end;
    Exit(TInteropLeveledStatus.Progressed);
  end;
end;

procedure TInteropLeveledHost.SendAlert(AAlertByte: Byte);
var
  LAlert: TBytes;
begin
  // a fatal alert: level 2, then the description
  LAlert := nil;
  SetLength(LAlert, 2);
  LAlert[0] := 2;
  LAlert[1] := AAlertByte;
  try
    WriteRecord(RecordAlert, FAlertLevel, LAlert);
  except
    // the peer may already be gone, which leaves the alert unsent and the failure unchanged
    on EInteropSocket do
      ;
  end;
end;

function TInteropLeveledHost.Collect: TArray<THandshakeOutput>;
var
  LOutput: THandshakeOutput;
begin
  if FEngine.AwaitingCertificateVerdict then
    FEngine.SetCertificateVerdict(FAcceptVerdict, TTlsAlertDescription.BadCertificate);
  Result := nil;
  while FEngine.NextOutput(LOutput) do
    TArrayUtilities.Append<THandshakeOutput>(Result, LOutput);
end;

procedure TInteropLeveledHost.Transmit(const AOutputs: TArray<THandshakeOutput>);
var
  LOutput: THandshakeOutput;
  LEvent: ITlsEvent;
begin
  for LOutput in AOutputs do
    case LOutput.Kind of
      THandshakeOutputKind.HandshakeData:
        WriteRecord(RecordHandshake, LOutput.Level, LOutput.Data);
      THandshakeOutputKind.ReadSecret:
        FRead[LOutput.Level] := TLevelKey.From(LOutput.Secret);
      THandshakeOutputKind.WriteSecret:
        begin
          FWrite[LOutput.Level] := TLevelKey.From(LOutput.Secret);
          // an early-data key never carries handshake bytes or alerts
          if LOutput.Level <> TTlsEpoch.EarlyData then
            FAlertLevel := LOutput.Level;
          if FIsServer and (LOutput.Level = TTlsEpoch.Application) then
            FFlightSent := True;
        end;
      THandshakeOutputKind.HandshakeComplete:
        FComplete := True;
    end;
  while FEngine.NextEvent(LEvent) do
    // a refused offer takes the early write key with it
    if LEvent.Kind = TTlsEventKind.EarlyDataRejected then
    begin
      TSecureMemory.WipeBytes(FWrite[TTlsEpoch.EarlyData].Secret);
      FWrite[TTlsEpoch.EarlyData] := Default(TLevelKey);
    end;
end;

function TInteropLeveledHost.EngineFailed(
  const AOutputs: TArray<THandshakeOutput>): TInteropLeveledStatus;
var
  LError: TTlsError;
begin
  // the flight the engine produced before it failed goes out first, then the alert
  Transmit(AOutputs);
  LError := FEngine.LastError;
  FDetail := LError.Message;
  // a failure TLS has no alert for is reported to the peer by closing, so nothing is sent
  if LError.Origin = TTlsErrorOrigin.Local then
    SendAlert(LError.AlertByte);
  Result := TInteropLeveledStatus.Failed;
end;

procedure TInteropLeveledHost.Start;
begin
  FEngine.StartHandshake;
  Transmit(Collect);
end;

function TInteropLeveledHost.WriteApplication(const AData: TBytes): Boolean;
var
  LLevel: TTlsEpoch;
begin
  LLevel := TTlsEpoch.Application;
  if (not FIsServer) and (not FComplete) then
    LLevel := TTlsEpoch.EarlyData;
  Result := FWrite[LLevel].Installed;
  if Result then
    WriteRecord(RecordApplication, LLevel, AData);
end;

function TInteropLeveledHost.Pump(out AApp: TBytes): TInteropLeveledStatus;
var
  LType: Byte;
  LLevel: TTlsEpoch;
  LData: TBytes;
  LOutputs: TArray<THandshakeOutput>;
  LOutput: THandshakeOutput;
  LSettled: Boolean;
begin
  AApp := nil;
  Result := ReadRecord(LType, LLevel, LData);
  if Result <> TInteropLeveledStatus.Progressed then
    Exit;
  case LType of
    RecordHandshake:
      begin
        if FEngine.ProvideHandshakeData(LLevel, LData, 0, System.Length(LData)) =
          TTlsOutcome.Fatal then
          Exit(EngineFailed(Collect));
        LOutputs := Collect;
        if FEngine.IsTerminal then
          Exit(EngineFailed(LOutputs));
        // the protocol is settled once a server answers with its handshake keys, and for a client
        // when it answers at the handshake level; it is checked before any of that is transmitted
        LSettled := False;
        for LOutput in LOutputs do
          if (FIsServer and (LOutput.Kind = THandshakeOutputKind.WriteSecret) and
            (LOutput.Level = TTlsEpoch.Handshake)) or
            ((not FIsServer) and ((LOutput.Kind = THandshakeOutputKind.HandshakeComplete) or
            ((LOutput.Kind = THandshakeOutputKind.HandshakeData) and
            (LOutput.Level = TTlsEpoch.Handshake)))) then
            LSettled := True;
        if FRequireAlpn and (not FAlpnChecked) and LSettled then
        begin
          FAlpnChecked := True;
          if System.Length(FEngine.ConnectionInfo.AlpnProtocol) = 0 then
          begin
            FDetail := SNoApplicationProtocol;
            SendAlert(NoApplicationProtocolAlert);
            Exit(TInteropLeveledStatus.Failed);
          end;
        end;
        Transmit(LOutputs);
      end;
    RecordApplication:
      // early data reaches a server before its handshake completes; nothing else does
      if FComplete or (FIsServer and (LLevel = TTlsEpoch.EarlyData)) then
        AApp := LData
      else
      begin
        FDetail := SEarlyApplicationData;
        Result := TInteropLeveledStatus.Failed;
      end;
    RecordAlert:
      begin
        FDetail := SPeerAlert;
        Result := TInteropLeveledStatus.Failed;
      end;
  else
    FDetail := SUnexpectedRecord;
    Result := TInteropLeveledStatus.Failed;
  end;
end;

end.
