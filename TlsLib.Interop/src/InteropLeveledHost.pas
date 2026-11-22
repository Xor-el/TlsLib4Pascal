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
  TlpTlsAlert,
  TlpTlsError,
  TlpISecretBuffer,
  TlpIKeySchedule,
  TlpITlsEngine,
  TlpITlsHandshakeEngine,
  TlpHandshakeOutput,
  InteropSocket,
  InteropUtils;

const
  LeveledRecordAlert = 21;
  LeveledRecordHandshake = 22;
  LeveledRecordApplication = 23;

type
  /// <summary>How one host step ended: a record was handled, the transport ended, or the
  /// exchange failed (Detail says why).</summary>
  TInteropLeveledStatus = (Progressed, Closed, Failed);

  /// <summary>
  /// The host of a handshake-only engine over the reference runner's leveled record framing: each
  /// record is a type byte, a level byte, the cipher suite, a four-byte length and the level's
  /// traffic secret followed by the payload, so both sides check that they agree on the keys. The
  /// host owns the per-level secrets the engine hands out, writes the engine's handshake bytes at
  /// the level it names, feeds the engine what the peer sends at the level it arrived on, and
  /// carries application data. A local failure goes out as an alert record at the latest
  /// handshake or application write level.
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
    FServerAnswered: Boolean;
    FDetail: string;
    procedure WriteRecord(AType: Byte; ALevel: TTlsEpoch; const AData: TBytes);
    function ReceiveExact(ACount: Int32; out AData: TBytes): Boolean;
    function ReadRecord(out AType: Byte; out ALevel: TTlsEpoch;
      out AData: TBytes): TInteropLeveledStatus;
    procedure SendAlert(AAlertByte: Byte);
    function EngineFailed: TInteropLeveledStatus;
    function MissingAlpn: TInteropLeveledStatus;
    procedure Drain;
  public
    /// <summary>ARequireAlpn makes the host abort a connection that settles on no ALPN protocol;
    /// AAcceptVerdict is the answer it gives when the engine parks on a certificate verdict.</summary>
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
    property Detail: string read FDetail;
  end;

implementation

const
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
  LI: Int32;
begin
  // the secrets are the host's copies: zero them before they go
  for LLevel := System.Low(TTlsEpoch) to System.High(TTlsEpoch) do
  begin
    for LI := 0 to System.High(FRead[LLevel].Secret) do
      FRead[LLevel].Secret[LI] := 0;
    for LI := 0 to System.High(FWrite[LLevel].Secret) do
      FWrite[LLevel].Secret[LI] := 0;
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

function TInteropLeveledHost.ReceiveExact(ACount: Int32; out AData: TBytes): Boolean;
var
  LChunk: TBytes;
  LGot, LPos: Int32;
begin
  AData := nil;
  SetLength(AData, ACount);
  LChunk := nil;
  SetLength(LChunk, ReceiveChunk);
  LPos := 0;
  Result := True;
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
      Exit(False);
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
begin
  AData := nil;
  AType := 0;
  ALevel := TTlsEpoch.Plaintext;
  while True do
  begin
    if not ReceiveExact(8, LHeader) then
      Exit(TInteropLeveledStatus.Closed);
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
      if not ReceiveExact(Int32(LLength), LBody) then
        Exit(TInteropLeveledStatus.Closed);
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
    if not ReceiveExact(LSecretLength, LSecret) then
      Exit(TInteropLeveledStatus.Closed);
    if not TInteropUtils.BytesEqual(LSecret, LKey.Secret) then
    begin
      FDetail := SSecretMismatch;
      Exit(TInteropLeveledStatus.Failed);
    end;
    if not ReceiveExact(Int32(LLength) - LSecretLength, AData) then
      Exit(TInteropLeveledStatus.Closed);
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
    WriteRecord(LeveledRecordAlert, FAlertLevel, LAlert);
  except
    // the peer may already be gone, which leaves the alert unsent and the failure unchanged
    on EInteropSocket do
      ;
  end;
end;

function TInteropLeveledHost.EngineFailed: TInteropLeveledStatus;
var
  LError: TTlsError;
begin
  LError := FEngine.LastError;
  FDetail := LError.Message;
  // a failure TLS has no alert for is reported to the peer by closing, so nothing is sent
  if LError.Origin = TTlsErrorOrigin.Local then
    SendAlert(LError.AlertByte);
  Result := TInteropLeveledStatus.Failed;
end;

function TInteropLeveledHost.MissingAlpn: TInteropLeveledStatus;
begin
  FDetail := SNoApplicationProtocol;
  SendAlert(NoApplicationProtocolAlert);
  Result := TInteropLeveledStatus.Failed;
end;

procedure TInteropLeveledHost.Drain;
var
  LOutput: THandshakeOutput;
  LEvent: ITlsEvent;
begin
  if FEngine.AwaitingCertificateVerdict then
    FEngine.SetCertificateVerdict(FAcceptVerdict, TTlsAlertDescription.BadCertificate);
  while FEngine.NextOutput(LOutput) do
    case LOutput.Kind of
      THandshakeOutputKind.HandshakeData:
        WriteRecord(LeveledRecordHandshake, LOutput.Level, LOutput.Data);
      THandshakeOutputKind.ReadSecret:
        FRead[LOutput.Level] := TLevelKey.From(LOutput.Secret);
      THandshakeOutputKind.WriteSecret:
        begin
          FWrite[LOutput.Level] := TLevelKey.From(LOutput.Secret);
          // an early-data key never carries handshake bytes or alerts
          if LOutput.Level <> TTlsEpoch.EarlyData then
            FAlertLevel := LOutput.Level;
          if FIsServer and (LOutput.Level = TTlsEpoch.Handshake) then
            FServerAnswered := True;
        end;
      THandshakeOutputKind.HandshakeComplete:
        FComplete := True;
    end;
  while FEngine.NextEvent(LEvent) do
    // a refused offer takes the early write key with it
    if LEvent.Kind = TTlsEventKind.EarlyDataRejected then
      FWrite[TTlsEpoch.EarlyData] := Default(TLevelKey);
end;

procedure TInteropLeveledHost.Start;
begin
  FEngine.StartHandshake;
  Drain;
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
    WriteRecord(LeveledRecordApplication, LLevel, AData);
end;

function TInteropLeveledHost.Pump(out AApp: TBytes): TInteropLeveledStatus;
var
  LType: Byte;
  LLevel: TTlsEpoch;
  LData: TBytes;
  LOutcome: TTlsOutcome;
begin
  AApp := nil;
  Result := ReadRecord(LType, LLevel, LData);
  if Result <> TInteropLeveledStatus.Progressed then
    Exit;
  case LType of
    LeveledRecordHandshake:
      begin
        LOutcome := FEngine.ProvideHandshakeData(LLevel, LData, 0, System.Length(LData));
        if LOutcome = TTlsOutcome.Fatal then
          Exit(EngineFailed);
        Drain;
        if FEngine.IsTerminal then
          Exit(EngineFailed);
        // the protocol is settled once a server has answered with its handshake keys, and for a
        // client when the handshake completes
        if FRequireAlpn and (not FAlpnChecked) and (FServerAnswered or FComplete) then
        begin
          FAlpnChecked := True;
          if System.Length(FEngine.ConnectionInfo.AlpnProtocol) = 0 then
            Exit(MissingAlpn);
        end;
      end;
    LeveledRecordApplication:
      // early data reaches a server before its handshake completes; nothing else does
      if FComplete or (FIsServer and (LLevel = TTlsEpoch.EarlyData)) then
        AApp := LData
      else
      begin
        FDetail := SEarlyApplicationData;
        Result := TInteropLeveledStatus.Failed;
      end;
    LeveledRecordAlert:
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
