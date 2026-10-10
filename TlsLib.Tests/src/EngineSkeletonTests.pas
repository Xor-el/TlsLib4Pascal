{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit EngineSkeletonTests;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  SysUtils,
{$IFDEF FPC}
  fpcunit,
  testregistry,
{$ELSE}
  TestFramework,
{$ENDIF FPC}
  TlpTlsAlert,
  TlpTlsError,
  TlpTlsLibExceptions,
  TlpTlsContentType,
  TlpTlsVersion,
  TlpEchConfig,
  TlpTlsConnectionInfo,
  TlpRecordLayer,
  TlpTlsPresets,
  TlpTlsEngineFactory,
  TlpITlsEngine,
  TlpIHandshakeMachine,
  TlsLibTestBase;

type
  TTestEngineSkeleton = class(TTlsLibAlgorithmTestCase)
  private
    function NewEngine: ITlsEngine;
    function TakeAll(const AEngine: ITlsEngine): TBytes;
    function PeerRecord(AContentType: TTlsContentType; const AData: TBytes): TBytes;
  published
    procedure TestEngineDoesNotExposeInstallerSeam;
    procedure TestFatalPreQueuesAlertAndTerminal;
    procedure TestWantsReadWantsWriteReflectState;
    procedure TestCleartextApplicationDataBeforeKeysIsFatal;
    procedure TestWriteBeforeWriteEpochIsRefused;
    procedure TestZeroLengthWriteBeforeEpochIsRefused;
    procedure TestOutOfRangeSliceRaisesWithoutTerminating;
    procedure TestAlertBetweenHandshakeFragmentsIsUnexpected;
    procedure TestReceivedCloseNotifyBeforeHandshakeCompletesIsTerminal;
    procedure TestCloseNotifyWithBogusAlertLevelIsIllegalParameter;
    procedure TestOutOfRangeWriteSliceRaisesWithoutTerminating;
    procedure TestReceivedFatalAlertIsTerminal;
    procedure TestReceivedUnknownFatalAlertIsPeerOrigin;
    procedure TestLastErrorOriginIsUnknownBeforeAnyFailure;
    procedure TestSendAlertMarksLocalOrigin;
    procedure TestConnectionInfoZeroStateBeforeHandshake;
  end;

implementation

{ TTestEngineSkeleton }

function TTestEngineSkeleton.NewEngine: ITlsEngine;
begin
  // a client engine before StartHandshake: it frames records and processes plaintext
  // alerts without needing a live peer. A real single-root store satisfies the builder's
  // trust check for a handshake that is never completed here.
  Result := TTlsEngineFactory.CreateClientEngine(
    TTlsPresets.Compatible(Crypto, Pkix).Client
    .WithTrustStore(EcP256RootStore)
    .Build, 'localhost');
end;

function TTestEngineSkeleton.TakeAll(const AEngine: ITlsEngine): TBytes;
var
  LChunk: TBytes;
  LN: Int32;
begin
  Result := nil;
  repeat
    LChunk := nil;
    SetLength(LChunk, 4096);
    LN := AEngine.TakeOutgoing(LChunk, 0);
    if LN > 0 then
      Result := ConcatBytes(Result, System.Copy(LChunk, 0, LN));
  until LN <= 0;
end;

function TTestEngineSkeleton.PeerRecord(AContentType: TTlsContentType;
  const AData: TBytes): TBytes;
var
  LLayer: TRecordLayer;
  LChunk: TBytes;
  LN: Int32;
begin
  // frame a plaintext record exactly as a peer's record layer would
  LLayer := TRecordLayer.Create;
  try
    LLayer.Write(AContentType, AData, 0, System.Length(AData));
    Result := nil;
    repeat
      LChunk := nil;
      SetLength(LChunk, 4096);
      LN := LLayer.TakeOutgoing(LChunk, 0);
      if LN > 0 then
        Result := ConcatBytes(Result, System.Copy(LChunk, 0, LN));
    until LN <= 0;
  finally
    LLayer.Free;
  end;
end;

procedure TTestEngineSkeleton.TestEngineDoesNotExposeInstallerSeam;
var
  LEngine: ITlsEngine;
  LInstaller: IRecordEpochInstaller;
begin
  // the engine must not surface an installer reference to callers; the handshake bridge
  // links the engine and driver without either owning the other
  LEngine := NewEngine;
  CheckFalse(Supports(LEngine, IRecordEpochInstaller, LInstaller),
    'the engine does not expose IRecordEpochInstaller');
end;

procedure TTestEngineSkeleton.TestFatalPreQueuesAlertAndTerminal;
var
  LEngine: ITlsEngine;
  LOutcome: TTlsOutcome;
  LRaised: Boolean;
begin
  LEngine := NewEngine;
  // an over-long record length trips record_overflow in the record layer
  LOutcome := LEngine.ProcessInput(DecodeHex('170303FFFF'), 0, 5);
  CheckEquals(Ord(TTlsOutcome.Fatal), Ord(LOutcome), 'fatal outcome');
  CheckTrue(LEngine.IsTerminal, 'engine is terminal');
  // the record_overflow alert (fatal=2, 22) is pre-queued as a plaintext record; a client's
  // first outbound record carries legacy_record_version 0x0301 (RFC 8446 5.1)
  CheckEqualBytes('alert record pre-queued', DecodeHex('15030100020216'),
    TakeAll(LEngine));
  CheckEquals(Ord(TTlsAlertDescription.RecordOverflow),
    Ord(LEngine.LastError.Alert.Description), 'last error is record_overflow');
  CheckEquals(Ord(TTlsErrorOrigin.Local), Ord(LEngine.LastError.Origin),
    'a failure we detected is our own');
  // further input is refused with Fatal, and a write after a fatal is API misuse (raises)
  CheckEquals(Ord(TTlsOutcome.Fatal),
    Ord(LEngine.ProcessInput(DecodeHex('1703030000'), 0, 5)), 'still fatal');
  CheckTrue(LEngine.WriteClosed, 'the write side is closed after a fatal');
  LRaised := False;
  try
    LEngine.Write(DecodeHex('00'), 0, 1);
  except
    on EInvalidOperationTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a write after a fatal raises');
end;

procedure TTestEngineSkeleton.TestWantsReadWantsWriteReflectState;
var
  LEngine: ITlsEngine;
begin
  LEngine := NewEngine;
  CheckTrue(LEngine.WantsRead, 'a fresh engine wants input');
  CheckFalse(LEngine.WantsWrite, 'nothing to write yet');
  LEngine.StartHandshake;
  CheckTrue(LEngine.WantsWrite, 'starting the handshake queues the ClientHello');
  TakeAll(LEngine);
  CheckFalse(LEngine.WantsWrite, 'draining clears the outbound queue');
end;

procedure TTestEngineSkeleton.TestCleartextApplicationDataBeforeKeysIsFatal;
var
  LEngine: ITlsEngine;
  LWire: TBytes;
begin
  // a cleartext application_data record before any read epoch key is unexpected on a real
  // handshake (RFC 8446 5.1): the engine fails with unexpected_message
  LEngine := NewEngine;
  LWire := PeerRecord(TTlsContentType.ApplicationData, DecodeHex('deadbeef'));
  CheckEquals(Ord(TTlsOutcome.Fatal),
    Ord(LEngine.ProcessInput(LWire, 0, System.Length(LWire))),
    'cleartext application data before keys is fatal');
  CheckTrue(LEngine.IsTerminal, 'the engine is terminal');
  CheckEquals(Ord(TTlsAlertDescription.UnexpectedMessage),
    Ord(LEngine.LastError.Alert.Description), 'last error is unexpected_message');
  CheckEquals(Ord(TTlsErrorOrigin.Local), Ord(LEngine.LastError.Origin),
    'a failure we detected is our own');
end;

procedure TTestEngineSkeleton.TestWriteBeforeWriteEpochIsRefused;
var
  LEngine: ITlsEngine;
  LRaised: Boolean;
begin
  // no write epoch key is installed before the handshake; a Write would otherwise frame
  // application data in the clear, so the engine refuses it (library policy)
  LEngine := NewEngine;
  LRaised := False;
  try
    LEngine.Write(DecodeHex('deadbeef'), 0, 4);
  except
    on EInvalidOperationTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'application data before a write epoch is refused, not sent in the clear');
end;

procedure TTestEngineSkeleton.TestZeroLengthWriteBeforeEpochIsRefused;
var
  LEngine: ITlsEngine;
  LRaised: Boolean;
begin
  // the close/epoch guards run before the zero-length no-op, so even an empty write before a
  // write epoch is refused rather than silently swallowed
  LEngine := NewEngine;
  LRaised := False;
  try
    LEngine.Write(nil, 0, 0);
  except
    on EInvalidOperationTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a zero-length write before a write epoch is still refused');
end;

procedure TTestEngineSkeleton.TestOutOfRangeSliceRaisesWithoutTerminating;
var
  LEngine: ITlsEngine;
  LWire: TBytes;
  LRaised: Boolean;
begin
  // an out-of-range (AOffset, ALength) is caller misuse, not a peer fault: it raises an API-misuse
  // exception and must NOT put an internal_error on the wire or make the engine terminal, so the
  // caller can correct the slice and continue
  LEngine := NewEngine;
  LWire := DecodeHex('1703030000');
  LRaised := False;
  try
    LEngine.ProcessInput(LWire, 0, System.Length(LWire) + 100);
  except
    on E: EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'an out-of-range slice raises an argument error');
  CheckFalse(LEngine.IsTerminal, 'a caller slice error does not make the engine terminal');
  CheckEquals(0, System.Length(TakeAll(LEngine)), 'no alert was put on the wire');
end;

procedure TTestEngineSkeleton.TestAlertBetweenHandshakeFragmentsIsUnexpected;
var
  LEngine: ITlsEngine;
  LWire: TBytes;
begin
  // a handshake message that spans records must not have another record type interleaved
  // between its fragments (RFC 8446 5.1) - an alert is that violation as much as app data is
  LEngine := NewEngine;
  LEngine.StartHandshake;
  // a ServerHello handshake header claiming a 4-byte body with none present: one partial
  // handshake message is now buffered
  LWire := PeerRecord(TTlsContentType.Handshake, DecodeHex('02000004'));
  LEngine.ProcessInput(LWire, 0, System.Length(LWire));
  // an alert arriving mid-message is the interleaving violation, not a clean close
  LWire := PeerRecord(TTlsContentType.Alert, DecodeHex('0100'));
  CheckEquals(Ord(TTlsOutcome.Fatal),
    Ord(LEngine.ProcessInput(LWire, 0, System.Length(LWire))),
    'an alert between handshake fragments is fatal');
  CheckTrue(LEngine.IsTerminal, 'the engine is terminal');
  CheckEquals(Ord(TTlsAlertDescription.UnexpectedMessage),
    Ord(LEngine.LastError.Alert.Description), 'the alert code is unexpected_message');
  CheckEquals(Ord(TTlsErrorOrigin.Local), Ord(LEngine.LastError.Origin),
    'a violation we detected is our own');
  CheckFalse(LEngine.IsInboundClosed,
    'an interleaved alert is a protocol failure, not a clean close');
end;

procedure TTestEngineSkeleton.TestReceivedCloseNotifyBeforeHandshakeCompletesIsTerminal;
var
  LEngine: ITlsEngine;
  LEvent: ITlsEvent;
  LRaised: Boolean;
begin
  LEngine := NewEngine;
  // a warning close_notify alert record (level 1, description 0) before the handshake finishes
  // abandons it: the engine fails rather than sitting half-closed and handshaking forever
  CheckEquals(Ord(TTlsOutcome.Fatal),
    Ord(LEngine.ProcessInput(PeerRecord(TTlsContentType.Alert, DecodeHex('0100')), 0, 7)),
    'a close before the handshake completes is fatal');
  CheckTrue(LEngine.NextEvent(LEvent), 'a close event is queued');
  CheckEquals(Ord(TTlsEventKind.Closed), Ord(LEvent.Kind), 'closed event');
  CheckTrue(LEngine.IsTerminal, 'the engine is terminal');
  CheckFalse(LEngine.IsHandshaking, 'a terminal engine is no longer handshaking');
  CheckTrue(LEngine.IsInboundClosed, 'the inbound side is closed');
  CheckEquals(Ord(TTlsErrorOrigin.Peer), Ord(LEngine.LastError.Origin),
    'the peer ended the handshake');
  CheckEquals(0, LEngine.LastError.AlertByte, 'the recorded code is close_notify');
  CheckEquals(0, System.Length(TakeAll(LEngine)), 'no alert is sent in reply to a close');
  LRaised := False;
  try
    LEngine.Write(DecodeHex('00'), 0, 1);
  except
    on EInvalidOperationTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a terminal engine refuses writes');
end;

procedure TTestEngineSkeleton.TestCloseNotifyWithBogusAlertLevelIsIllegalParameter;
var
  LEngine: ITlsEngine;
begin
  // the level check precedes the close_notify branch: a level that is neither warning nor fatal
  // is malformed even on close_notify
  LEngine := NewEngine;
  CheckEquals(Ord(TTlsOutcome.Fatal),
    Ord(LEngine.ProcessInput(PeerRecord(TTlsContentType.Alert, DecodeHex('0700')), 0, 7)),
    'a close_notify with an invalid level is fatal');
  CheckEquals(Ord(TTlsAlertDescription.IllegalParameter),
    Ord(LEngine.LastError.Alert.Description), 'the alert code is illegal_parameter');
  CheckFalse(LEngine.IsInboundClosed, 'it is not taken for an orderly close');
end;

procedure TTestEngineSkeleton.TestOutOfRangeWriteSliceRaisesWithoutTerminating;
var
  LEngine: ITlsEngine;
  LData: TBytes;
  LI: Int32;
  LRaised: Boolean;
begin
  // an out-of-range (AOffset, ALength) on a write is caller misuse, like on ProcessInput: it raises
  // an argument error, sends no alert and leaves the engine alive, even before a write epoch exists
  LEngine := NewEngine;
  LData := DecodeHex('0102');
  for LI := 0 to 3 do
  begin
    LRaised := False;
    try
      case LI of
        0: LEngine.Write(LData, 0, 3);
        1: LEngine.Write(LData, -1, 1);
        2: LEngine.Write(LData, 0, -1);
        3: LEngine.WriteEarlyData(LData, 1, 2);
      end;
    except
      on EArgumentTlsLibException do
        LRaised := True;
    end;
    CheckTrue(LRaised, Format('write slice case %d raises an argument error', [LI]));
  end;
  CheckFalse(LEngine.IsTerminal, 'a caller slice error does not make the engine terminal');
  CheckEquals(0, System.Length(TakeAll(LEngine)), 'no alert was put on the wire');
end;

procedure TTestEngineSkeleton.TestReceivedFatalAlertIsTerminal;
var
  LEngine: ITlsEngine;
  LEvent: ITlsEvent;
  LAlert: IPeerAlertEvent;
begin
  LEngine := NewEngine;
  // a fatal handshake_failure alert (level 2, description 40)
  CheckEquals(Ord(TTlsOutcome.Fatal),
    Ord(LEngine.ProcessInput(PeerRecord(TTlsContentType.Alert,
    DecodeHex('0228')), 0, 7)), 'received fatal alert -> Fatal');
  CheckTrue(LEngine.IsTerminal, 'a received fatal alert is terminal');
  CheckTrue(LEngine.NextEvent(LEvent), 'a peer-alert event is queued');
  CheckEquals(Ord(TTlsEventKind.PeerAlert), Ord(LEvent.Kind), 'peer-alert event');
  CheckTrue(Supports(LEvent, IPeerAlertEvent, LAlert), 'carries the alert');
  CheckEquals($28, LAlert.Alert.DescriptionByte, 'handshake_failure code');
  CheckEquals(Ord(TTlsAlertDescription.HandshakeFailure),
    Ord(LEngine.LastError.Alert.Description), 'last error reflects the peer alert');
  CheckEquals(Ord(TTlsErrorOrigin.Peer), Ord(LEngine.LastError.Origin),
    'a received fatal alert is the peer''s');
end;

procedure TTestEngineSkeleton.TestReceivedUnknownFatalAlertIsPeerOrigin;
var
  LEngine: ITlsEngine;
begin
  LEngine := NewEngine;
  // a fatal alert with an unregistered description byte (level 2, description 0xFF)
  CheckEquals(Ord(TTlsOutcome.Fatal),
    Ord(LEngine.ProcessInput(PeerRecord(TTlsContentType.Alert,
    DecodeHex('02FF')), 0, 7)), 'received fatal alert -> Fatal');
  CheckTrue(LEngine.IsTerminal, 'terminal');
  CheckEquals(Ord(TTlsErrorOrigin.Peer), Ord(LEngine.LastError.Origin),
    'an unknown-description peer fatal is still the peer''s');
end;

procedure TTestEngineSkeleton.TestLastErrorOriginIsUnknownBeforeAnyFailure;
var
  LEngine: ITlsEngine;
begin
  LEngine := NewEngine;
  CheckEquals(Ord(TTlsErrorOrigin.Unknown), Ord(LEngine.LastError.Origin),
    'no failure recorded yet');
end;

procedure TTestEngineSkeleton.TestSendAlertMarksLocalOrigin;
var
  LEngine: ITlsEngine;
begin
  LEngine := NewEngine;
  LEngine.SendAlert(TTlsAlertDescription.HandshakeFailure);
  CheckTrue(LEngine.IsTerminal, 'sending a fatal alert is terminal');
  CheckEquals(Ord(TTlsErrorOrigin.Local), Ord(LEngine.LastError.Origin),
    'an alert we send is our own');
end;

procedure TTestEngineSkeleton.TestConnectionInfoZeroStateBeforeHandshake;
var
  LEngine: ITlsEngine;
  LInfo: TTlsConnectionInfo;
begin
  // before StartHandshake nothing is negotiated: ConnectionInfo reads back the zero snapshot
  LEngine := NewEngine;
  LInfo := LEngine.ConnectionInfo;
  CheckEquals(0, LInfo.NegotiatedVersion.WireValue, 'no version negotiated yet');
  CheckTrue(LInfo.EchStatus = TEchStatus.NotOffered, 'ECH not offered yet');
  CheckFalse(LInfo.Resumed, 'not a resumed handshake');
  CheckEquals(0, LInfo.CipherSuite, 'no cipher suite negotiated');
  CheckEquals(0, LInfo.NamedGroup, 'no named group negotiated');
  CheckEquals(0, System.Length(LInfo.AlpnProtocol), 'no ALPN protocol selected');
  CheckEquals('', LInfo.ServerName, 'no server name recorded');
  CheckEquals(0, System.Length(LInfo.PeerCertificates), 'no peer certificates');
  CheckEquals(0, System.Length(LInfo.ValidatedPath), 'no validated path yet');
  CheckEquals(0, System.Length(LInfo.RequestedCertificateAuthorities),
    'no requested certificate authorities');
  CheckEquals(0, System.Length(LInfo.PeerOcspStaple), 'no peer OCSP staple');
  CheckEquals(0, System.Length(LInfo.EchRetryConfigs), 'no ECH retry configs');
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestEngineSkeleton);
{$ELSE}
  RegisterTest(TTestEngineSkeleton.Suite);
{$ENDIF FPC}

end.
