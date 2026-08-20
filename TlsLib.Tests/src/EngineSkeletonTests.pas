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
  TlpTlsLibExceptions,
  TlpTlsContentType,
  TlpSecretBuffer,
  TlpICryptoProvider,
  TlpCryptoAlgorithms,
  TlpIRecordProtection,
  TlpRecordProtection,
  TlpRecordLayer,
  TlpITlsEngine,
  TlpITlsEventSink,
  TlpTlsEngine,
  TlsLibTestBase;

type
  IRecordingSink = interface(ITlsEventSink)
    ['{1A2B3C4D-5E6F-4071-8192-A3B4C5D6E7F8}']
    function EventCount: Int32;
    function LastKind: TTlsEventKind;
  end;

  TRecordingSink = class(TInterfacedObject, ITlsEventSink, IRecordingSink)
  strict private
  var
    FCount: Int32;
    FLastKind: TTlsEventKind;
  public
    procedure OnEvent(const AEvent: ITlsEvent);
    function EventCount: Int32;
    function LastKind: TTlsEventKind;
  end;

  TTestEngineSkeleton = class(TTlsLibAlgorithmTestCase)
  private
    function NewEngine: ITlsEngine;
    function MakeTls13(const AKey, AIv: TBytes): IRecordProtection;
    function TakeAll(const AEngine: ITlsEngine): TBytes;
    function ReadAllApp(const AEngine: ITlsEngine): TBytes;
    function PeerRecord(AContentType: TTlsContentType; const AData: TBytes): TBytes;
  published
    procedure TestNullPlumbingRoundTrip;
    procedure TestEngineDoesNotExposeInstallerSeam;
    procedure TestProtectedRoundTripAfterInstallKeys;
    procedure TestFatalPreQueuesAlertAndTerminal;
    procedure TestWantsReadWantsWriteReflectState;
    procedure TestEventQueueOrdering;
    procedure TestStartHandshakeRaisesNotSupported;
    procedure TestReceivedCloseNotify;
    procedure TestReceivedFatalAlertIsTerminal;
    procedure TestPushSinkDeliversEvents;
  end;

implementation

{ TRecordingSink }

procedure TRecordingSink.OnEvent(const AEvent: ITlsEvent);
begin
  Inc(FCount);
  FLastKind := AEvent.Kind;
end;

function TRecordingSink.EventCount: Int32;
begin
  Result := FCount;
end;

function TRecordingSink.LastKind: TTlsEventKind;
begin
  Result := FLastKind;
end;

{ TTestEngineSkeleton }

function TTestEngineSkeleton.NewEngine: ITlsEngine;
begin
  Result := TTlsEngine.Create;
end;

function TTestEngineSkeleton.MakeTls13(const AKey, AIv: TBytes): IRecordProtection;
begin
  Result := TTls13RecordProtection.Create(TSecretBuffer.From(AKey),
    TSecretBuffer.From(AIv), Provider.CreateAead(TAeadAlgorithm.AES_128_GCM));
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

function TTestEngineSkeleton.ReadAllApp(const AEngine: ITlsEngine): TBytes;
var
  LChunk: TBytes;
  LN: Int32;
begin
  Result := nil;
  repeat
    LChunk := nil;
    SetLength(LChunk, 4096);
    LN := AEngine.ReadAppData(LChunk, 0, 4096);
    if LN > 0 then
      Result := ConcatBytes(Result, System.Copy(LChunk, 0, LN));
  until LN <= 0;
end;

function TTestEngineSkeleton.PeerRecord(AContentType: TTlsContentType;
  const AData: TBytes): TBytes;
var
  LLayer: TRecordLayer;
begin
  // frame a plaintext record exactly as a peer's record layer would
  LLayer := TRecordLayer.Create;
  try
    LLayer.Write(AContentType, AData, 0, System.Length(AData));
    Result := LLayer.TakeOutgoing;
  finally
    LLayer.Free;
  end;
end;

procedure TTestEngineSkeleton.TestNullPlumbingRoundTrip;
var
  LEngine: ITlsEngine;
  LData, LWire: TBytes;
  LEvent: ITlsEvent;
begin
  LEngine := NewEngine;
  LData := DecodeHex('48656c6c6f2c20706c756d62696e6721'); // "Hello, plumbing!"
  LWire := PeerRecord(TTlsContentType.ApplicationData, LData);
  CheckEquals(Ord(TTlsOutcome.Advanced),
    Ord(LEngine.ProcessInput(LWire, 0, System.Length(LWire))), 'advanced');
  CheckTrue(LEngine.NextEvent(LEvent), 'an event is queued');
  CheckEquals(Ord(TTlsEventKind.AppData), Ord(LEvent.Kind), 'app-data event');
  CheckEqualBytes('app data surfaces', LData, ReadAllApp(LEngine));
end;

procedure TTestEngineSkeleton.TestEngineDoesNotExposeInstallerSeam;
var
  LEngine: ITlsEngine;
  LInstaller: IRecordEpochInstaller;
begin
  // the engine must not surface a counted installer reference: that would re-enable
  // the engine<->driver refcount cycle the handshake bridge exists to break
  LEngine := NewEngine;
  CheckFalse(Supports(LEngine, IRecordEpochInstaller, LInstaller),
    'the engine does not expose IRecordEpochInstaller');
end;

procedure TTestEngineSkeleton.TestProtectedRoundTripAfterInstallKeys;
var
  LClientObj, LServerObj: TTlsEngine;
  LClient, LServer: ITlsEngine;
  LKey, LIv, LData, LWire: TBytes;
begin
  LKey := DecodeHex('000102030405060708090a0b0c0d0e0f');
  LIv := DecodeHex('101112131415161718191a1b');
  // the engine no longer exposes an installer interface; the concrete install
  // methods the handshake bridge uses are called directly here
  LClientObj := TTlsEngine.Create;
  LClient := LClientObj;
  LServerObj := TTlsEngine.Create;
  LServer := LServerObj;
  LClientObj.InstallWriteProtection(MakeTls13(LKey, LIv));
  LServerObj.InstallReadProtection(MakeTls13(LKey, LIv));

  // installing an epoch does not by itself establish the handshake: only the
  // state machine's completion signal does (see the loopback tests)
  CheckTrue(LClient.IsHandshaking, 'a raw epoch install does not establish the handshake');

  LData := DecodeHex('746f70207365637265742064617461'); // "top secret data"
  LClient.Write(LData, 0, System.Length(LData));
  LWire := TakeAll(LClient);
  // a protected record is longer than plaintext by inner type (1) + tag (16)
  CheckEquals(5 + System.Length(LData) + 1 + 16, System.Length(LWire),
    'record carries AEAD overhead');
  LServer.ProcessInput(LWire, 0, System.Length(LWire));
  CheckEqualBytes('server decrypts the app data', LData, ReadAllApp(LServer));
end;

procedure TTestEngineSkeleton.TestFatalPreQueuesAlertAndTerminal;
var
  LEngine: ITlsEngine;
  LOutcome: TTlsOutcome;
begin
  LEngine := NewEngine;
  // an over-long record length trips record_overflow in the record layer
  LOutcome := LEngine.ProcessInput(DecodeHex('170303FFFF'), 0, 5);
  CheckEquals(Ord(TTlsOutcome.Fatal), Ord(LOutcome), 'fatal outcome');
  CheckTrue(LEngine.IsTerminal, 'engine is terminal');
  // the record_overflow alert (fatal=2, 22) is pre-queued as a plaintext record
  CheckEqualBytes('alert record pre-queued', DecodeHex('15030300020216'),
    TakeAll(LEngine));
  CheckEquals(Ord(TTlsAlertDescription.RecordOverflow),
    Ord(LEngine.LastError.Alert.Description), 'last error is record_overflow');
  // further input is refused with Fatal, and writes are no-ops
  CheckEquals(Ord(TTlsOutcome.Fatal),
    Ord(LEngine.ProcessInput(DecodeHex('1703030000'), 0, 5)), 'still fatal');
  LEngine.Write(DecodeHex('00'), 0, 1);
  CheckEquals(0, System.Length(TakeAll(LEngine)), 'no output after terminal');
end;

procedure TTestEngineSkeleton.TestWantsReadWantsWriteReflectState;
var
  LEngine: ITlsEngine;
begin
  LEngine := NewEngine;
  CheckTrue(LEngine.WantsRead, 'a fresh engine wants input');
  CheckFalse(LEngine.WantsWrite, 'nothing to write yet');
  LEngine.Write(DecodeHex('cafebabe'), 0, 4);
  CheckTrue(LEngine.WantsWrite, 'a write queues outbound bytes');
  TakeAll(LEngine);
  CheckFalse(LEngine.WantsWrite, 'draining clears the outbound queue');
end;

procedure TTestEngineSkeleton.TestEventQueueOrdering;
var
  LEngine: ITlsEngine;
  LSender: TRecordLayer;
  LWire, LHs, LApp: TBytes;
  LEvent: ITlsEvent;
  LHsEvent: IHandshakeDataEvent;
begin
  LEngine := NewEngine;
  LHs := DecodeHex('0a0b0c');
  LApp := DecodeHex('d0d0');
  LSender := TRecordLayer.Create;
  try
    LSender.Write(TTlsContentType.Handshake, LHs, 0, System.Length(LHs));
    LSender.Write(TTlsContentType.ApplicationData, LApp, 0, System.Length(LApp));
    LWire := LSender.TakeOutgoing;
  finally
    LSender.Free;
  end;
  LEngine.ProcessInput(LWire, 0, System.Length(LWire));
  // handshake fragment first, then app-data - the arrival order
  CheckTrue(LEngine.NextEvent(LEvent), 'first event');
  CheckEquals(Ord(TTlsEventKind.HandshakeFragment), Ord(LEvent.Kind), 'handshake first');
  CheckTrue(Supports(LEvent, IHandshakeDataEvent, LHsEvent), 'carries fragment data');
  CheckEqualBytes('handshake fragment bytes', LHs, LHsEvent.Data);
  CheckTrue(LEngine.NextEvent(LEvent), 'second event');
  CheckEquals(Ord(TTlsEventKind.AppData), Ord(LEvent.Kind), 'app-data second');
  CheckFalse(LEngine.NextEvent(LEvent), 'queue drained in order');
end;

procedure TTestEngineSkeleton.TestStartHandshakeRaisesNotSupported;
var
  LEngine: ITlsEngine;
  LRaised: Boolean;
begin
  LEngine := NewEngine;
  LRaised := False;
  try
    LEngine.StartHandshake;
  except
    on E: ENotSupportedTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'the handshake intent is cleanly stubbed');
end;

procedure TTestEngineSkeleton.TestReceivedCloseNotify;
var
  LEngine: ITlsEngine;
  LEvent: ITlsEvent;
begin
  LEngine := NewEngine;
  // a warning close_notify alert record (level 1, description 0)
  LEngine.ProcessInput(PeerRecord(TTlsContentType.Alert, DecodeHex('0100')), 0, 7);
  CheckTrue(LEngine.NextEvent(LEvent), 'a close event is queued');
  CheckEquals(Ord(TTlsEventKind.Closed), Ord(LEvent.Kind), 'closed event');
  CheckFalse(LEngine.IsTerminal, 'a clean close is not a fatal termination');
  CheckFalse(LEngine.WantsRead, 'no more input is wanted after close');
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
end;

procedure TTestEngineSkeleton.TestPushSinkDeliversEvents;
var
  LEngine: ITlsEngine;
  LSource: ITlsEventSource;
  LSink: IRecordingSink;
  LWire: TBytes;
begin
  LEngine := NewEngine;
  LSink := TRecordingSink.Create;
  CheckTrue(Supports(LEngine, ITlsEventSource, LSource), 'engine is an event source');
  LSource.SetEventSink(LSink);
  LWire := PeerRecord(TTlsContentType.ApplicationData, DecodeHex('01020304'));
  LEngine.ProcessInput(LWire, 0, System.Length(LWire));
  CheckTrue(LSink.EventCount >= 1, 'the sink is notified');
  CheckEquals(Ord(TTlsEventKind.AppData), Ord(LSink.LastKind), 'app-data pushed');
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestEngineSkeleton);
{$ELSE}
  RegisterTest(TTestEngineSkeleton.Suite);
{$ENDIF FPC}

end.
