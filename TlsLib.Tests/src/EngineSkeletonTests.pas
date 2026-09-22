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
  TlpRecordLayer,
  TlpICertificateTrust,
  TlpCertificateVerifier,
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
    procedure TestReceivedCloseNotify;
    procedure TestReceivedFatalAlertIsTerminal;
  end;

implementation

{ TTestEngineSkeleton }

function TTestEngineSkeleton.NewEngine: ITlsEngine;
begin
  // a client engine before StartHandshake: it frames records and processes plaintext
  // alerts without needing a live peer. An empty anchor store satisfies the builder's
  // trust check for a handshake that is never completed here.
  Result := TTlsEngineFactory.CreateClientEngine(
    TTlsPresets.Compatible(Crypto, Pkix).Client
    .WithTrustStore(TTrustAnchorStore.Create(nil) as ITrustAnchorStore)
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
  CheckTrue(LEngine.IsInboundClosed, 'the inbound side is closed');
  CheckFalse(LEngine.WantsRead, 'no more input is wanted after close');

  // bytes the peer sends after its close_notify are discarded, not framed or treated as a
  // protocol error (RFC 9846 6.1): a further feed is a clean no-op, not a fatal outcome
  CheckFalse(LEngine.ProcessInput(PeerRecord(TTlsContentType.ApplicationData,
    DecodeHex('deadbeef')), 0, 9) = TTlsOutcome.Fatal,
    'post-close input is discarded, not a fatal outcome');
  CheckFalse(LEngine.IsTerminal, 'post-close input does not make the engine terminal');
  CheckTrue(LEngine.IsInboundClosed, 'the inbound side stays closed (idempotent)');
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


initialization

{$IFDEF FPC}
  RegisterTest(TTestEngineSkeleton);
{$ELSE}
  RegisterTest(TTestEngineSkeleton.Suite);
{$ENDIF FPC}

end.
