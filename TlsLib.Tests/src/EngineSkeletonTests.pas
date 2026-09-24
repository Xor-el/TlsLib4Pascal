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
  CheckEquals('', LInfo.AlpnProtocol, 'no ALPN protocol selected');
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
