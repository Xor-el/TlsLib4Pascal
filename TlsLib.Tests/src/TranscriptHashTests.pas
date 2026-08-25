{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TranscriptHashTests;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  SysUtils,
  Classes,
{$IFDEF FPC}
  fpcunit,
  testregistry,
{$ELSE}
  TestFramework,
{$ENDIF FPC}
  TlpTlsLibExceptions,
  TlpICryptoProvider,
  TlpCryptoAlgorithms,
  TlpITranscriptHash,
  TlpTranscriptHash,
  TlsLibTestBase;

type
  TTestTranscriptHash = class(TTlsLibAlgorithmTestCase)
  private
    FVec: TStringList;
    function Msg(const AName: string): TBytes;
    function Sha256: IHash;
    function RawSha256(const AData: TBytes): TBytes;
    function MessageHashWrapper(const ACh1Hash: TBytes): TBytes;
    procedure FeedThroughServerFinished(const ATranscript: ITranscriptHash);
  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestRfc8448RunningHashes;
    procedure TestDeferredThenActivateReplays;
    procedure TestCloneBranchesIndependently;
    procedure TestCurrentHashDoesNotConsume;
    procedure TestDeferredCurrentHashRaises;
    procedure TestReplaceWithMessageHashMatchesRfc8448Section5;
    procedure TestSeedWithMessageHashEqualsReplace;
  end;

implementation

{ TTestTranscriptHash }

procedure TTestTranscriptHash.SetUp;
begin
  inherited SetUp;
  FVec := LoadVectorFields('Rfc8448/HandshakeMessages.txt');
end;

procedure TTestTranscriptHash.TearDown;
begin
  FVec.Free;
  inherited TearDown;
end;

function TTestTranscriptHash.Msg(const AName: string): TBytes;
begin
  Result := DecodeHex(FVec.Values[AName]);
end;

function TTestTranscriptHash.Sha256: IHash;
begin
  Result := Provider.Primitives.CreateHash(THashAlgorithm.SHA_256);
end;

function TTestTranscriptHash.RawSha256(const AData: TBytes): TBytes;
var
  LHash: IHash;
begin
  LHash := Sha256;
  LHash.Update(AData, 0, System.Length(AData));
  Result := LHash.DoFinal;
end;

function TTestTranscriptHash.MessageHashWrapper(const ACh1Hash: TBytes): TBytes;
begin
  // Handshake(message_hash, Hash(ClientHello1)): 254 || uint24(len) || hash
  Result := ConcatBytes(TBytes.Create($FE, $00, $00, Byte(System.Length(ACh1Hash))),
    ACh1Hash);
end;

procedure TTestTranscriptHash.FeedThroughServerFinished(
  const ATranscript: ITranscriptHash);
begin
  ATranscript.Update(Msg('client_hello'));
  ATranscript.Update(Msg('server_hello'));
  ATranscript.Update(Msg('encrypted_ext'));
  ATranscript.Update(Msg('certificate'));
  ATranscript.Update(Msg('cert_verify'));
  ATranscript.Update(Msg('server_finished'));
end;

procedure TTestTranscriptHash.TestRfc8448RunningHashes;
var
  LTranscript: ITranscriptHash;
begin
  LTranscript := TTranscriptHash.Create(Sha256);
  LTranscript.Update(Msg('client_hello'));
  LTranscript.Update(Msg('server_hello'));
  CheckEqualBytes('hash(CH..SH)', Msg('hash_ch_sh'), LTranscript.CurrentHash);

  LTranscript.Update(Msg('encrypted_ext'));
  LTranscript.Update(Msg('certificate'));
  LTranscript.Update(Msg('cert_verify'));
  LTranscript.Update(Msg('server_finished'));
  CheckEqualBytes('hash(CH..server Finished)', Msg('hash_ch_sf'),
    LTranscript.CurrentHash);

  LTranscript.Update(Msg('client_finished'));
  CheckEqualBytes('hash(CH..client Finished)', Msg('hash_ch_cf'),
    LTranscript.CurrentHash);
end;

procedure TTestTranscriptHash.TestDeferredThenActivateReplays;
var
  LTranscript: ITranscriptHash;
begin
  // the suite (hence the hash) is unknown until ServerHello: buffer, then replay
  LTranscript := TTranscriptHash.Create;
  LTranscript.Update(Msg('client_hello'));
  LTranscript.Update(Msg('server_hello'));
  CheckFalse(LTranscript.IsActive, 'still deferred before Activate');
  CheckEquals(0, LTranscript.HashSize, 'no hash size while deferred');

  LTranscript.Activate(Sha256);
  CheckTrue(LTranscript.IsActive, 'active after Activate');
  CheckEqualBytes('replayed hash(CH..SH)', Msg('hash_ch_sh'),
    LTranscript.CurrentHash);
end;

procedure TTestTranscriptHash.TestCloneBranchesIndependently;
var
  LTranscript, LBranch: ITranscriptHash;
begin
  LTranscript := TTranscriptHash.Create(Sha256);
  LTranscript.Update(Msg('client_hello'));
  LTranscript.Update(Msg('server_hello'));
  LBranch := LTranscript.Clone;

  // advance only the original; the branch stays pinned at CH..SH
  LTranscript.Update(Msg('encrypted_ext'));
  CheckEqualBytes('branch is unchanged', Msg('hash_ch_sh'), LBranch.CurrentHash);
  CheckFalse(AreEqual(LTranscript.CurrentHash, LBranch.CurrentHash),
    'original diverged from the branch');
end;

procedure TTestTranscriptHash.TestCurrentHashDoesNotConsume;
var
  LTranscript: ITranscriptHash;
  LFirst, LSecond: TBytes;
begin
  LTranscript := TTranscriptHash.Create(Sha256);
  FeedThroughServerFinished(LTranscript);
  LFirst := LTranscript.CurrentHash;
  LSecond := LTranscript.CurrentHash;
  CheckEqualBytes('snapshot is repeatable', LFirst, LSecond);
  // and the running state still advances afterwards
  LTranscript.Update(Msg('client_finished'));
  CheckFalse(AreEqual(LFirst, LTranscript.CurrentHash),
    'the transcript keeps advancing after a snapshot');
end;

procedure TTestTranscriptHash.TestDeferredCurrentHashRaises;
var
  LTranscript: ITranscriptHash;
  LRaised: Boolean;
begin
  LTranscript := TTranscriptHash.Create;
  LTranscript.Update(Msg('client_hello'));
  LRaised := False;
  try
    LTranscript.CurrentHash;
  except
    on E: EInvalidOperationTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a deferred transcript has no hash to snapshot');
end;

procedure TTestTranscriptHash.TestReplaceWithMessageHashMatchesRfc8448Section5;
var
  LHrr: TStringList;
  LTranscript: ITranscriptHash;
  LCh1, LCh1Hash, LExpected: TBytes;
begin
  // RFC 8446 4.4.1: on a HelloRetryRequest, ClientHello1 is replaced in the transcript
  // by Handshake(message_hash, Hash(ClientHello1)). Verify byte-exact against the
  // RFC 8448 Section 5 ClientHello1 by recomputing the wrapper independently.
  LHrr := LoadVectorFields('Rfc8448/HelloRetryRequest.txt');
  try
    LCh1 := DecodeHex(LHrr.Values['client_hello_1']);
  finally
    LHrr.Free;
  end;
  LCh1Hash := RawSha256(LCh1);
  LExpected := RawSha256(MessageHashWrapper(LCh1Hash));

  // feed CH1 into a deferred transcript, then apply the message_hash replacement
  LTranscript := TTranscriptHash.Create;
  LTranscript.Update(LCh1);
  LTranscript.Activate(Sha256);
  LTranscript.ReplaceWithMessageHash(Sha256);
  CheckEqualBytes('transcript after message_hash = SHA256(254 || len || Hash(CH1))',
    LExpected, LTranscript.CurrentHash);
end;

procedure TTestTranscriptHash.TestSeedWithMessageHashEqualsReplace;
var
  LHrr: TStringList;
  LReplace, LSeed: ITranscriptHash;
  LCh1, LCh1Hash: TBytes;
begin
  // seeding from a known Hash(CH1) (the stateless-cookie rebuild path) must produce the
  // same transcript as replacing an in-hand CH1
  LHrr := LoadVectorFields('Rfc8448/HelloRetryRequest.txt');
  try
    LCh1 := DecodeHex(LHrr.Values['client_hello_1']);
  finally
    LHrr.Free;
  end;
  LCh1Hash := RawSha256(LCh1);

  LReplace := TTranscriptHash.Create;
  LReplace.Update(LCh1);
  LReplace.Activate(Sha256);
  LReplace.ReplaceWithMessageHash(Sha256);

  LSeed := TTranscriptHash.Create;
  LSeed.SeedWithMessageHash(Sha256, LCh1Hash);

  CheckEqualBytes('seed-from-hash matches replace-in-hand', LReplace.CurrentHash,
    LSeed.CurrentHash);
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestTranscriptHash);
{$ELSE}
  RegisterTest(TTestTranscriptHash.Suite);
{$ENDIF FPC}

end.
