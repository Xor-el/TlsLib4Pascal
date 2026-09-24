{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpTranscriptHash;

{$I ..\Include\TlsLib.inc}

interface

uses
  SysUtils,
  TlpArrayUtilities,
  TlpBinaryPrimitives,
  TlpTlsLibExceptions,
  TlpICryptoProvider,
  TlpITranscriptHash;

type
  /// <summary>
  /// The running transcript hash over the provider's IHash. Snapshots via
  /// CurrentHash clone the digest so the running state is never consumed, and
  /// Clone forks the whole transcript. Starts deferred - buffering the pre-suite
  /// messages until Activate replays them into the negotiated hash.
  /// </summary>
  TTranscriptHash = class sealed(TInterfacedObject, ITranscriptHash)
  strict private
  var
    FHash: IHash;      // nil while deferred
    FPending: TBytes;  // messages buffered before Activate
  public
    /// <summary>A transcript already bound to AHash (the suite is known).</summary>
    constructor Create(const AHash: IHash); overload;
    /// <summary>A deferred transcript that buffers until Activate selects the hash.</summary>
    constructor Create; overload;

    procedure Update(const AData: TBytes); overload;
    procedure Update(const AData: TBytes; AOffset, ALength: Int32); overload;
    procedure Activate(const AHash: IHash);
    function IsActive: Boolean;
    procedure SeedWithMessageHash(const AFreshHash: IHash; const ACh1Hash: TBytes);
    function CurrentHash: TBytes;
    function HashPrefixExcludingBinders(const APartialClientHello: TBytes): TBytes;
    function HashSize: Int32;
    function Clone: ITranscriptHash;
  end;

implementation

const
  MessageHashType = Byte(254); // the message_hash handshake type (RFC 8446 4.4.1)

resourcestring
  SAlreadyActive = 'the transcript hash is already bound to a hash';
  SNotActive = 'the transcript hash is still deferred (no hash selected)';

{ TTranscriptHash }

constructor TTranscriptHash.Create(const AHash: IHash);
begin
  inherited Create;
  FHash := AHash;
  FPending := nil;
end;

constructor TTranscriptHash.Create;
begin
  inherited Create;
  FHash := nil;
  FPending := nil;
end;

procedure TTranscriptHash.Update(const AData: TBytes);
begin
  Update(AData, 0, System.Length(AData));
end;

procedure TTranscriptHash.Update(const AData: TBytes; AOffset, ALength: Int32);
begin
  if ALength <= 0 then
    Exit;
  if FHash <> nil then
    FHash.Update(AData, AOffset, ALength)
  else
    // still deferred: buffer verbatim so Activate can replay in order
    FPending := TArrayUtilities.Concat(FPending, System.Copy(AData, AOffset, ALength));
end;

procedure TTranscriptHash.Activate(const AHash: IHash);
begin
  if FHash <> nil then
    raise EInvalidOperationTlsLibException.CreateRes(@SAlreadyActive);
  FHash := AHash;
  if System.Length(FPending) > 0 then
    FHash.Update(FPending, 0, System.Length(FPending));
  FPending := nil;
end;

function TTranscriptHash.IsActive: Boolean;
begin
  Result := FHash <> nil;
end;

procedure TTranscriptHash.SeedWithMessageHash(const AFreshHash: IHash;
  const ACh1Hash: TBytes);
var
  LWrapper: TBytes;
  LLen: Int32;
begin
  // Handshake(message_hash, Hash(ClientHello1)): type(1) || uint24 length || hash.
  // The 4-byte header is one big-endian word - a digest length always fits in 24 bits
  LLen := System.Length(ACh1Hash);
  LWrapper := nil;
  SetLength(LWrapper, 4 + LLen);
  TBinaryPrimitives.WriteUInt32BigEndian(LWrapper, 0,
    (UInt32(MessageHashType) shl 24) or UInt32(LLen));
  if LLen > 0 then
    Move(ACh1Hash[0], LWrapper[4], LLen);
  FHash := AFreshHash;
  FPending := nil;
  FHash.Update(LWrapper, 0, System.Length(LWrapper));
end;

function TTranscriptHash.CurrentHash: TBytes;
begin
  Result := nil;
  if FHash = nil then
    raise EInvalidOperationTlsLibException.CreateRes(@SNotActive);
  // hash a clone so the running transcript is not finalized/reset
  Result := FHash.Clone.DoFinal;
end;

function TTranscriptHash.HashPrefixExcludingBinders(
  const APartialClientHello: TBytes): TBytes;
var
  LClone: IHash;
begin
  Result := nil;
  if FHash = nil then
    raise EInvalidOperationTlsLibException.CreateRes(@SNotActive);
  LClone := FHash.Clone;
  if System.Length(APartialClientHello) > 0 then
    LClone.Update(APartialClientHello, 0, System.Length(APartialClientHello));
  Result := LClone.DoFinal;
end;

function TTranscriptHash.HashSize: Int32;
begin
  if FHash = nil then
    Result := 0
  else
    Result := FHash.HashSize;
end;

function TTranscriptHash.Clone: ITranscriptHash;
var
  LClone: TTranscriptHash;
begin
  if FHash <> nil then
    LClone := TTranscriptHash.Create(FHash.Clone)
  else
  begin
    LClone := TTranscriptHash.Create;
    LClone.FPending := System.Copy(FPending, 0, System.Length(FPending));
  end;
  Result := LClone;
end;

end.
