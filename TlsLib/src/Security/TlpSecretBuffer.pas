{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpSecretBuffer;

{$I ..\Include\TlsLib.inc}

interface

uses
  SysUtils,
  TlpISecretBuffer,
  TlpSecureMemory,
  TlpTlsLibExceptions;

type
  /// <summary>
  /// The default <see cref="ISecretBuffer" />: a class over a raw, heap-stable
  /// buffer. The destructor wipes the region before freeing it, so the secret is
  /// zeroized on release. Construct through <see cref="From" /> /
  /// <see cref="Allocate" /> and hold the interface.
  /// </summary>
  TSecretBuffer = class sealed(TInterfacedObject, ISecretBuffer)
  strict private
  var
    FPtr: PByte;
    FLen: Int32;
  strict protected
    constructor Create(ALen: Int32);
  public
    destructor Destroy; override;

    function Len: Int32;
    function DataPtr: PByte;
    procedure CopyFrom(ASrc: PByte; ALen: Int32);
    function ToBytes: TBytes;
    function ConstantTimeAreEqual(const AOther: ISecretBuffer): Boolean;

    /// <summary>A secret buffer holding a copy of ABytes.</summary>
    class function From(const ABytes: TBytes): ISecretBuffer; static;
    /// <summary>A secret buffer holding AValue as UTF-8, so a passphrase is carried as a wiped
    /// buffer instead of an immutable string. Empty yields a zero-length buffer, distinct from nil.</summary>
    class function FromString(const AValue: string): ISecretBuffer; static;
    /// <summary>A zero-filled secret buffer of ALen bytes.</summary>
    class function Allocate(ALen: Int32): ISecretBuffer; static;
    /// <summary>A secret buffer holding APrefix (public) followed by ASecret's bytes,
    /// without materializing the secret in a non-wiped intermediate.</summary>
    class function Concat(const APrefix: TBytes;
      const ASecret: ISecretBuffer): ISecretBuffer; static;
    /// <summary>A secret buffer holding ASource[AOffset .. AOffset+ALength), copied without a
    /// non-wiped byte-array intermediate (a TLS 1.2 key block sliced into per-direction keys).</summary>
    class function Slice(const ASource: ISecretBuffer;
      AOffset, ALength: Int32): ISecretBuffer; static;
    /// <summary>A secret buffer holding AFirst's bytes followed by ASecond's, neither
    /// materialized in a non-wiped intermediate (a hybrid group's concatenated shared secret).
    /// A nil operand contributes nothing.</summary>
    class function Join(const AFirst, ASecond: ISecretBuffer): ISecretBuffer; static;
  end;

implementation

resourcestring
  SNegativeLength = 'secret buffer length cannot be negative';
  SCopyLengthExceedsBuffer = 'copy length %d exceeds secret buffer length %d';
  SSliceOutOfRange = 'secret buffer slice is out of range';

{ TSecretBuffer }

constructor TSecretBuffer.Create(ALen: Int32);
begin
  inherited Create;
  if ALen < 0 then
    raise EArgumentTlsLibException.CreateRes(@SNegativeLength);
  FLen := ALen;
  if FLen > 0 then
  begin
    GetMem(FPtr, FLen);
    FillChar(FPtr^, FLen, 0);
  end
  else
    FPtr := nil;
end;

destructor TSecretBuffer.Destroy;
begin
  if FPtr <> nil then
  begin
    TSecureMemory.Wipe(FPtr, FLen);
    FreeMem(FPtr);
    FPtr := nil;
  end;
  inherited Destroy;
end;

function TSecretBuffer.Len: Int32;
begin
  Result := FLen;
end;

function TSecretBuffer.DataPtr: PByte;
begin
  Result := FPtr;
end;

procedure TSecretBuffer.CopyFrom(ASrc: PByte; ALen: Int32);
begin
  if (ALen < 0) or (ALen > FLen) then
    raise EArgumentTlsLibException.CreateResFmt(@SCopyLengthExceedsBuffer,
      [ALen, FLen]);
  if ALen > 0 then
    Move(ASrc^, FPtr^, ALen);
end;

function TSecretBuffer.ToBytes: TBytes;
begin
  Result := nil;
  SetLength(Result, FLen);
  if FLen > 0 then
    Move(FPtr^, Result[0], FLen);
end;

function TSecretBuffer.ConstantTimeAreEqual(const AOther: ISecretBuffer): Boolean;
begin
  // the length is not secret, so an early length mismatch is fine
  if (AOther = nil) or (AOther.Len <> FLen) then
    Result := False
  else if FLen = 0 then
    Result := True
  else
    Result := TSecureMemory.ConstantTimeAreEqual(FPtr, AOther.DataPtr, FLen);
end;

class function TSecretBuffer.From(const ABytes: TBytes): ISecretBuffer;
var
  LLen: Int32;
begin
  LLen := System.Length(ABytes);
  Result := TSecretBuffer.Create(LLen);
  if LLen > 0 then
    Result.CopyFrom(@ABytes[0], LLen);
end;

class function TSecretBuffer.Allocate(ALen: Int32): ISecretBuffer;
begin
  Result := TSecretBuffer.Create(ALen);
end;

class function TSecretBuffer.FromString(const AValue: string): ISecretBuffer;
begin
  Result := TSecretBuffer.From(TEncoding.UTF8.GetBytes(AValue));
end;

class function TSecretBuffer.Concat(const APrefix: TBytes;
  const ASecret: ISecretBuffer): ISecretBuffer;
var
  LPrefixLen, LSecretLen: Int32;
  LDst: PByte;
begin
  LPrefixLen := System.Length(APrefix);
  if ASecret <> nil then
    LSecretLen := ASecret.Len
  else
    LSecretLen := 0;
  Result := TSecretBuffer.Create(LPrefixLen + LSecretLen);
  LDst := Result.DataPtr;
  if LPrefixLen > 0 then
    Move(APrefix[0], LDst^, LPrefixLen);
  if LSecretLen > 0 then
    Move(ASecret.DataPtr^, (LDst + LPrefixLen)^, LSecretLen);
end;

class function TSecretBuffer.Slice(const ASource: ISecretBuffer;
  AOffset, ALength: Int32): ISecretBuffer;
begin
  if (ASource = nil) or (AOffset < 0) or (ALength < 0) or
    (AOffset + ALength > ASource.Len) then
    raise EArgumentTlsLibException.CreateRes(@SSliceOutOfRange);
  Result := TSecretBuffer.Create(ALength);
  if ALength > 0 then
    Move((ASource.DataPtr + AOffset)^, Result.DataPtr^, ALength);
end;

class function TSecretBuffer.Join(const AFirst,
  ASecond: ISecretBuffer): ISecretBuffer;
var
  LFirstLen, LSecondLen: Int32;
  LDst: PByte;
begin
  if AFirst <> nil then
    LFirstLen := AFirst.Len
  else
    LFirstLen := 0;
  if ASecond <> nil then
    LSecondLen := ASecond.Len
  else
    LSecondLen := 0;
  Result := TSecretBuffer.Create(LFirstLen + LSecondLen);
  LDst := Result.DataPtr;
  if LFirstLen > 0 then
    Move(AFirst.DataPtr^, LDst^, LFirstLen);
  if LSecondLen > 0 then
    Move(ASecond.DataPtr^, (LDst + LFirstLen)^, LSecondLen);
end;

end.
