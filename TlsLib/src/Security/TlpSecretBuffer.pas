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
  /// The default <see cref="ISecretBuffer" />: a refcounted class over a raw,
  /// heap-stable buffer. The destructor wipes the region before freeing it, so
  /// the secret is zeroized once, when the last reference releases. Construct
  /// through <see cref="From" /> / <see cref="Allocate" /> and hold the interface.
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
    /// <summary>A zero-filled secret buffer of ALen bytes.</summary>
    class function Allocate(ALen: Int32): ISecretBuffer; static;
    /// <summary>A secret buffer holding APrefix (public) followed by ASecret's bytes,
    /// without materializing the secret in a non-wiped intermediate.</summary>
    class function Concat(const APrefix: TBytes;
      const ASecret: ISecretBuffer): ISecretBuffer; static;
  end;

implementation

resourcestring
  SNegativeLength = 'secret buffer length cannot be negative';
  SCopyLengthExceedsBuffer = 'copy length %d exceeds secret buffer length %d';

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

end.
