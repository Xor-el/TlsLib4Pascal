{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit MockRandom;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  SysUtils,
  TlpICryptoProvider;

type
  /// <summary>
  /// A deterministic <see cref="IRandom" /> for tests: a seeded xorshift stream,
  /// so a given seed always yields the same bytes. Never for production use.
  /// </summary>
  TMockRandom = class(TInterfacedObject, IRandom)
  strict private
  var
    FState: UInt64;
    function NextByte: Byte;
  public
    constructor Create(ASeed: UInt64);
    procedure NextBytes(const ABuffer: TBytes);
    function GenerateBytes(ALength: Int32): TBytes;
  end;

implementation

{ TMockRandom }

constructor TMockRandom.Create(ASeed: UInt64);
begin
  inherited Create;
  // xorshift has a fixed point at zero; any other seed gives a full-period stream
  if ASeed = 0 then
    ASeed := 1;
  FState := ASeed;
end;

function TMockRandom.NextByte: Byte;
begin
  FState := FState xor (FState shl 13);
  FState := FState xor (FState shr 7);
  FState := FState xor (FState shl 17);
  Result := Byte(FState);
end;

procedure TMockRandom.NextBytes(const ABuffer: TBytes);
var
  LI: Int32;
begin
  for LI := 0 to System.Length(ABuffer) - 1 do
    ABuffer[LI] := NextByte;
end;

function TMockRandom.GenerateBytes(ALength: Int32): TBytes;
begin
  Result := nil;
  SetLength(Result, ALength);
  NextBytes(Result);
end;

end.
