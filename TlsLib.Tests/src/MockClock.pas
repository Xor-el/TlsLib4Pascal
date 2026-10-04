{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit MockClock;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  TlpIClock;

type
  /// <summary>
  /// An <see cref="ITlsClock" /> pinned to a fixed instant, so a test can drive time-based
  /// checks (certificate validity, staple freshness) deterministically. SetUnixMillis advances
  /// it. Never for production use.
  /// </summary>
  TMockClock = class(TInterfacedObject, ITlsClock)
  strict private
  var
    FUnixMillis: UInt64;
  public
    constructor Create(AUnixMillis: UInt64);
    procedure SetUnixMillis(AValue: UInt64);
    /// <summary>Moves the clock forward by AMillis.</summary>
    procedure Advance(AMillis: UInt64);
    /// <summary>Moves the clock back by AMillis (a wall-clock step back).</summary>
    procedure Retreat(AMillis: UInt64);
    function NowUnixMillis: UInt64;
  end;

implementation

{ TMockClock }

constructor TMockClock.Create(AUnixMillis: UInt64);
begin
  inherited Create;
  FUnixMillis := AUnixMillis;
end;

procedure TMockClock.SetUnixMillis(AValue: UInt64);
begin
  FUnixMillis := AValue;
end;

procedure TMockClock.Advance(AMillis: UInt64);
begin
  Inc(FUnixMillis, AMillis);
end;

procedure TMockClock.Retreat(AMillis: UInt64);
begin
  Dec(FUnixMillis, AMillis);
end;

function TMockClock.NowUnixMillis: UInt64;
begin
  Result := FUnixMillis;
end;

end.
