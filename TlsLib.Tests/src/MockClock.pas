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

  /// <summary>
  /// An <see cref="ITlsMonotonicClock" /> a test advances by hand, so a deadline can be driven
  /// without waiting. It only moves forward, as the real source does. Never for production use.
  /// </summary>
  TMockMonotonicClock = class(TInterfacedObject, ITlsMonotonicClock)
  strict private
  var
    FMillis: Int64;
  public
    constructor Create(AMillis: Int64);
    /// <summary>Moves the clock forward by AMillis.</summary>
    procedure Advance(AMillis: Int64);
    function NowMonotonicMillis: Int64;
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

{ TMockMonotonicClock }

constructor TMockMonotonicClock.Create(AMillis: Int64);
begin
  inherited Create;
  FMillis := AMillis;
end;

procedure TMockMonotonicClock.Advance(AMillis: Int64);
begin
  Inc(FMillis, AMillis);
end;

function TMockMonotonicClock.NowMonotonicMillis: Int64;
begin
  Result := FMillis;
end;

end.
