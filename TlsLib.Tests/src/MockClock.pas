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
  SyncObjs,
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
    FStepPerRead: Int64;
    // the stepping read may come from several threads, and an Int64 can tear on a 32-bit target
    FLock: TCriticalSection;
  public
    constructor Create(AMillis: Int64); overload;
    destructor Destroy; override;
    /// <summary>A clock that also moves forward by AStepPerRead on every read, so code that polls
    /// the time spends a budget without the test waiting.</summary>
    constructor Create(AMillis, AStepPerRead: Int64); overload;
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
  FStepPerRead := 0;
  FLock := TCriticalSection.Create;
end;

destructor TMockMonotonicClock.Destroy;
begin
  FLock.Free;
  inherited Destroy;
end;

constructor TMockMonotonicClock.Create(AMillis, AStepPerRead: Int64);
begin
  Create(AMillis);
  FStepPerRead := AStepPerRead;
end;

procedure TMockMonotonicClock.Advance(AMillis: Int64);
begin
  FLock.Acquire;
  try
    Inc(FMillis, AMillis);
  finally
    FLock.Release;
  end;
end;

function TMockMonotonicClock.NowMonotonicMillis: Int64;
begin
  FLock.Acquire;
  try
    Result := FMillis;
    Inc(FMillis, FStepPerRead);
  finally
    FLock.Release;
  end;
end;

end.
