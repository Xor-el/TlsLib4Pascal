{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit BenchAllocCounter;

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

interface

type
  /// <summary>
  /// Counts heap requests over a window: the memory manager is wrapped by a counting
  /// shim for the duration of Start..Stop and restored afterwards, so the timed passes
  /// run on the plain manager and the count never skews the throughput figure. Every
  /// GetMem / AllocMem / ReAllocMem is one request (a realloc is at least a potential
  /// move + copy); bytes are the sizes requested. Single-threaded use only.
  /// </summary>
  TBenchAllocCounter = class sealed(TObject)
  public
    class procedure Start; static;
    class procedure Stop(out ARequests, ABytes: Int64); static;
  end;

implementation

var
  GBase: TMemoryManager;
  GRequests, GBytes: Int64;
  GActive: Boolean;

function CountingGetMem(ASize: PtrUInt): Pointer;
begin
  Inc(GRequests);
  Inc(GBytes, ASize);
  Result := GBase.GetMem(ASize);
end;

function CountingAllocMem(ASize: PtrUInt): Pointer;
begin
  Inc(GRequests);
  Inc(GBytes, ASize);
  Result := GBase.AllocMem(ASize);
end;

function CountingReAllocMem(var AP: Pointer; ASize: PtrUInt): Pointer;
begin
  Inc(GRequests);
  Inc(GBytes, ASize);
  Result := GBase.ReAllocMem(AP, ASize);
end;

class procedure TBenchAllocCounter.Start;
var
  LCounting: TMemoryManager;
begin
  if GActive then
    Exit;
  GetMemoryManager(GBase);
  LCounting := GBase;
  LCounting.GetMem := @CountingGetMem;
  LCounting.AllocMem := @CountingAllocMem;
  LCounting.ReAllocMem := @CountingReAllocMem;
  GRequests := 0;
  GBytes := 0;
  GActive := True;
  SetMemoryManager(LCounting);
end;

class procedure TBenchAllocCounter.Stop(out ARequests, ABytes: Int64);
begin
  ARequests := 0;
  ABytes := 0;
  if not GActive then
    Exit;
  SetMemoryManager(GBase);
  GActive := False;
  ARequests := GRequests;
  ABytes := GBytes;
end;

end.
