{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

/// <summary>
/// Build-once-reuse support for the integration adapters. A frozen ITlsServerConfig /
/// ITlsClientConfig is meant to be built once and reused for every connection, not rebuilt per
/// connection. An adapter builds its config with its own logic (trust composition, system trust,
/// credentials - untouched), then memoises it here keyed by a signature of its inputs (built with
/// TTlsSignatureBuilder), so subsequent connections reuse the same config identity - which the
/// session-ticket / resumption domain also requires. Keyed rather than single-slot only so a
/// process with several listeners on different certificates does not thrash.
/// </summary>
unit TlpTlsConfigMemo;

{$I ..\Include\TlsLib.inc}

interface

uses
  SyncObjs,
  TlpITlsConfig,
  TlpITlsConfigMemo;

/// <summary>A new empty server-config memo.</summary>
function NewTlsServerConfigMemo: ITlsServerConfigMemo;
/// <summary>A new empty client-config memo.</summary>
function NewTlsClientConfigMemo: ITlsClientConfigMemo;

implementation

type
  /// <summary>The keyed build-once-reuse ring shared by both config variants: a fixed-capacity,
  /// signature-keyed store guarded by a lock. The sealed server/client subclasses only bind T and
  /// the matching interface; all behaviour lives here.</summary>
  TTlsConfigMemo<T> = class abstract(TInterfacedObject)
  strict private
  var
    FLock: TCriticalSection;
    FSignatures: TArray<string>;
    FConfigs: TArray<T>;
    FCount: Int32;
    FNext: Int32;
  public
    constructor Create;
    destructor Destroy; override;
    function TryGet(const ASignature: string; out AConfig: T): Boolean;
    function StoreOrAdopt(const ASignature: string; const ABuilt: T): T;
    procedure Clear;
  end;

  TTlsServerConfigMemo = class sealed(TTlsConfigMemo<ITlsServerConfig>, ITlsServerConfigMemo)
  end;

  TTlsClientConfigMemo = class sealed(TTlsConfigMemo<ITlsClientConfig>, ITlsClientConfigMemo)
  end;

function NewTlsServerConfigMemo: ITlsServerConfigMemo;
begin
  Result := TTlsServerConfigMemo.Create;
end;

function NewTlsClientConfigMemo: ITlsClientConfigMemo;
begin
  Result := TTlsClientConfigMemo.Create;
end;

const
  // enough distinct configs for a multi-listener / multi-cert process without unbounded growth;
  // the oldest entry is evicted when full and simply rebuilt if seen again. A rebuild now also
  // mints a fresh default STEK, so headroom here reduces needless ticket-key churn under load.
  MemoCapacity = 16;

{ TTlsConfigMemo<T> }

constructor TTlsConfigMemo<T>.Create;
begin
  inherited Create;
  SetLength(FSignatures, MemoCapacity);
  SetLength(FConfigs, MemoCapacity);
  FCount := 0;
  FNext := 0;
  FLock := TCriticalSection.Create;
end;

destructor TTlsConfigMemo<T>.Destroy;
begin
  FLock.Free;
  inherited Destroy;
end;

function TTlsConfigMemo<T>.TryGet(const ASignature: string;
  out AConfig: T): Boolean;
var
  LI: Int32;
begin
  Result := False;
  AConfig := Default(T);
  FLock.Enter;
  try
    for LI := 0 to FCount - 1 do
      if FSignatures[LI] = ASignature then
      begin
        AConfig := FConfigs[LI];
        Exit(True);
      end;
  finally
    FLock.Leave;
  end;
end;

function TTlsConfigMemo<T>.StoreOrAdopt(const ASignature: string;
  const ABuilt: T): T;
var
  LI: Int32;
begin
  FLock.Enter;
  try
    // adopt a config another thread stored for this signature while we were building
    for LI := 0 to FCount - 1 do
      if FSignatures[LI] = ASignature then
        Exit(FConfigs[LI]);
    FSignatures[FNext] := ASignature;
    FConfigs[FNext] := ABuilt;
    FNext := (FNext + 1) mod MemoCapacity;
    if FCount < MemoCapacity then
      Inc(FCount);
    Result := ABuilt;
  finally
    FLock.Leave;
  end;
end;

procedure TTlsConfigMemo<T>.Clear;
var
  LI: Int32;
begin
  FLock.Enter;
  try
    for LI := 0 to MemoCapacity - 1 do
    begin
      FSignatures[LI] := '';
      FConfigs[LI] := Default(T);
    end;
    FCount := 0;
    FNext := 0;
  finally
    FLock.Leave;
  end;
end;

end.
