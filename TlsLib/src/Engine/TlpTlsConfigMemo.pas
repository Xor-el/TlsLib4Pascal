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

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

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
  TTlsServerConfigMemo = class sealed(TInterfacedObject, ITlsServerConfigMemo)
  strict private
  var
    FLock: TCriticalSection;
    FSignatures: TArray<string>;
    FConfigs: TArray<ITlsServerConfig>;
    FCount: Int32;
    FNext: Int32;
  public
    constructor Create;
    destructor Destroy; override;
    function TryGet(const ASignature: string; out AConfig: ITlsServerConfig): Boolean;
    function StoreOrAdopt(const ASignature: string;
      const ABuilt: ITlsServerConfig): ITlsServerConfig;
    procedure Clear;
  end;

  TTlsClientConfigMemo = class sealed(TInterfacedObject, ITlsClientConfigMemo)
  strict private
  var
    FLock: TCriticalSection;
    FSignatures: TArray<string>;
    FConfigs: TArray<ITlsClientConfig>;
    FCount: Int32;
    FNext: Int32;
  public
    constructor Create;
    destructor Destroy; override;
    function TryGet(const ASignature: string; out AConfig: ITlsClientConfig): Boolean;
    function StoreOrAdopt(const ASignature: string;
      const ABuilt: ITlsClientConfig): ITlsClientConfig;
    procedure Clear;
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
  // enough distinct configs for a multi-listener process without unbounded growth; the oldest
  // entry is evicted when full and simply rebuilt if seen again
  MemoCapacity = 8;

{ TTlsServerConfigMemo }

constructor TTlsServerConfigMemo.Create;
begin
  inherited Create;
  System.SetLength(FSignatures, MemoCapacity);
  System.SetLength(FConfigs, MemoCapacity);
  FCount := 0;
  FNext := 0;
  FLock := TCriticalSection.Create;
end;

destructor TTlsServerConfigMemo.Destroy;
begin
  FLock.Free;
  inherited Destroy;
end;

function TTlsServerConfigMemo.TryGet(const ASignature: string;
  out AConfig: ITlsServerConfig): Boolean;
var
  LI: Int32;
begin
  Result := False;
  AConfig := nil;
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

function TTlsServerConfigMemo.StoreOrAdopt(const ASignature: string;
  const ABuilt: ITlsServerConfig): ITlsServerConfig;
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

procedure TTlsServerConfigMemo.Clear;
var
  LI: Int32;
begin
  FLock.Enter;
  try
    for LI := 0 to MemoCapacity - 1 do
    begin
      FSignatures[LI] := '';
      FConfigs[LI] := nil;
    end;
    FCount := 0;
    FNext := 0;
  finally
    FLock.Leave;
  end;
end;

{ TTlsClientConfigMemo }

constructor TTlsClientConfigMemo.Create;
begin
  inherited Create;
  System.SetLength(FSignatures, MemoCapacity);
  System.SetLength(FConfigs, MemoCapacity);
  FCount := 0;
  FNext := 0;
  FLock := TCriticalSection.Create;
end;

destructor TTlsClientConfigMemo.Destroy;
begin
  FLock.Free;
  inherited Destroy;
end;

function TTlsClientConfigMemo.TryGet(const ASignature: string;
  out AConfig: ITlsClientConfig): Boolean;
var
  LI: Int32;
begin
  Result := False;
  AConfig := nil;
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

function TTlsClientConfigMemo.StoreOrAdopt(const ASignature: string;
  const ABuilt: ITlsClientConfig): ITlsClientConfig;
var
  LI: Int32;
begin
  FLock.Enter;
  try
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

procedure TTlsClientConfigMemo.Clear;
var
  LI: Int32;
begin
  FLock.Enter;
  try
    for LI := 0 to MemoCapacity - 1 do
    begin
      FSignatures[LI] := '';
      FConfigs[LI] := nil;
    end;
    FCount := 0;
    FNext := 0;
  finally
    FLock.Leave;
  end;
end;

end.
