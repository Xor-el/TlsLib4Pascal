{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpInMemoryCertificateCompressionCache;

{$I ..\Include\TlsLib.inc}

interface

uses
  SysUtils,
  SyncObjs,
  Generics.Collections,
  TlpDataEncoding,
  TlpICertificateCompressionCache;

type
  /// <summary>
  /// The default in-memory <see cref="ICertificateCompressionCache" />: a bounded map
  /// of compressed Certificate bodies keyed by a content digest the policy derives.
  /// When the cap is reached the oldest entry is evicted. Guarded by an internal lock,
  /// so one instance is safe to share across connections/threads.
  /// </summary>
  TInMemoryCertificateCompressionCache = class sealed(TInterfacedObject,
    ICertificateCompressionCache)
  strict private
  var
    FByKey: TDictionary<string, TBytes>;
    FOrder: TQueue<string>;
    FCapacity: Int32;
    FLock: TCriticalSection;
    class function KeyOf(const AKey: TBytes): string; static;
    procedure EvictToCapacity;
  public
    /// <summary>A cache holding up to ACapacity entries (default when 0 or less).</summary>
    constructor Create; overload;
    constructor Create(ACapacity: Int32); overload;
    destructor Destroy; override;

    function TryGet(const AKey: TBytes; out ACompressed: TBytes): Boolean;
    procedure Put(const AKey: TBytes; const ACompressed: TBytes);
    procedure Clear;
    function Count: Int32;
  end;

implementation

const
  DefaultCertCompressionCacheCapacity = Int32(64);

{ TInMemoryCertificateCompressionCache }

constructor TInMemoryCertificateCompressionCache.Create;
begin
  Create(0);
end;

constructor TInMemoryCertificateCompressionCache.Create(ACapacity: Int32);
begin
  inherited Create;
  if ACapacity > 0 then
    FCapacity := ACapacity
  else
    FCapacity := DefaultCertCompressionCacheCapacity;
  FByKey := TDictionary<string, TBytes>.Create;
  FOrder := TQueue<string>.Create;
  FLock := TCriticalSection.Create;
end;

destructor TInMemoryCertificateCompressionCache.Destroy;
begin
  FByKey.Free;
  FOrder.Free;
  FLock.Free;
  inherited Destroy;
end;

class function TInMemoryCertificateCompressionCache.KeyOf(const AKey: TBytes): string;
begin
  // a lossless, encoding-independent text key over the binary digest
  Result := TDataEncoding.HexEncode(AKey);
end;

procedure TInMemoryCertificateCompressionCache.EvictToCapacity;
var
  LKey: string;
begin
  while (FByKey.Count > FCapacity) and (FOrder.Count > 0) do
  begin
    LKey := FOrder.Dequeue;
    FByKey.Remove(LKey);
  end;
end;

function TInMemoryCertificateCompressionCache.TryGet(const AKey: TBytes;
  out ACompressed: TBytes): Boolean;
var
  LKey: string;
begin
  ACompressed := nil;
  LKey := KeyOf(AKey);
  FLock.Enter;
  try
    Result := FByKey.TryGetValue(LKey, ACompressed);
  finally
    FLock.Leave;
  end;
end;

procedure TInMemoryCertificateCompressionCache.Put(const AKey: TBytes;
  const ACompressed: TBytes);
var
  LKey: string;
begin
  LKey := KeyOf(AKey);
  FLock.Enter;
  try
    // each key sits in FOrder once, so an overwrite must not enqueue again
    if FByKey.ContainsKey(LKey) then
      FByKey[LKey] := ACompressed
    else
    begin
      FByKey.Add(LKey, ACompressed);
      FOrder.Enqueue(LKey);
      EvictToCapacity;
    end;
  finally
    FLock.Leave;
  end;
end;

procedure TInMemoryCertificateCompressionCache.Clear;
begin
  FLock.Enter;
  try
    FByKey.Clear;
    FOrder.Clear;
  finally
    FLock.Leave;
  end;
end;

function TInMemoryCertificateCompressionCache.Count: Int32;
begin
  FLock.Enter;
  try
    Result := FByKey.Count;
  finally
    FLock.Leave;
  end;
end;

end.
