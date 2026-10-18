{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpCodeKeyedRegistry;

{$I ..\Include\TlsLib.inc}

interface

uses
  SysUtils,
  TlpArrayUtilities;

type
  /// <summary>
  /// The read side shared by the code-keyed registries: an ordered list keyed by a UInt16 wire
  /// code, fixed when the registry is created. A concrete registry supplies the code extractor
  /// (through the constructor) and the specific registry interface; the vocabulary - Items /
  /// Contains / TryGet - is then uniform across all of them. Insertion order is preserved (it is
  /// the on-wire preference order).
  /// </summary>
  TCodeKeyedRegistryBase<T> = class abstract(TInterfacedObject)
  strict protected
  var
    FItems: TArray<T>;
    FCodeOf: TKeyOf<T, UInt16>;
    constructor Create(const ACodeOf: TKeyOf<T, UInt16>; const AItems: TArray<T>);
  public
    /// <summary>All entries, in insertion (preference) order.</summary>
    function Items: TArray<T>;
    /// <summary>Whether an entry with ACode is registered.</summary>
    function Contains(ACode: UInt16): Boolean;
    /// <summary>The entry with ACode; False (AItem unset) when none.</summary>
    function TryGet(ACode: UInt16; out AItem: T): Boolean;
  end;

  /// <summary>
  /// A registry that can still change: the base of the registry builders. Add is a no-op when the
  /// code is already present.
  /// </summary>
  TCodeKeyedRegistryBuilderBase<T> = class abstract(TCodeKeyedRegistryBase<T>)
  public
    /// <summary>Appends AItem unless its code is already present.</summary>
    procedure Add(const AItem: T);
    /// <summary>Removes the entry with ACode, if any.</summary>
    procedure Prune(ACode: UInt16);
  end;

implementation

{ TCodeKeyedRegistryBase<T> }

constructor TCodeKeyedRegistryBase<T>.Create(const ACodeOf: TKeyOf<T, UInt16>;
  const AItems: TArray<T>);
begin
  inherited Create;
  FCodeOf := ACodeOf;
  FItems := System.Copy(AItems);
end;

function TCodeKeyedRegistryBase<T>.Items: TArray<T>;
begin
  Result := System.Copy(FItems);
end;

function TCodeKeyedRegistryBase<T>.TryGet(ACode: UInt16; out AItem: T): Boolean;
var
  LIndex: Int32;
begin
  LIndex := TArrayUtilities.IndexOfKey<T, UInt16>(FItems, FCodeOf, ACode);
  Result := LIndex >= 0;
  if Result then
    AItem := FItems[LIndex];
end;

function TCodeKeyedRegistryBase<T>.Contains(ACode: UInt16): Boolean;
var
  LItem: T;
begin
  Result := TryGet(ACode, LItem);
end;

{ TCodeKeyedRegistryBuilderBase<T> }

procedure TCodeKeyedRegistryBuilderBase<T>.Add(const AItem: T);
begin
  if Contains(FCodeOf(AItem)) then
    Exit;
  TArrayUtilities.Append<T>(FItems, AItem);
end;

procedure TCodeKeyedRegistryBuilderBase<T>.Prune(ACode: UInt16);
begin
  TArrayUtilities.RemoveKey<T, UInt16>(FItems, FCodeOf, ACode);
end;

end.
