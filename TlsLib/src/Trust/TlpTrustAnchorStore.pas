{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpTrustAnchorStore;

{$I ..\Include\TlsLib.inc}

interface

uses
  SysUtils,
  Generics.Collections,
  TlpArrayUtilities,
  TlpITrustAnchorStore;

type
  /// <summary>The immutable in-memory trust store over a fixed set of root CA DERs and, optionally,
  /// the certificates its source distrusts. Any root that is also distrusted is dropped from the
  /// anchors and exact duplicates collapse, so every anchor is one certificate the path builder
  /// considers once.</summary>
  TTrustAnchorStore = class sealed(TInterfacedObject, ITrustAnchorStore)
  strict private
  var
    FRoots: TArray<TBytes>;
    FDistrusted: TArray<TBytes>;
    // read-only after Create, so concurrent verifiers may share them
    FRootIndex: TDictionary<TBytes, Boolean>;
    FDistrustIndex: TDictionary<TBytes, Boolean>;
    // the stores a union was built from, kept alive so an identity-keyed cache of one of them
    // cannot see its address handed to a different store while this one is in use
    FSources: TArray<ITrustAnchorStore>;
    procedure Index(const ARoots, ADistrusted: TArray<TBytes>);
  public
    constructor Create(const ARoots: TArray<TBytes>); overload;
    constructor Create(const ARoots, ADistrusted: TArray<TBytes>); overload;
    destructor Destroy; override;
    /// <summary>One store over every child's roots and distrust. Distrust from any child beats an
    /// anchor from another, so a root one child distrusts is not an anchor of the union. Nil
    /// children are skipped, and a single remaining child is returned as it is. A union keeps
    /// its children alive.</summary>
    class function Union(const AStores: TArray<ITrustAnchorStore>): ITrustAnchorStore; static;
    function AnchorCount: Int32;
    function RootCertificates: TArray<TBytes>;
    function IsAnchor(const ACertificate: TBytes): Boolean;
    function DistrustedCertificates: TArray<TBytes>;
    function IsDistrusted(const ACertificate: TBytes): Boolean;
  end;

implementation

{ TTrustAnchorStore }

constructor TTrustAnchorStore.Create(const ARoots: TArray<TBytes>);
begin
  Create(ARoots, nil);
end;

constructor TTrustAnchorStore.Create(const ARoots, ADistrusted: TArray<TBytes>);
begin
  inherited Create;
  FRootIndex := TDictionary<TBytes, Boolean>.Create;
  FDistrustIndex := TDictionary<TBytes, Boolean>.Create;
  // own immutable snapshots: a caller that mutates its arrays later must not change our sets
  Index(TArrayUtilities.DeepCopy<Byte>(ARoots), TArrayUtilities.DeepCopy<Byte>(ADistrusted));
end;

destructor TTrustAnchorStore.Destroy;
begin
  FRootIndex.Free;
  FDistrustIndex.Free;
  inherited Destroy;
end;

procedure TTrustAnchorStore.Index(const ARoots, ADistrusted: TArray<TBytes>);
var
  LI, LCount: Int32;
begin
  FDistrusted := nil;
  SetLength(FDistrusted, System.Length(ADistrusted));
  LCount := 0;
  for LI := 0 to System.High(ADistrusted) do
    if not FDistrustIndex.ContainsKey(ADistrusted[LI]) then
    begin
      FDistrustIndex.Add(ADistrusted[LI], True);
      FDistrusted[LCount] := ADistrusted[LI];
      Inc(LCount);
    end;
  SetLength(FDistrusted, LCount);
  FRoots := nil;
  SetLength(FRoots, System.Length(ARoots));
  LCount := 0;
  for LI := 0 to System.High(ARoots) do
    if (not FDistrustIndex.ContainsKey(ARoots[LI])) and
      (not FRootIndex.ContainsKey(ARoots[LI])) then
    begin
      FRootIndex.Add(ARoots[LI], True);
      FRoots[LCount] := ARoots[LI];
      Inc(LCount);
    end;
  SetLength(FRoots, LCount);
end;

class function TTrustAnchorStore.Union(
  const AStores: TArray<ITrustAnchorStore>): ITrustAnchorStore;
var
  LI: Int32;
  LLive: TArray<ITrustAnchorStore>;
  LRoots, LDistrusted: TArray<TBytes>;
  LUnion: TTrustAnchorStore;
begin
  LLive := nil;
  for LI := 0 to System.High(AStores) do
    if AStores[LI] <> nil then
      TArrayUtilities.Append<ITrustAnchorStore>(LLive, AStores[LI]);
  if System.Length(LLive) = 1 then
    Exit(LLive[0]);
  LRoots := nil;
  LDistrusted := nil;
  for LI := 0 to System.High(LLive) do
  begin
    LRoots := TArrayUtilities.Concat<TBytes>(LRoots, LLive[LI].RootCertificates);
    LDistrusted := TArrayUtilities.Concat<TBytes>(LDistrusted, LLive[LI].DistrustedCertificates);
  end;
  LUnion := TTrustAnchorStore.Create(LRoots, LDistrusted);
  Result := LUnion;
  LUnion.FSources := LLive;
end;

function TTrustAnchorStore.AnchorCount: Int32;
begin
  Result := System.Length(FRoots);
end;

function TTrustAnchorStore.RootCertificates: TArray<TBytes>;
begin
  Result := TArrayUtilities.DeepCopy<Byte>(FRoots);
end;

function TTrustAnchorStore.IsAnchor(const ACertificate: TBytes): Boolean;
begin
  Result := FRootIndex.ContainsKey(ACertificate);
end;

function TTrustAnchorStore.DistrustedCertificates: TArray<TBytes>;
begin
  Result := TArrayUtilities.DeepCopy<Byte>(FDistrusted);
end;

function TTrustAnchorStore.IsDistrusted(const ACertificate: TBytes): Boolean;
begin
  Result := FDistrustIndex.ContainsKey(ACertificate);
end;

end.
