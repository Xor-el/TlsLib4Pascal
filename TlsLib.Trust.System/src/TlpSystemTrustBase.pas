{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpSystemTrustBase;

{$I ..\..\TlsLib\src\Include\TlsLib.inc}

interface

uses
  SysUtils,
  Generics.Collections,
  TlpICryptoProvider,
  TlpICertificateTrust,
  TlpCertificateVerifier,
  TlpSystemTrustExceptions;

type
  /// <summary>
  /// Deduplicates harvested roots by exact bytes: a filesystem store walking
  /// hashed-symlink directories sees the same certificate under several names.
  /// </summary>
  TSystemRootAccumulator = class sealed(TObject)
  strict private
    FRoots: TList<TBytes>;
    FSeen: TDictionary<TBytes, Boolean>;
  public
    constructor Create;
    destructor Destroy; override;
    procedure Add(const ADer: TBytes);
    function ToArray: TArray<TBytes>;
  end;

  /// <summary>
  /// Abstract platform trust-root SOURCE - it reads the OS trust store, it is not
  /// itself a trust store. Snapshot freezes the harvested roots into an immutable
  /// TTrustAnchorStore that the verifier consumes, so the anchors a config validates
  /// against are fixed at build time and never change under it; picking up OS changes
  /// means building a new snapshot. A source is a short-lived helper the caller owns
  /// and frees, and nothing is read until Harvest. Fail-closed: an empty or unreadable
  /// harvest raises rather than yielding an empty anchor set. Subclasses override
  /// HarvestRoots.
  /// </summary>
  TSystemRootSource = class abstract(TObject)
  strict private
    FProvider: ICryptoProvider;
  strict protected
    /// <summary>Gather the platform's trusted roots as DER. May return empty; Harvest
    /// turns an empty result into a fail-closed error.</summary>
    function HarvestRoots: TArray<TBytes>; virtual; abstract;
    /// <summary>Human-readable source label, used in the fail-closed message.</summary>
    function SourceName: string; virtual; abstract;
    /// <summary>The crypto provider, for subclasses that must parse (e.g. PEM).</summary>
    property Provider: ICryptoProvider read FProvider;
  protected
    /// <summary>Adds ADer to AAccumulator only if the provider confirms it a
    /// well-formed X.509 certificate; the accumulator handles the exact-byte
    /// de-dup for hashed-symlink directories.</summary>
    procedure AddUnique(const AAccumulator: TSystemRootAccumulator;
      const ADer: TBytes);
  public
    constructor Create(const AProvider: ICryptoProvider);
    /// <summary>Reads the source now. Fail-closed: an empty or unreadable source
    /// raises ESystemTrustUnavailableTlsLibException; a non-empty result is returned
    /// as harvested.</summary>
    function Harvest: TArray<TBytes>;
    /// <summary>Harvests now and freezes the result into an immutable anchor store.</summary>
    function Snapshot: ITrustAnchorStore;
  end;

implementation

resourcestring
  SSystemTrustEmpty =
    'the %s trust store could not be read or contained no usable root certificates';
  SNoProvider = 'a crypto provider is required to read the system trust store';

{ TSystemRootAccumulator }

constructor TSystemRootAccumulator.Create;
begin
  inherited Create;
  FRoots := TList<TBytes>.Create;
  FSeen := TDictionary<TBytes, Boolean>.Create;
end;

destructor TSystemRootAccumulator.Destroy;
begin
  FSeen.Free;
  FRoots.Free;
  inherited Destroy;
end;

procedure TSystemRootAccumulator.Add(const ADer: TBytes);
var
  LCopy: TBytes;
begin
  if FSeen.ContainsKey(ADer) then
    Exit;
  LCopy := Copy(ADer, 0, Length(ADer));
  FSeen.Add(LCopy, True);
  FRoots.Add(LCopy);
end;

function TSystemRootAccumulator.ToArray: TArray<TBytes>;
begin
  Result := FRoots.ToArray;
end;

{ TSystemRootSource }

constructor TSystemRootSource.Create(const AProvider: ICryptoProvider);
begin
  inherited Create;
  if AProvider = nil then
    raise ESystemTrustUnavailableTlsLibException.CreateRes(@SNoProvider);
  FProvider := AProvider;
end;

procedure TSystemRootSource.AddUnique(const AAccumulator: TSystemRootAccumulator;
  const ADer: TBytes);
begin
  if not FProvider.Certificates.IsWellFormed(ADer) then
    Exit;
  AAccumulator.Add(ADer);
end;

function TSystemRootSource.Harvest: TArray<TBytes>;
begin
  Result := HarvestRoots;
  if Length(Result) = 0 then
    raise ESystemTrustUnavailableTlsLibException.CreateResFmt(
      @SSystemTrustEmpty, [SourceName]);
end;

function TSystemRootSource.Snapshot: ITrustAnchorStore;
begin
  // a failed harvest raises here, before any store is built
  Result := TTrustAnchorStore.Create(Harvest) as ITrustAnchorStore;
end;

end.
