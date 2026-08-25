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
  SyncObjs,
  Generics.Collections,
  TlpICryptoProvider,
  TlpICertificateTrust,
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
  /// Abstract base for the platform trust-anchor harvesters. Caches the harvested
  /// roots behind a lock (refreshable), validates each blob is a well-formed DER
  /// certificate, and de-duplicates. Fail-closed: an empty harvest raises rather
  /// than presenting an empty anchor set. Subclasses override HarvestRoots.
  /// </summary>
  TSystemTrustBase = class abstract(TInterfacedObject, ITrustAnchorStore)
  strict private
    FLock: TCriticalSection;
    FProvider: ICryptoProvider;
    FRoots: TArray<TBytes>;
    FLoaded: Boolean;
    class function CloneRoots(const ARoots: TArray<TBytes>): TArray<TBytes>; static;
  strict protected
    /// <summary>Gather the platform's trusted roots as DER. May return empty; the
    /// base turns an empty result into a fail-closed error.</summary>
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
    destructor Destroy; override;

    function RootCertificates: TArray<TBytes>;
    /// <summary>Discards the cache so the next access re-harvests the OS store.</summary>
    procedure Refresh;
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

{ TSystemTrustBase }

constructor TSystemTrustBase.Create(const AProvider: ICryptoProvider);
begin
  inherited Create;
  if AProvider = nil then
    raise ESystemTrustUnavailableTlsLibException.CreateRes(@SNoProvider);
  FProvider := AProvider;
  FLock := TCriticalSection.Create;
  FLoaded := False;
end;

destructor TSystemTrustBase.Destroy;
begin
  FLock.Free;
  inherited Destroy;
end;

procedure TSystemTrustBase.AddUnique(const AAccumulator: TSystemRootAccumulator;
  const ADer: TBytes);
begin
  if not FProvider.Certificates.IsWellFormed(ADer) then
    Exit;
  AAccumulator.Add(ADer);
end;

class function TSystemTrustBase.CloneRoots(
  const ARoots: TArray<TBytes>): TArray<TBytes>;
var
  LI: Integer;
begin
  Result := nil;
  SetLength(Result, Length(ARoots));
  for LI := 0 to Length(ARoots) - 1 do
    Result[LI] := Copy(ARoots[LI], 0, Length(ARoots[LI]));
end;

function TSystemTrustBase.RootCertificates: TArray<TBytes>;
begin
  FLock.Enter;
  try
    if not FLoaded then
    begin
      FRoots := HarvestRoots;
      FLoaded := True;
    end;

    if Length(FRoots) = 0 then
      raise ESystemTrustUnavailableTlsLibException.CreateResFmt(
        @SSystemTrustEmpty, [SourceName]);

    Result := CloneRoots(FRoots);
  finally
    FLock.Leave;
  end;
end;

procedure TSystemTrustBase.Refresh;
begin
  FLock.Enter;
  try
    FRoots := nil;
    FLoaded := False;
  finally
    FLock.Leave;
  end;
end;

end.
