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
  TlpArrayUtilities,
  TlpICryptoProvider,
  TlpICertificateTrust,
  TlpSystemTrustExceptions;

type
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
    /// <summary>Appends ADer to ARoots only if the provider confirms it a
    /// well-formed X.509 certificate not already present (exact-byte de-dup for
    /// hashed-symlink directories).</summary>
    procedure AddUnique(var ARoots: TArray<TBytes>; const ADer: TBytes);
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

procedure TSystemTrustBase.AddUnique(var ARoots: TArray<TBytes>;
  const ADer: TBytes);
var
  LI, LN: Integer;
begin
  if not FProvider.Certificates.IsWellFormed(ADer) then
    Exit;

  for LI := 0 to Length(ARoots) - 1 do
  begin
    if TArrayUtilities.AreEqual(ARoots[LI], ADer) then
      Exit;
  end;

  LN := Length(ARoots);
  SetLength(ARoots, LN + 1);
  ARoots[LN] := Copy(ADer, 0, Length(ADer));
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
