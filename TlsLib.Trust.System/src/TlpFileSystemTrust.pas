{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpFileSystemTrust;

{$I ..\..\TlsLib\src\Include\TlsLib.inc}

interface

uses
  SysUtils,
  Classes,
  TlpICryptoProvider,
  TlpSystemTrustBase,
  TlpSystemTrustExceptions;

type
  /// <summary>
  /// Harvests trusted roots from the well-known Unix CA-bundle filesystem convention: an
  /// SSL_CERT_FILE / SSL_CERT_DIR style environment override, else the first
  /// well-known CA bundle file or certificate directory that exists. The chosen
  /// source is authoritative: if it cannot be parsed the harvest fails closed
  /// rather than falling through to a different store. PEM parsing is delegated
  /// to the crypto provider.
  ///
  /// The path resolution is platform-neutral - it only manipulates strings and
  /// files - so this store is driven with injected path lists on any host, and
  /// is the reusable engine every filesystem-based platform builds on (see
  /// TUnixAnchorStore for the Unix env + path defaults).
  /// </summary>
  TFileSystemAnchorStore = class(TSystemTrustBase)
  strict private
    FEnvFile: string;
    FEnvDir: string;
    FFiles: TArray<string>;
    FDirs: TArray<string>;

    class function ReadAllBytes(const APath: string): TBytes; static;
    function ParseBundle(const AData: TBytes): TArray<TBytes>;
    procedure HarvestFile(const APath: string;
      const AAccumulator: TSystemRootAccumulator);
    procedure HarvestDir(const APath: string;
      const AAccumulator: TSystemRootAccumulator);
    function FirstExistingFile: string;
    function FirstExistingDir: string;
  strict protected
    function HarvestRoots: TArray<TBytes>; override;
    function SourceName: string; override;
  public
    /// <summary>The explicit form: the env overrides and candidate lists are all
    /// supplied, decoupled from the process environment and any built-in table.
    /// This is the form tests and advanced callers use.</summary>
    constructor Create(const AProvider: ICryptoProvider;
      const AEnvFile, AEnvDir: string;
      const AFiles, ADirs: TArray<string>); overload;
  end;

implementation

resourcestring
  SEnvFileMissing =
    'the SSL_CERT_FILE override names a bundle that could not be read: %s';
  SEnvDirMissing =
    'the SSL_CERT_DIR override names a directory that does not exist: %s';
  SBundleUnreadable =
    'the system CA bundle could not be parsed: %s';

{ TFileSystemAnchorStore }

constructor TFileSystemAnchorStore.Create(const AProvider: ICryptoProvider;
  const AEnvFile, AEnvDir: string; const AFiles, ADirs: TArray<string>);
begin
  inherited Create(AProvider);
  FEnvFile := AEnvFile;
  FEnvDir := AEnvDir;
  FFiles := AFiles;
  FDirs := ADirs;
end;

class function TFileSystemAnchorStore.ReadAllBytes(const APath: string): TBytes;
var
  LStream: TMemoryStream;
begin
  Result := nil;
  LStream := TMemoryStream.Create;
  try
    LStream.LoadFromFile(APath);
    SetLength(Result, LStream.Size);
    if LStream.Size > 0 then
      Move(LStream.Memory^, Result[0], LStream.Size);
  finally
    LStream.Free;
  end;
end;

function TFileSystemAnchorStore.ParseBundle(const AData: TBytes): TArray<TBytes>;
begin
  if Length(AData) = 0 then
    Result := nil
  else
    Result := Provider.Certificates.LoadChain(AData);
end;

procedure TFileSystemAnchorStore.HarvestFile(const APath: string;
  const AAccumulator: TSystemRootAccumulator);
var
  LCerts: TArray<TBytes>;
  LI: Integer;
begin
  try
    LCerts := ParseBundle(ReadAllBytes(APath));
  except
    on E: Exception do
      raise ESystemTrustUnavailableTlsLibException.CreateResFmt(
        @SBundleUnreadable, [APath]);
  end;

  for LI := 0 to Length(LCerts) - 1 do
    AddUnique(AAccumulator, LCerts[LI]);
end;

procedure TFileSystemAnchorStore.HarvestDir(const APath: string;
  const AAccumulator: TSystemRootAccumulator);
var
  LSearch: TSearchRec;
  LBase, LFull: string;
  LCerts: TArray<TBytes>;
  LI: Integer;
begin
  LBase := IncludeTrailingPathDelimiter(APath);
  if FindFirst(LBase + '*', faAnyFile, LSearch) <> 0 then
    Exit;
  try
    repeat
      if (LSearch.Attr and faDirectory) <> 0 then
        Continue;
      LFull := LBase + LSearch.Name;
      // A certificate directory can also hold CRLs, indexes and other non-PEM
      // files; tolerate per-file parse failures and keep the certificates found.
      try
        LCerts := ParseBundle(ReadAllBytes(LFull));
      except
        LCerts := nil;
      end;
      for LI := 0 to Length(LCerts) - 1 do
        AddUnique(AAccumulator, LCerts[LI]);
    until FindNext(LSearch) <> 0;
  finally
    FindClose(LSearch);
  end;
end;

function TFileSystemAnchorStore.FirstExistingFile: string;
var
  LI: Integer;
begin
  Result := '';
  for LI := 0 to Length(FFiles) - 1 do
  begin
    if FileExists(FFiles[LI]) then
    begin
      Result := FFiles[LI];
      Exit;
    end;
  end;
end;

function TFileSystemAnchorStore.FirstExistingDir: string;
var
  LI: Integer;
begin
  Result := '';
  for LI := 0 to Length(FDirs) - 1 do
  begin
    if DirectoryExists(FDirs[LI]) then
    begin
      Result := FDirs[LI];
      Exit;
    end;
  end;
end;

function TFileSystemAnchorStore.HarvestRoots: TArray<TBytes>;
var
  LFile, LDir: string;
  LAcc: TSystemRootAccumulator;
begin
  Result := nil;
  LAcc := TSystemRootAccumulator.Create;
  try
    // Explicit environment overrides take precedence and are strict: if named, the
    // source must be usable, otherwise fail closed (no fallback to the table).
    if FEnvFile <> '' then
    begin
      if not FileExists(FEnvFile) then
        raise ESystemTrustUnavailableTlsLibException.CreateResFmt(
          @SEnvFileMissing, [FEnvFile]);
      HarvestFile(FEnvFile, LAcc);
    end
    else if FEnvDir <> '' then
    begin
      if not DirectoryExists(FEnvDir) then
        raise ESystemTrustUnavailableTlsLibException.CreateResFmt(
          @SEnvDirMissing, [FEnvDir]);
      HarvestDir(FEnvDir, LAcc);
    end
    // Otherwise the first candidate that exists is authoritative.
    else
    begin
      LFile := FirstExistingFile;
      if LFile <> '' then
        HarvestFile(LFile, LAcc)
      else
      begin
        LDir := FirstExistingDir;
        if LDir <> '' then
          HarvestDir(LDir, LAcc);
        // If nothing existed, the accumulator stays empty and the base fails closed.
      end;
    end;
    Result := LAcc.ToArray;
  finally
    LAcc.Free;
  end;
end;

function TFileSystemAnchorStore.SourceName: string;
begin
  Result := 'filesystem';
end;

end.
