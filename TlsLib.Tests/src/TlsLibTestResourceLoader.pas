{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlsLibTestResourceLoader;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  SysUtils;

type
  /// <summary>
  /// Locates test vectors in TlsLib.Tests\Data at runtime (files, never string
  /// literals). The data root is discovered by walking up from the current
  /// directory until a TlsLib.Tests\Data folder is found.
  /// </summary>
  TTlsLibTestResourceLoader = class sealed(TObject)
  strict private
    class var FDataRoot: string;
    class function DiscoverDataRoot: string; static;
    class function ResolveDataRoot: string; static;
  public
    /// <summary>The absolute path to TlsLib.Tests\Data (discovered once).</summary>
    class function DataRoot: string; static;
    /// <summary>Absolute path of a vector given its Data-relative path.</summary>
    class function ResourcePath(const ARelativePath: string): string; static;
  end;

implementation

const
  TestsProjectName = 'TlsLib.Tests';
  TestsDataFolderName = 'Data';

resourcestring
  SDataRootNotFound =
    'could not locate the %s%s%s test-data folder by walking up from %s';

class function TTlsLibTestResourceLoader.DiscoverDataRoot: string;
var
  LDir, LCandidate, LParent: string;
  LI: Int32;
begin
  Result := '';
  LDir := ExcludeTrailingPathDelimiter(GetCurrentDir);
  for LI := 0 to 12 do
  begin
    if LDir = '' then
      Break;
    LCandidate := IncludeTrailingPathDelimiter(LDir) + TestsProjectName +
      PathDelim + TestsDataFolderName;
    if DirectoryExists(LCandidate) then
      Exit(ExcludeTrailingPathDelimiter(LCandidate));
    LParent := ExcludeTrailingPathDelimiter(ExtractFilePath(LDir));
    if (LParent = '') or SameText(LParent, LDir) then
      Break;
    LDir := LParent;
  end;
end;

class function TTlsLibTestResourceLoader.ResolveDataRoot: string;
begin
  if FDataRoot = '' then
    FDataRoot := DiscoverDataRoot;
  if FDataRoot = '' then
    raise Exception.CreateResFmt(@SDataRootNotFound,
      [TestsProjectName, PathDelim, TestsDataFolderName, GetCurrentDir]);
  Result := FDataRoot;
end;

class function TTlsLibTestResourceLoader.DataRoot: string;
begin
  Result := ResolveDataRoot;
end;

class function TTlsLibTestResourceLoader.ResourcePath(const ARelativePath: string): string;
var
  LRel: string;
begin
  LRel := StringReplace(ARelativePath, '/', PathDelim, [rfReplaceAll]);
  LRel := StringReplace(LRel, '\', PathDelim, [rfReplaceAll]);
  Result := IncludeTrailingPathDelimiter(ResolveDataRoot) + LRel;
end;

end.
