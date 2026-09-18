{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit InteropUtils;

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

interface

uses
  SysUtils,
  StrUtils,
  Classes;

type
  /// <summary>A malformed vector/PEM/hex input in the interop harness.</summary>
  EInteropData = class(Exception);

  /// <summary>
  /// The process command-line arguments, read so that raw bytes survive. The BoGo
  /// runner passes some flag values as length-prefixed wire octets (e.g. an ALPN list
  /// <c>#3'foo'#3'bar'</c>), whose control-byte prefixes FPC's ParamStr drops on Windows
  /// (it routes the command line through a text codepage). On Windows this reads the raw
  /// UTF-16 command line via CommandLineToArgvW and maps each code unit straight to a
  /// byte; elsewhere it defers to ParamStr. Indexing matches ParamStr: 0 is the program.
  /// </summary>
  TInteropArgs = class sealed(TObject)
  strict private
    class var FArgs: TArray<string>;
    class var FLoaded: Boolean;
    class procedure EnsureLoaded; static;
  public
    /// <summary>The argument count, excluding the program name (like ParamCount).</summary>
    class function Count: Int32; static;
    /// <summary>Argument AIndex with its bytes intact; 0 is the program (like ParamStr).</summary>
    class function Get(AIndex: Int32): string; static;
  end;

  /// <summary>Standalone (no test-framework) helpers the interop programs share.</summary>
  TInteropUtils = class sealed(TObject)
  public
    /// <summary>Decodes a whitespace-tolerant hex string into bytes.</summary>
    class function DecodeHex(const AHex: string): TBytes; static;
    /// <summary>Decodes standard base64 (whitespace tolerant) into bytes.</summary>
    class function DecodeBase64(const AText: string): TBytes; static;
    /// <summary>Decodes the first PEM block of AText (any label) into DER bytes.</summary>
    class function PemToDer(const AText: string): TBytes; static;
    /// <summary>Loads KEY=hexvalue lines (# comments) from AFile into AFields.</summary>
    class procedure LoadFieldFile(const AFile: string; AFields: TStrings); static;
    /// <summary>Reads a whole file as text.</summary>
    class function ReadAllText(const AFile: string): string; static;
    /// <summary>Reads a whole file as raw bytes (e.g. a DER OCSP response).</summary>
    class function ReadAllBytes(const AFile: string): TBytes; static;
    /// <summary>Concatenates two byte slices.</summary>
    class function Concat(const A, B: TBytes): TBytes; static;
    /// <summary>Whether two byte slices have the same length and contents.</summary>
    class function BytesEqual(const A, B: TBytes): Boolean; static;
    /// <summary>
    /// Locates the interop Data directory: honors the INTEROP_DATA environment
    /// variable, else walks up from the executable and the working directory for a
    /// "TlsLib.Interop/Data" (or a bare "Data") folder.
    /// </summary>
    class function LocateDataDir: string; static;
  end;

implementation

{$IFDEF MSWINDOWS}
type
  PPWideChar = ^PWideChar;

// pulled in directly (not via the Windows unit, whose GetEnvironmentVariable overload
// would shadow the SysUtils one this unit relies on)
function GetCommandLineW: PWideChar; stdcall;
  external 'kernel32' name 'GetCommandLineW';
function CommandLineToArgvW(ALine: PWideChar; var ANumArgs: Integer): PPWideChar; stdcall;
  external 'shell32' name 'CommandLineToArgvW';
function LocalFree(AMem: Pointer): Pointer; stdcall;
  external 'kernel32' name 'LocalFree';
{$ENDIF MSWINDOWS}

{ TInteropArgs }

class procedure TInteropArgs.EnsureLoaded;
{$IFDEF MSWINDOWS}
var
  LArgv: PPWideChar;
  LArgc, LI, LJ: Integer;
  LWide: PWideChar;
  LArg: string;
begin
  if FLoaded then
    Exit;
  // read the raw UTF-16 command line and split it with the same rules the runner's Go
  // exec quoted it under (CommandLineToArgvW), then map each code unit to a single byte -
  // the length-prefix octets the ALPN/QUIC wire flags carry survive intact, whereas the
  // codepage ParamStr routes through would drop them
  LArgv := CommandLineToArgvW(GetCommandLineW, LArgc);
  if LArgv = nil then
  begin
    SetLength(FArgs, ParamCount + 1);
    for LI := 0 to ParamCount do
      FArgs[LI] := ParamStr(LI);
    FLoaded := True;
    Exit;
  end;
  try
    SetLength(FArgs, LArgc);
    for LI := 0 to LArgc - 1 do
    begin
      LWide := PPWideChar(PByte(LArgv) + LI * SizeOf(PWideChar))^;
      LArg := '';
      LJ := 0;
      while LWide[LJ] <> #0 do
      begin
        // low byte only: the wire values are ASCII plus control-byte prefixes (< 0x100)
        LArg := LArg + Char(Byte(Word(LWide[LJ]) and $FF));
        Inc(LJ);
      end;
      FArgs[LI] := LArg;
    end;
  finally
    LocalFree(Pointer(LArgv));
  end;
  FLoaded := True;
end;
{$ELSE MSWINDOWS}
var
  LI: Integer;
begin
  if FLoaded then
    Exit;
  // POSIX argv is already raw bytes; ParamStr preserves them
  SetLength(FArgs, ParamCount + 1);
  for LI := 0 to ParamCount do
    FArgs[LI] := ParamStr(LI);
  FLoaded := True;
end;
{$ENDIF MSWINDOWS}

class function TInteropArgs.Count: Int32;
begin
  EnsureLoaded;
  Result := System.Length(FArgs) - 1;
end;

class function TInteropArgs.Get(AIndex: Int32): string;
begin
  EnsureLoaded;
  if (AIndex < 0) or (AIndex > System.High(FArgs)) then
    Result := ''
  else
    Result := FArgs[AIndex];
end;

{ TInteropUtils }

class function TInteropUtils.DecodeHex(const AHex: string): TBytes;
var
  LClean: string;
  LI, LN: Int32;
  LCh: Char;

  function NibbleOf(ACh: Char): Int32;
  begin
    case ACh of
      '0' .. '9':
        Result := Ord(ACh) - Ord('0');
      'a' .. 'f':
        Result := 10 + Ord(ACh) - Ord('a');
      'A' .. 'F':
        Result := 10 + Ord(ACh) - Ord('A');
    else
      Result := -1;
    end;
  end;

begin
  Result := nil;
  LClean := '';
  for LI := 1 to System.Length(AHex) do
  begin
    LCh := AHex[LI];
    if NibbleOf(LCh) >= 0 then
      LClean := LClean + LCh
    else if (LCh <> ' ') and (LCh <> #9) and (LCh <> #10) and (LCh <> #13) then
      raise EInteropData.CreateFmt('invalid hex character: %s', [LCh]);
  end;
  if System.Length(LClean) mod 2 <> 0 then
    raise EInteropData.Create('hex string has an odd length');
  SetLength(Result, System.Length(LClean) div 2);
  LN := 0;
  LI := 1;
  while LI < System.Length(LClean) do
  begin
    Result[LN] := (NibbleOf(LClean[LI]) shl 4) or NibbleOf(LClean[LI + 1]);
    Inc(LN);
    Inc(LI, 2);
  end;
end;

class function TInteropUtils.DecodeBase64(const AText: string): TBytes;
const
  Pad = Ord('=');
var
  LI, LBits, LAcc, LOut: Int32;
  LVal: Int32;
  LCh: Char;

  function SextetOf(ACh: Char): Int32;
  begin
    case ACh of
      'A' .. 'Z':
        Result := Ord(ACh) - Ord('A');
      'a' .. 'z':
        Result := 26 + Ord(ACh) - Ord('a');
      '0' .. '9':
        Result := 52 + Ord(ACh) - Ord('0');
      '+':
        Result := 62;
      '/':
        Result := 63;
    else
      Result := -1;
    end;
  end;

begin
  Result := nil;
  SetLength(Result, System.Length(AText)); // upper bound; trimmed below
  LOut := 0;
  LAcc := 0;
  LBits := 0;
  for LI := 1 to System.Length(AText) do
  begin
    LCh := AText[LI];
    if Ord(LCh) = Pad then
      Break;
    LVal := SextetOf(LCh);
    if LVal < 0 then
      Continue; // skip newlines and any framing whitespace
    LAcc := (LAcc shl 6) or LVal;
    Inc(LBits, 6);
    if LBits >= 8 then
    begin
      Dec(LBits, 8);
      Result[LOut] := (LAcc shr LBits) and $FF;
      Inc(LOut);
    end;
  end;
  SetLength(Result, LOut);
end;

class function TInteropUtils.PemToDer(const AText: string): TBytes;
var
  LStart, LEnd: Int32;
  LBody: string;
const
  BeginMark = '-----BEGIN';
  EndMark = '-----END';
begin
  Result := nil;
  LStart := Pos(BeginMark, AText);
  if LStart = 0 then
    raise EInteropData.Create('no PEM BEGIN marker found');
  // skip past the end of the BEGIN line
  LStart := PosEx(#10, AText, LStart);
  if LStart = 0 then
    raise EInteropData.Create('malformed PEM header');
  LEnd := PosEx(EndMark, AText, LStart);
  if LEnd = 0 then
    raise EInteropData.Create('no PEM END marker found');
  LBody := System.Copy(AText, LStart + 1, LEnd - LStart - 1);
  Result := DecodeBase64(LBody);
end;

class procedure TInteropUtils.LoadFieldFile(const AFile: string; AFields: TStrings);
var
  LLines: TStringList;
  LI, LEq: Int32;
  LLine, LKey, LValue: string;
begin
  AFields.Clear;
  LLines := TStringList.Create;
  try
    LLines.LoadFromFile(AFile);
    for LI := 0 to LLines.Count - 1 do
    begin
      LLine := Trim(LLines[LI]);
      if (LLine = '') or (LLine[1] = '#') then
        Continue;
      LEq := Pos('=', LLine);
      if LEq = 0 then
        Continue;
      LKey := Trim(System.Copy(LLine, 1, LEq - 1));
      LValue := Trim(System.Copy(LLine, LEq + 1, System.Length(LLine) - LEq));
      AFields.Values[LKey] := LValue;
    end;
  finally
    LLines.Free;
  end;
end;

class function TInteropUtils.ReadAllText(const AFile: string): string;
var
  LList: TStringList;
begin
  LList := TStringList.Create;
  try
    LList.LoadFromFile(AFile);
    Result := LList.Text;
  finally
    LList.Free;
  end;
end;

class function TInteropUtils.ReadAllBytes(const AFile: string): TBytes;
var
  LStream: TFileStream;
begin
  LStream := TFileStream.Create(AFile, fmOpenRead or fmShareDenyWrite);
  try
    SetLength(Result, LStream.Size);
    if LStream.Size > 0 then
      LStream.ReadBuffer(Result[0], LStream.Size);
  finally
    LStream.Free;
  end;
end;

class function TInteropUtils.Concat(const A, B: TBytes): TBytes;
begin
  Result := nil;
  SetLength(Result, System.Length(A) + System.Length(B));
  if System.Length(A) > 0 then
    Move(A[0], Result[0], System.Length(A));
  if System.Length(B) > 0 then
    Move(B[0], Result[System.Length(A)], System.Length(B));
end;

class function TInteropUtils.BytesEqual(const A, B: TBytes): Boolean;
begin
  // a plain (variable-time) compare: these are public OCSP bytes, not secrets. The
  // length guard also keeps @A[0] valid - it is never taken on an empty array.
  Result := (System.Length(A) = System.Length(B)) and
    ((System.Length(A) = 0) or CompareMem(@A[0], @B[0], System.Length(A)));
end;

class function TInteropUtils.LocateDataDir: string;
const
  Marker = 'Certs' + PathDelim + 'EcP256Chain.txt';
var
  LBases: TArray<string>;
  LBase, LProbe, LUps: string;
  LDepth, LI: Int32;

  function TryBase(const ADir: string): Boolean;
  begin
    Result := False;
    LProbe := IncludeTrailingPathDelimiter(ADir) + 'Data' + PathDelim;
    if FileExists(LProbe + Marker) then
    begin
      LocateDataDir := ExcludeTrailingPathDelimiter(LProbe);
      Exit(True);
    end;
    LProbe := IncludeTrailingPathDelimiter(ADir) + 'TlsLib.Interop' + PathDelim +
      'Data' + PathDelim;
    if FileExists(LProbe + Marker) then
    begin
      LocateDataDir := ExcludeTrailingPathDelimiter(LProbe);
      Exit(True);
    end;
  end;

begin
  Result := GetEnvironmentVariable('INTEROP_DATA');
  if (Result <> '') and DirectoryExists(Result) then
    Exit;
  LBases := TArray<string>.Create(ExtractFilePath(ParamStr(0)),
    IncludeTrailingPathDelimiter(GetCurrentDir));
  // walk each base and its ancestors looking for a Data (or TlsLib.Interop/Data) dir
  for LI := 0 to System.High(LBases) do
  begin
    LUps := '';
    for LDepth := 0 to 5 do
    begin
      LBase := LBases[LI] + LUps;
      if TryBase(LBase) then
        Exit;
      LUps := LUps + '..' + PathDelim;
    end;
  end;
  raise EInteropData.Create('could not locate the interop Data directory ' +
    '(set INTEROP_DATA)');
end;

end.
