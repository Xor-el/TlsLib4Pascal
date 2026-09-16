{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpPem;

{$I ..\Include\TlsLib.inc}

interface

uses
  SysUtils,
  TlpDataEncoding,
  TlpTlsLibExceptions;

type
  /// <summary>One PEM block (RFC 7468): its label (e.g. "PRIVATE KEY", "ECHCONFIG") and
  /// the base64-decoded content (opaque bytes - DER for keys and certificates).</summary>
  TPemBlock = record
    PemType: string;
    Content: TBytes;
  end;

  /// <summary>
  /// The generic PEM codec (RFC 7468): reads and writes labeled blocks whose content is
  /// opaque bytes. It is pure text framing (no cryptography), so it lives outside the
  /// crypto provider. Reading ignores explanatory text and RFC 1421 headers.
  /// </summary>
  TPem = class sealed(TObject)
  strict private
  const
    BodyLineLength = Int32(64);
    // splits on CR, LF, or CRLF (input line endings are not assumed to match the platform)
    class function SplitLines(const AText: string): TArray<string>; static;
    // matches "-----AKeyword <label>-----" (any dash run), yielding the trimmed label
    class function TryBoundary(const ALine, AKeyword: string;
      out ALabel: string): Boolean; static;
  public
    /// <summary>
    /// Every PEM block in AData, in order (empty when none). Explanatory text before a
    /// block and RFC 1421 headers are ignored. Raises EArgumentTlsLibException on a
    /// malformed block (unterminated, or a mismatched end label).
    /// </summary>
    class function ReadBlocks(const AData: TBytes): TArray<TPemBlock>; static;
    /// <summary>Serializes ABlocks as PEM (RFC 7468), LF line endings, 64-column body.</summary>
    class function WriteBlocks(const ABlocks: TArray<TPemBlock>): TBytes; static;
    /// <summary>Whether AData is PEM-armored: a "-----BEGIN " boundary at the start of a
    /// line (so binary DER carrying those bytes mid-content does not false-positive).</summary>
    class function IsArmored(const AData: TBytes): Boolean; static;
  end;

implementation

resourcestring
  SMalformedPem = 'the PEM data is malformed';

class function TPem.SplitLines(const AText: string): TArray<string>;
var
  LNorm: string;
  LStart, LI, LCount: Int32;
begin
  Result := nil;
  // fold CRLF and lone CR to LF so every break is a single #10, then cut on #10
  LNorm := StringReplace(AText, #13#10, #10, [rfReplaceAll]);
  LNorm := StringReplace(LNorm, #13, #10, [rfReplaceAll]);
  LCount := 0;
  LStart := 1;
  for LI := 1 to System.Length(LNorm) do
    if LNorm[LI] = #10 then
    begin
      SetLength(Result, LCount + 1);
      Result[LCount] := System.Copy(LNorm, LStart, LI - LStart);
      Inc(LCount);
      LStart := LI + 1;
    end;
  // the final segment (text need not end in a line break)
  SetLength(Result, LCount + 1);
  Result[LCount] := System.Copy(LNorm, LStart, System.Length(LNorm) - LStart + 1);
end;

class function TPem.TryBoundary(const ALine, AKeyword: string;
  out ALabel: string): Boolean;
var
  LS: string;
  LStart, LStop: Int32;
begin
  ALabel := '';
  Result := False;
  LS := Trim(ALine);
  // require and strip a leading dash run
  LStart := 1;
  while (LStart <= System.Length(LS)) and (LS[LStart] = '-') do
    Inc(LStart);
  if LStart = 1 then
    Exit;
  LS := System.Copy(LS, LStart, System.Length(LS));
  // require the keyword and a following space
  if Pos(AKeyword + ' ', LS) <> 1 then
    Exit;
  LS := System.Copy(LS, System.Length(AKeyword) + 2, System.Length(LS));
  // require and strip a trailing dash run
  LStop := System.Length(LS);
  while (LStop >= 1) and (LS[LStop] = '-') do
    Dec(LStop);
  if LStop = System.Length(LS) then
    Exit;
  ALabel := Trim(System.Copy(LS, 1, LStop));
  Result := True;
end;

class function TPem.ReadBlocks(const AData: TBytes): TArray<TPemBlock>;
var
  LLines: TArray<string>;
  LI, LCount: Int32;
  LLabel, LEndLabel, LBody, LTrim: string;
  LTerminated: Boolean;
begin
  Result := nil;
  LCount := 0;
  LLines := SplitLines(TEncoding.ASCII.GetString(AData));
  LI := 0;
  while LI < System.Length(LLines) do
  begin
    if not TryBoundary(LLines[LI], 'BEGIN', LLabel) then
    begin
      Inc(LI);
      Continue;
    end;
    Inc(LI);
    LBody := '';
    LTerminated := False;
    while LI < System.Length(LLines) do
    begin
      if TryBoundary(LLines[LI], 'END', LEndLabel) then
      begin
        if LEndLabel <> LLabel then
          raise EArgumentTlsLibException.CreateRes(@SMalformedPem);
        LTerminated := True;
        Inc(LI);
        Break;
      end;
      // skip blank lines and RFC 1421 headers - base64 never contains a colon
      LTrim := Trim(LLines[LI]);
      if (LTrim <> '') and (Pos(':', LTrim) = 0) then
        LBody := LBody + LTrim;
      Inc(LI);
    end;
    if not LTerminated then
      raise EArgumentTlsLibException.CreateRes(@SMalformedPem);
    SetLength(Result, LCount + 1);
    Result[LCount].PemType := LLabel;
    Result[LCount].Content := TDataEncoding.Base64Decode(LBody);
    Inc(LCount);
  end;
end;

class function TPem.WriteBlocks(const ABlocks: TArray<TPemBlock>): TBytes;
var
  LOut, LB64: string;
  LI, LPos: Int32;
begin
  LOut := '';
  for LI := 0 to System.High(ABlocks) do
  begin
    LOut := LOut + '-----BEGIN ' + ABlocks[LI].PemType + '-----'#10;
    LB64 := TDataEncoding.Base64Encode(ABlocks[LI].Content);
    LPos := 1;
    while LPos <= System.Length(LB64) do
    begin
      LOut := LOut + System.Copy(LB64, LPos, BodyLineLength) + #10;
      Inc(LPos, BodyLineLength);
    end;
    LOut := LOut + '-----END ' + ABlocks[LI].PemType + '-----'#10;
  end;
  Result := TEncoding.ASCII.GetBytes(LOut);
end;

class function TPem.IsArmored(const AData: TBytes): Boolean;
const
  BeginTag: array [0 .. 10] of Byte = (Ord('-'), Ord('-'), Ord('-'), Ord('-'),
    Ord('-'), Ord('B'), Ord('E'), Ord('G'), Ord('I'), Ord('N'), Ord(' '));
var
  LI, LN, LLen: Int32;
  LAtLineStart: Boolean;
begin
  Result := False;
  LN := System.Length(AData);
  LLen := System.Length(BeginTag);
  LI := 0;
  while (LI < LN) and (AData[LI] <= Ord(' ')) do
    Inc(LI);
  // the first non-blank byte begins a line; thereafter a line starts right after each newline
  LAtLineStart := True;
  while LI <= (LN - LLen) do
  begin
    if LAtLineStart and CompareMem(@AData[LI], @BeginTag[0], LLen) then
      Exit(True);
    LAtLineStart := AData[LI] = Ord(#10);
    Inc(LI);
  end;
end;

end.
