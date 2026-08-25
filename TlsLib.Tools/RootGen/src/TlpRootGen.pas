{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpRootGen;

{$IFDEF FPC}
{$MODE DELPHI}
{$H+}
{$ENDIF}

interface

uses
  SysUtils,
  Classes;

type
  /// <summary>
  /// Turns a Mozilla NSS certdata.txt into a compiled-in Pascal roots unit that
  /// exposes an ITrustAnchorStore. Only certificates the file marks trusted for
  /// server authentication (CKT_NSS_TRUSTED_DELEGATOR) are kept; the output is
  /// deterministic (roots sorted by their DER). The tool ships; the root data does
  /// not - point it at a certdata.txt you fetched and refresh on your own cadence.
  /// </summary>
  TRootGenerator = class sealed(TObject)
  strict private
    class function ReadOctalBlock(const ALines: TStringList;
      var AIndex: Integer): TBytes; static;
    class function EncodeBase64(const AData: TBytes): string; static;
    class function PemLines(const ADer: TBytes): TArray<string>; static;
    class function CompareDer(const AA, AB: TBytes): Integer; static;
    class procedure SortRoots(var ARoots: TArray<TBytes>); static;
  public
    /// <summary>The DER of every server-auth-trusted root in ACertData, deterministically
    /// ordered.</summary>
    class function ExtractTrustedRoots(const ACertData: string): TArray<TBytes>; static;
    /// <summary>The source of a Pascal unit named AUnitName exposing
    /// T&lt;AUnitName&gt;.AnchorStore(provider): ITrustAnchorStore over ARoots.</summary>
    class function GenerateUnit(const ARoots: TArray<TBytes>;
      const AUnitName: string): string; static;
    /// <summary>Reads ACertDataPath, writes the generated unit to AOutputPath. Returns 0
    /// on success, non-zero on error (message written to the console).</summary>
    class function Run(const ACertDataPath, AOutputPath,
      AUnitName: string): Integer; static;
  end;

implementation

const
  CBase64 =
    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  CClassCertificate = 1;
  CClassTrust = 2;

{ TRootGenerator }

class function TRootGenerator.ReadOctalBlock(const ALines: TStringList;
  var AIndex: Integer): TBytes;
var
  LLine: string;
  LI, LDigit, LValue, LN: Integer;
begin
  Result := nil;
  LN := 0;
  // AIndex is on the "... MULTILINE_OCTAL" line; consume following lines to END
  Inc(AIndex);
  while AIndex < ALines.Count do
  begin
    LLine := Trim(ALines[AIndex]);
    if LLine = 'END' then
      Break;
    LI := 1;
    while LI <= Length(LLine) do
    begin
      if LLine[LI] = '\' then
      begin
        LValue := 0;
        LDigit := 0;
        Inc(LI);
        while (LDigit < 3) and (LI <= Length(LLine)) and
          (LLine[LI] >= '0') and (LLine[LI] <= '7') do
        begin
          LValue := (LValue shl 3) or (Ord(LLine[LI]) - Ord('0'));
          Inc(LI);
          Inc(LDigit);
        end;
        SetLength(Result, LN + 1);
        Result[LN] := Byte(LValue);
        Inc(LN);
      end
      else
        Inc(LI);
    end;
    Inc(AIndex);
  end;
end;

class function TRootGenerator.ExtractTrustedRoots(
  const ACertData: string): TArray<TBytes>;
var
  LLines: TStringList;
  LI, LJ, LN: Integer;
  LLine: string;
  LCurClass: Integer;
  LCurDer, LCurIssuer, LCurSerial: TBytes;
  LCurTrusted, LFound: Boolean;
  LCertDers: TArray<TBytes>;
  LCertIssuers, LCertSerials: TArray<TBytes>;
  LTrustIssuers, LTrustSerials: TArray<TBytes>;

  // NSS keys a trust record to its certificate by (CKA_ISSUER, CKA_SERIAL_NUMBER) -
  // the canonical identity present on both objects - not by the display CKA_LABEL,
  // which is neither unique nor guaranteed to match between a cert and its trust.
  procedure FinalizeObject;
  var
    LK: Integer;
  begin
    if (LCurClass = CClassCertificate) and (Length(LCurDer) > 0) and
      (Length(LCurIssuer) > 0) and (Length(LCurSerial) > 0) then
    begin
      LK := Length(LCertDers);
      SetLength(LCertDers, LK + 1);
      SetLength(LCertIssuers, LK + 1);
      SetLength(LCertSerials, LK + 1);
      LCertDers[LK] := LCurDer;
      LCertIssuers[LK] := LCurIssuer;
      LCertSerials[LK] := LCurSerial;
    end
    else if (LCurClass = CClassTrust) and LCurTrusted and
      (Length(LCurIssuer) > 0) and (Length(LCurSerial) > 0) then
    begin
      LK := Length(LTrustIssuers);
      SetLength(LTrustIssuers, LK + 1);
      SetLength(LTrustSerials, LK + 1);
      LTrustIssuers[LK] := LCurIssuer;
      LTrustSerials[LK] := LCurSerial;
    end;
  end;

begin
  Result := nil;
  LLines := TStringList.Create;
  try
    LLines.Text := ACertData;
    LCurClass := 0;
    LCurDer := nil;
    LCurIssuer := nil;
    LCurSerial := nil;
    LCurTrusted := False;
    LI := 0;
    while LI < LLines.Count do
    begin
      LLine := Trim(LLines[LI]);
      if Pos('CKA_CLASS', LLine) = 1 then
      begin
        FinalizeObject;
        LCurDer := nil;
        LCurIssuer := nil;
        LCurSerial := nil;
        LCurTrusted := False;
        if Pos('CKO_CERTIFICATE', LLine) > 0 then
          LCurClass := CClassCertificate
        else if Pos('CKO_NSS_TRUST', LLine) > 0 then
          LCurClass := CClassTrust
        else
          LCurClass := 0;
      end
      else if (LCurClass = CClassCertificate) and
        (Pos('CKA_VALUE MULTILINE_OCTAL', LLine) = 1) then
        LCurDer := ReadOctalBlock(LLines, LI)
      else if Pos('CKA_ISSUER MULTILINE_OCTAL', LLine) = 1 then
        LCurIssuer := ReadOctalBlock(LLines, LI)
      else if Pos('CKA_SERIAL_NUMBER MULTILINE_OCTAL', LLine) = 1 then
        LCurSerial := ReadOctalBlock(LLines, LI)
      else if (LCurClass = CClassTrust) and
        (Pos('CKA_TRUST_SERVER_AUTH', LLine) = 1) then
        LCurTrusted := Pos('CKT_NSS_TRUSTED_DELEGATOR', LLine) > 0;
      Inc(LI);
    end;
    FinalizeObject;

    // a certificate is a root iff a trust object with the SAME (issuer, serial),
    // byte-for-byte, marks it a server-auth trusted delegator
    LN := 0;
    for LI := 0 to High(LCertDers) do
    begin
      LFound := False;
      for LJ := 0 to High(LTrustIssuers) do
      begin
        if (CompareDer(LCertIssuers[LI], LTrustIssuers[LJ]) = 0) and
          (CompareDer(LCertSerials[LI], LTrustSerials[LJ]) = 0) then
        begin
          LFound := True;
          Break;
        end;
      end;
      if LFound then
      begin
        SetLength(Result, LN + 1);
        Result[LN] := LCertDers[LI];
        Inc(LN);
      end;
    end;
    SortRoots(Result);
  finally
    LLines.Free;
  end;
end;

class function TRootGenerator.CompareDer(const AA, AB: TBytes): Integer;
var
  LI, LMin: Integer;
begin
  LMin := Length(AA);
  if Length(AB) < LMin then
    LMin := Length(AB);
  for LI := 0 to LMin - 1 do
  begin
    if AA[LI] <> AB[LI] then
    begin
      Result := Integer(AA[LI]) - Integer(AB[LI]);
      Exit;
    end;
  end;
  Result := Length(AA) - Length(AB);
end;

class procedure TRootGenerator.SortRoots(var ARoots: TArray<TBytes>);
var
  LI, LJ: Integer;
  LTmp: TBytes;
begin
  // insertion sort: deterministic, dependency-free, ample for ~150 roots
  for LI := 1 to High(ARoots) do
  begin
    LTmp := ARoots[LI];
    LJ := LI - 1;
    while (LJ >= 0) and (CompareDer(ARoots[LJ], LTmp) > 0) do
    begin
      ARoots[LJ + 1] := ARoots[LJ];
      Dec(LJ);
    end;
    ARoots[LJ + 1] := LTmp;
  end;
end;

class function TRootGenerator.EncodeBase64(const AData: TBytes): string;
var
  LSb: TStringBuilder;
  LI, LLen, LRem: Integer;
  LB0, LB1, LB2: Byte;
begin
  LSb := TStringBuilder.Create;
  try
    LLen := Length(AData);
    LI := 0;
    while LI + 3 <= LLen do
    begin
      LB0 := AData[LI];
      LB1 := AData[LI + 1];
      LB2 := AData[LI + 2];
      LSb.Append(CBase64[(LB0 shr 2) + 1]);
      LSb.Append(CBase64[(((LB0 and 3) shl 4) or (LB1 shr 4)) + 1]);
      LSb.Append(CBase64[(((LB1 and 15) shl 2) or (LB2 shr 6)) + 1]);
      LSb.Append(CBase64[(LB2 and 63) + 1]);
      Inc(LI, 3);
    end;
    LRem := LLen - LI;
    if LRem = 1 then
    begin
      LB0 := AData[LI];
      LSb.Append(CBase64[(LB0 shr 2) + 1]);
      LSb.Append(CBase64[((LB0 and 3) shl 4) + 1]);
      LSb.Append('==');
    end
    else if LRem = 2 then
    begin
      LB0 := AData[LI];
      LB1 := AData[LI + 1];
      LSb.Append(CBase64[(LB0 shr 2) + 1]);
      LSb.Append(CBase64[(((LB0 and 3) shl 4) or (LB1 shr 4)) + 1]);
      LSb.Append(CBase64[((LB1 and 15) shl 2) + 1]);
      LSb.Append('=');
    end;
    Result := LSb.ToString;
  finally
    LSb.Free;
  end;
end;

class function TRootGenerator.PemLines(const ADer: TBytes): TArray<string>;
var
  LB64: string;
  LI, LN: Integer;
begin
  Result := nil;
  LB64 := EncodeBase64(ADer);
  SetLength(Result, 1);
  Result[0] := '-----BEGIN CERTIFICATE-----';
  LN := 1;
  LI := 1;
  while LI <= Length(LB64) do
  begin
    SetLength(Result, LN + 1);
    Result[LN] := Copy(LB64, LI, 64);
    Inc(LN);
    Inc(LI, 64);
  end;
  SetLength(Result, LN + 1);
  Result[LN] := '-----END CERTIFICATE-----';
end;

class function TRootGenerator.GenerateUnit(const ARoots: TArray<TBytes>;
  const AUnitName: string): string;
var
  LSb: TStringBuilder;
  LClass: string;
  LI, LJ, LTotal, LEmitted: Integer;
  LPem: TArray<string>;

  procedure AppendLine(const AText: string);
  begin
    LSb.Append(AText).Append(sLineBreak);
  end;

begin
  LClass := 'T' + AUnitName;
  // count total PEM lines to size the const array
  LTotal := 0;
  for LI := 0 to High(ARoots) do
    LTotal := LTotal + Length(PemLines(ARoots[LI]));

  LSb := TStringBuilder.Create;
  try
    AppendLine('{ Generated by TlsLib.Tools.RootGen - do not edit by hand. }');
    AppendLine('{ Regenerate from a Mozilla certdata.txt; the root data is not vendored. }');
    AppendLine('');
    AppendLine('unit ' + AUnitName + ';');
    AppendLine('');
    AppendLine('{$IFDEF FPC}');
    AppendLine('{$MODE DELPHI}');
    AppendLine('{$H+}');
    AppendLine('{$ENDIF}');
    AppendLine('');
    AppendLine('interface');
    AppendLine('');
    AppendLine('uses');
    AppendLine('  TlpICryptoProvider,');
    AppendLine('  TlpICertificateTrust;');
    AppendLine('');
    AppendLine('type');
    AppendLine('  ' + LClass + ' = class sealed(TObject)');
    AppendLine('  public');
    AppendLine('    class function AnchorStore(const AProvider: ICryptoProvider)');
    AppendLine('      : ITrustAnchorStore; static;');
    AppendLine('  end;');
    AppendLine('');
    AppendLine('implementation');
    AppendLine('');
    AppendLine('uses');
    AppendLine('  SysUtils,');
    AppendLine('  TlpCertificateVerifier;');
    AppendLine('');
    AppendLine('const');
    AppendLine('  CPemLines: array [0 .. ' + IntToStr(LTotal - 1) +
      '] of string = (');

    LEmitted := 0;
    for LI := 0 to High(ARoots) do
    begin
      LPem := PemLines(ARoots[LI]);
      for LJ := 0 to High(LPem) do
      begin
        Inc(LEmitted);
        if LEmitted < LTotal then
          AppendLine('    ''' + LPem[LJ] + ''',')
        else
          AppendLine('    ''' + LPem[LJ] + '''');
      end;
    end;
    AppendLine('  );');
    AppendLine('');
    AppendLine('{ ' + LClass + ' }');
    AppendLine('');
    AppendLine('class function ' + LClass +
      '.AnchorStore(const AProvider: ICryptoProvider): ITrustAnchorStore;');
    AppendLine('var');
    AppendLine('  LBuilder: TStringBuilder;');
    AppendLine('  LI: Integer;');
    AppendLine('begin');
    AppendLine('  LBuilder := TStringBuilder.Create;');
    AppendLine('  try');
    AppendLine('    for LI := 0 to System.High(CPemLines) do');
    AppendLine('      LBuilder.Append(CPemLines[LI]).Append(#10);');
    AppendLine('    Result := TTrustAnchorStore.Create(');
    AppendLine('      AProvider.Certificates.LoadChain(');
    AppendLine('        TEncoding.ASCII.GetBytes(LBuilder.ToString)))');
    AppendLine('      as ITrustAnchorStore;');
    AppendLine('  finally');
    AppendLine('    LBuilder.Free;');
    AppendLine('  end;');
    AppendLine('end;');
    AppendLine('');
    AppendLine('end.');
    Result := LSb.ToString;
  finally
    LSb.Free;
  end;
end;

class function TRootGenerator.Run(const ACertDataPath, AOutputPath,
  AUnitName: string): Integer;
var
  LInput: TStringList;
  LOutput: TStringList;
  LRoots: TArray<TBytes>;
begin
  if not FileExists(ACertDataPath) then
  begin
    WriteLn('error: certdata file not found: ', ACertDataPath);
    Result := 2;
    Exit;
  end;

  LInput := TStringList.Create;
  try
    LInput.LoadFromFile(ACertDataPath);
    LRoots := ExtractTrustedRoots(LInput.Text);
  finally
    LInput.Free;
  end;

  if Length(LRoots) = 0 then
  begin
    WriteLn('error: no server-auth-trusted roots found in ', ACertDataPath);
    Result := 3;
    Exit;
  end;

  LOutput := TStringList.Create;
  try
    LOutput.Text := GenerateUnit(LRoots, AUnitName);
    LOutput.SaveToFile(AOutputPath);
  finally
    LOutput.Free;
  end;

  WriteLn('generated ', AOutputPath, ' with ', Length(LRoots), ' trusted roots');
  Result := 0;
end;

end.
