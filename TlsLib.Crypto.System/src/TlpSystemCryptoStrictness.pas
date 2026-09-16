{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpSystemCryptoStrictness;

{$I ..\..\TlsLib\src\Include\TlsLib.inc}

interface

uses
  SysUtils,
  TlpArrayUtilities,
  TlpEnumUtilities,
  TlpCryptoDomainTypes,
  TlpSystemCryptoTypes,
  TlpSystemCryptoExceptions,
  TlpICryptoProvider,
  TlpICryptoBackendReport,
  TlpINamedGroup,
  TlpINegotiation,
  TlpNegotiationTypes,
  TlpNamedGroups,
  TlpCipherSuiteRegistry,
  TlpSignatureSchemeRegistry;

type
  /// <summary>
  /// Derives the negotiation registries filtered to only the entries this platform's
  /// OS-native backend actually serves, so a caller can offer OS-backed algorithms only.
  /// It reads the provider's <see cref="ICryptoBackendReport" /> (a provider with none is
  /// wholly portable, so every entry is dropped) and returns a fresh registry plus the
  /// names it removed, for logging. Install the result with the builder's WithNamedGroups /
  /// WithCipherSuites / WithSignatureSchemes seams. Native-vs-portable is decided once at
  /// provider construction, so the filtered set is stable for the provider's lifetime.
  /// </summary>
  TSystemCryptoStrictness = class sealed(TObject)
  strict private
    class function Report(const AProvider: ICryptoProvider): ICryptoBackendReport; static;
    // reads the group's composition via a local (direct field access) and checks each
    // primitive component against the report; a group is served natively when every
    // component it is built from is System-backed (both halves, for a hybrid).
    class function GroupIsNative(const AReport: ICryptoBackendReport;
      const AGroup: INamedGroup): Boolean; static;
    class function CommaList(const AItems: TArray<string>): string; static;
  public
    class function NativeNamedGroups(const AProvider: ICryptoProvider;
      out ADropped: TArray<string>): INamedGroupRegistry; static;
    class function NativeCipherSuites(const AProvider: ICryptoProvider;
      out ADropped: TArray<string>): ICipherSuiteRegistry; static;
    class function NativeSignatureSchemes(const AProvider: ICryptoProvider;
      out ADropped: TArray<string>): ISignatureSchemeRegistry; static;
    /// <summary>Fail-fast startup gates: raise
    /// <see cref="ESystemCryptoRequirementTlsLibException" /> listing every requested entry
    /// the OS-native backend does not serve, or return quietly when all are served.</summary>
    class procedure RequireNamedGroups(const AProvider: ICryptoProvider;
      const ACodes: array of UInt16); static;
    class procedure RequireCipherSuites(const AProvider: ICryptoProvider;
      const ACodes: array of UInt16); static;
    class procedure RequireSignatureSchemes(const AProvider: ICryptoProvider;
      const ASchemes: array of TSignatureScheme); static;
  end;

implementation

resourcestring
  SRequiredGroupsNotNative =
    'these required named groups are not served by the OS-native backend: %s';
  SRequiredSuitesNotNative =
    'these required cipher suites are not served by the OS-native backend: %s';
  SRequiredSchemesNotNative =
    'these required signature schemes are not served by the OS-native backend: %s';

{ TSystemCryptoStrictness }

class function TSystemCryptoStrictness.Report(
  const AProvider: ICryptoProvider): ICryptoBackendReport;
begin
  if not Supports(AProvider, ICryptoBackendReport, Result) then
    Result := nil;
end;

class function TSystemCryptoStrictness.GroupIsNative(
  const AReport: ICryptoBackendReport; const AGroup: INamedGroup): Boolean;
var
  LComp: TNamedGroupComposition;
begin
  if AReport = nil then
    Exit(False);
  LComp := AGroup.Composition;
  case LComp.Kind of
    TNamedGroupKind.Ecdhe:
      Result := AReport.KeyAgreementBackend(LComp.KeyAgreement).Backend =
        TCryptoBackend.System;
    TNamedGroupKind.Kem:
      Result := AReport.KemBackend(LComp.Kem).Backend = TCryptoBackend.System;
    TNamedGroupKind.Hybrid:
      // both halves must be OS-backed; the portable concatenation of the two shared
      // secrets is not a primitive, so it does not disqualify the group
      Result := (AReport.KeyAgreementBackend(LComp.KeyAgreement).Backend =
        TCryptoBackend.System) and
        (AReport.KemBackend(LComp.Kem).Backend = TCryptoBackend.System);
  else
    Result := False;
  end;
end;

class function TSystemCryptoStrictness.NativeNamedGroups(
  const AProvider: ICryptoProvider; out ADropped: TArray<string>): INamedGroupRegistry;
var
  LReport: ICryptoBackendReport;
  LGroup: INamedGroup;
  LCodes: TArray<UInt16>;
  LCode: UInt16;
begin
  ADropped := nil;
  LCodes := nil;
  LReport := Report(AProvider);
  // start from the provider's default registry (a fresh instance) and prune what is not
  // served natively
  Result := TNamedGroups.CreateDefaultRegistry(AProvider);
  for LGroup in Result.Items do
    if not GroupIsNative(LReport, LGroup) then
    begin
      TArrayUtilities.Append<string>(ADropped, LGroup.Name);
      TArrayUtilities.Append<UInt16>(LCodes, LGroup.Code);
    end;
  for LCode in LCodes do
    Result.Prune(LCode);
end;

class function TSystemCryptoStrictness.NativeCipherSuites(
  const AProvider: ICryptoProvider; out ADropped: TArray<string>): ICipherSuiteRegistry;
var
  LReport: ICryptoBackendReport;
  LSuite: TTlsCipherSuite;
  LCodes: TArray<UInt16>;
  LCode: UInt16;
  LNative: Boolean;
begin
  ADropped := nil;
  LCodes := nil;
  LReport := Report(AProvider);
  Result := TCipherSuiteRegistry.CreateDefault(AProvider);
  // a suite is native when both its record-protection hash and its AEAD are System-backed
  for LSuite in Result.Items do
  begin
    LNative := (LReport <> nil) and
      (LReport.HashBackend(LSuite.Common.Hash).Backend = TCryptoBackend.System) and
      (LReport.AeadBackend(LSuite.Common.Aead).Backend = TCryptoBackend.System);
    if not LNative then
    begin
      TArrayUtilities.Append<string>(ADropped, Format('0x%.4x', [LSuite.Common.Code]));
      TArrayUtilities.Append<UInt16>(LCodes, LSuite.Common.Code);
    end;
  end;
  for LCode in LCodes do
    Result.Prune(LCode);
end;

class function TSystemCryptoStrictness.NativeSignatureSchemes(
  const AProvider: ICryptoProvider; out ADropped: TArray<string>): ISignatureSchemeRegistry;
var
  LReport: ICryptoBackendReport;
  LScheme: TSignatureScheme;
  LName: string;
  LCodes: TArray<UInt16>;
  LCode: UInt16;
begin
  ADropped := nil;
  LCodes := nil;
  LReport := Report(AProvider);
  Result := TSignatureSchemeRegistry.CreateDefault;
  for LScheme in Result.Items do
    if (LReport = nil) or
      (LReport.SigningBackend(LScheme).Backend <> TCryptoBackend.System) then
    begin
      LName := TEnumUtilities.GetName<TSignatureScheme>(LScheme);
      TArrayUtilities.Append<string>(ADropped, LName);
      TArrayUtilities.Append<UInt16>(LCodes, LScheme.ToCode);
    end;
  for LCode in LCodes do
    Result.Prune(LCode);
end;

class function TSystemCryptoStrictness.CommaList(const AItems: TArray<string>): string;
var
  LI: Int32;
begin
  Result := '';
  for LI := 0 to System.High(AItems) do
    if LI = 0 then
      Result := AItems[LI]
    else
      Result := Result + ', ' + AItems[LI];
end;

class procedure TSystemCryptoStrictness.RequireNamedGroups(
  const AProvider: ICryptoProvider; const ACodes: array of UInt16);
var
  LNative: INamedGroupRegistry;
  LDropped, LMissing: TArray<string>;
  LI: Int32;
begin
  LNative := NativeNamedGroups(AProvider, LDropped);
  LMissing := nil;
  for LI := 0 to System.High(ACodes) do
    if not LNative.Contains(ACodes[LI]) then
      TArrayUtilities.Append<string>(LMissing, Format('0x%.4x', [ACodes[LI]]));
  if System.Length(LMissing) > 0 then
    raise ESystemCryptoRequirementTlsLibException.CreateResFmt(@SRequiredGroupsNotNative,
      [CommaList(LMissing)]);
end;

class procedure TSystemCryptoStrictness.RequireCipherSuites(
  const AProvider: ICryptoProvider; const ACodes: array of UInt16);
var
  LNative: ICipherSuiteRegistry;
  LDropped, LMissing: TArray<string>;
  LI: Int32;
begin
  LNative := NativeCipherSuites(AProvider, LDropped);
  LMissing := nil;
  for LI := 0 to System.High(ACodes) do
    if not LNative.Contains(ACodes[LI]) then
      TArrayUtilities.Append<string>(LMissing, Format('0x%.4x', [ACodes[LI]]));
  if System.Length(LMissing) > 0 then
    raise ESystemCryptoRequirementTlsLibException.CreateResFmt(@SRequiredSuitesNotNative,
      [CommaList(LMissing)]);
end;

class procedure TSystemCryptoStrictness.RequireSignatureSchemes(
  const AProvider: ICryptoProvider; const ASchemes: array of TSignatureScheme);
var
  LNative: ISignatureSchemeRegistry;
  LDropped, LMissing: TArray<string>;
  LI: Int32;
  LName: string;
begin
  LNative := NativeSignatureSchemes(AProvider, LDropped);
  LMissing := nil;
  for LI := 0 to System.High(ASchemes) do
    if not LNative.Contains(ASchemes[LI].ToCode) then
    begin
      LName := TEnumUtilities.GetName<TSignatureScheme>(ASchemes[LI]);
      TArrayUtilities.Append<string>(LMissing, LName);
    end;
  if System.Length(LMissing) > 0 then
    raise ESystemCryptoRequirementTlsLibException.CreateResFmt(@SRequiredSchemesNotNative,
      [CommaList(LMissing)]);
end;

end.
