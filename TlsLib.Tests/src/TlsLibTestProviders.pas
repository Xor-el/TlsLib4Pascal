{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlsLibTestProviders;

{$I ..\..\TlsLib\src\Include\TlsLib.inc}

interface

uses
  SysUtils,
  TlpEnumUtilities,
  TlpICryptoProvider,
  TlpIPkixProvider,
  TlpDefaultCryptoProvider,
  TlpDefaultPkixProvider,
  TlpOSCryptoProvider;

type
  /// <summary>Registered crypto providers; a new provider is one member here and one case arm
  /// in <see cref="TTlsLibTestProviders.Crypto" />.</summary>
  TCryptoProviderChoice = (Portable, OS);

  /// <summary>Registered PKIX providers; a new provider is one member here and one case arm
  /// in <see cref="TTlsLibTestProviders.Pkix" />.</summary>
  TPkixProviderChoice = (Portable);

  /// <summary>
  /// The single place the test suites and the interop harness obtain their providers. Each
  /// kind has its own switch: --crypto-provider=NAME / TLSLIB_CRYPTO_PROVIDER and
  /// --pkix-provider=NAME / TLSLIB_PKIX_PROVIDER (flag first, then variable, else portable).
  /// </summary>
  TTlsLibTestProviders = class sealed(TObject)
  strict private
    // not inlined into Choice: a generic body cannot reference the implementation's resourcestring
    class procedure RaiseUnknownProvider(const AEnvVar, AValue, AValid: string); static;
    class function Choice<T>(const AFlag, AEnvVar: string; const AFallback: T): T; static;
  public
    const
      CryptoFlag = 'crypto-provider';
      CryptoEnvVar = 'TLSLIB_CRYPTO_PROVIDER';
      PkixFlag = 'pkix-provider';
      PkixEnvVar = 'TLSLIB_PKIX_PROVIDER';
    class function SelectedCrypto: TCryptoProviderChoice; static;
    class function SelectedPkix: TPkixProviderChoice; static;
    /// <summary>The selected provider, fresh per call.</summary>
    class function Crypto: ICryptoProvider; overload; static;
    class function Pkix: IPkixProvider; overload; static;
    /// <summary>A named provider, for tests that assert one provider's behaviour. OS is the
    /// portable base where the platform has no native facets.</summary>
    class function Crypto(AChoice: TCryptoProviderChoice): ICryptoProvider; overload; static;
    class function Pkix(AChoice: TPkixProviderChoice): IPkixProvider; overload; static;
    /// <summary>One line naming the active providers, for runner start-up.</summary>
    class function Describe: string; static;
  end;

implementation

resourcestring
  SUnknownProvider = '%s: unknown provider "%s" (valid: %s)';

class function TTlsLibTestProviders.Choice<T>(const AFlag, AEnvVar: string;
  const AFallback: T): T;
var
  LPrefix, LValue, LValid: string;
  LNames: TArray<T>;
  LI: Int32;
begin
  LValue := '';
  LPrefix := '--' + AFlag + '=';
  for LI := 1 to ParamCount do
    if Copy(ParamStr(LI), 1, Length(LPrefix)) = LPrefix then
      LValue := Copy(ParamStr(LI), Length(LPrefix) + 1, MaxInt);
  if LValue = '' then
    LValue := Trim(GetEnvironmentVariable(AEnvVar));
  if LValue = '' then
    Exit(AFallback);
  if TEnumUtilities.TryGetEnumValue<T>(LValue, Result) then
    Exit;
  LValid := '';
  LNames := TEnumUtilities.GetEnumValues<T>;
  for LI := 0 to High(LNames) do
  begin
    if LI > 0 then
      LValid := LValid + ', ';
    LValid := LValid + LowerCase(TEnumUtilities.GetName<T>(LNames[LI]));
  end;
  RaiseUnknownProvider(AEnvVar, LValue, LValid);
end;

class procedure TTlsLibTestProviders.RaiseUnknownProvider(const AEnvVar, AValue,
  AValid: string);
begin
  raise EArgumentException.CreateFmt(SUnknownProvider, [AEnvVar, AValue, AValid]);
end;

class function TTlsLibTestProviders.SelectedCrypto: TCryptoProviderChoice;
begin
  Result := Choice<TCryptoProviderChoice>(CryptoFlag, CryptoEnvVar,
    TCryptoProviderChoice.Portable);
end;

class function TTlsLibTestProviders.SelectedPkix: TPkixProviderChoice;
begin
  Result := Choice<TPkixProviderChoice>(PkixFlag, PkixEnvVar, TPkixProviderChoice.Portable);
end;

class function TTlsLibTestProviders.Crypto: ICryptoProvider;
begin
  Result := Crypto(SelectedCrypto);
end;

class function TTlsLibTestProviders.Pkix: IPkixProvider;
begin
  Result := Pkix(SelectedPkix);
end;

class function TTlsLibTestProviders.Crypto(AChoice: TCryptoProviderChoice): ICryptoProvider;
begin
  case AChoice of
    TCryptoProviderChoice.Portable:
      Result := TDefaultCryptoProvider.Create as ICryptoProvider;
    TCryptoProviderChoice.OS:
      Result := TOSCryptoProvider.Compose(Crypto(TCryptoProviderChoice.Portable));
  end;
end;

class function TTlsLibTestProviders.Pkix(AChoice: TPkixProviderChoice): IPkixProvider;
begin
  case AChoice of
    TPkixProviderChoice.Portable:
      Result := TDefaultPkixProvider.Create as IPkixProvider;
  end;
end;

class function TTlsLibTestProviders.Describe: string;
const
  Facets: array[Boolean] of string = ('no', 'yes');
var
  NativeSuffix: string;
begin
  NativeSuffix := '';
  if TOSCryptoProvider.PlatformName <> '' then
    NativeSuffix := ', ' + TOSCryptoProvider.PlatformName;
  Result := Format('crypto=%s (native facets: %s%s) pkix=%s',
    [LowerCase(TEnumUtilities.GetName<TCryptoProviderChoice>(SelectedCrypto)),
    Facets[TOSCryptoProvider.HasNativeFacets],
    NativeSuffix,
    LowerCase(TEnumUtilities.GetName<TPkixProviderChoice>(SelectedPkix))]);
end;

end.
