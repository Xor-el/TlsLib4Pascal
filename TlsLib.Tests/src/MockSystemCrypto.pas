{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit MockSystemCrypto;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  SysUtils,
  TlpCryptoDomainTypes,
  TlpICryptoProvider,
  TlpISigningKey,
  TlpISystemSigningKey,
  TlpISystemSignatureVerifier,
  TlpSystemCryptoTypes,
  TlpSystemCryptoBase,
  MockCryptoProvider;

type
  /// <summary>A backend report that overrides nothing: every per-algorithm answer is the base
  /// default, and the constructor flag selects whether the HPKE facet is claimed composed. Never
  /// for production use.</summary>
  TBareBackendReport = class(TSystemBackendReportBase)
  public
    function Describe: string; override;
  end;

  /// <summary>A backend report whose signing keys and verifiers answer by their
  /// <see cref="ISystemSigningKey" /> and <see cref="ISystemSignatureVerifier" /> markers alone,
  /// where a production report judges the class. Never for production use.</summary>
  TMarkedBackendReportBase = class abstract(TSystemBackendReportBase)
  public
    function SigningKeyBackend(const AKey: ISigningKey): TCryptoBackendEntry; override;
    function VerifierBackend(const AVerifier: ISignatureVerifier): TCryptoBackendEntry; override;
  end;

  /// <summary>A <see cref="TFakeSigningKey" /> that carries the OS marker and keeps it when
  /// narrowed.</summary>
  TFakeSystemSigningKey = class sealed(TFakeSigningKey, ISystemSigningKey)
  strict protected
    function Narrowed(const ASchemes: TArray<TSignatureScheme>): ISigningKey; override;
  end;

  /// <summary>A verifier that verifies nothing and carries the OS marker.</summary>
  TFakeSystemVerifier = class sealed(TRejectingSignatureVerifier, ISystemSignatureVerifier);

implementation

{ TBareBackendReport }

function TBareBackendReport.Describe: string;
begin
  Result := '';
end;

{ TMarkedBackendReportBase }

function TMarkedBackendReportBase.SigningKeyBackend(const AKey: ISigningKey): TCryptoBackendEntry;
begin
  if Supports(AKey, ISystemSigningKey) then
    Result := Ent(TCryptoBackend.System, TCryptoBackendReason.NotFallback)
  else
    Result := NotNative;
end;

function TMarkedBackendReportBase.VerifierBackend(
  const AVerifier: ISignatureVerifier): TCryptoBackendEntry;
begin
  if Supports(AVerifier, ISystemSignatureVerifier) then
    Result := Ent(TCryptoBackend.System, TCryptoBackendReason.NotFallback)
  else
    Result := NotNative;
end;

{ TFakeSystemSigningKey }

function TFakeSystemSigningKey.Narrowed(const ASchemes: TArray<TSignatureScheme>): ISigningKey;
begin
  Result := TFakeSystemSigningKey.Create(ASchemes, PublicKeyInfo) as ISigningKey;
end;

end.
