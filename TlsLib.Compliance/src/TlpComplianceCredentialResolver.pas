{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpComplianceCredentialResolver;

{$I ..\..\TlsLib\src\Include\TlsLib.inc}

interface

uses
  TlpCryptoDomainTypes,
  TlpTlsLibExceptions,
  TlpTlsCredential,
  TlpITlsCredentialResolver,
  TlpComplianceTypes,
  TlpICompliancePolicy,
  TlpIComplianceCredentialResolver;

type
  /// <summary>
  /// A credential resolver that asks an inner resolver and admits its answer only when the policy
  /// tolerates the credential: strict mode refuses any finding, relaxed mode a configuration
  /// finding. A refusal answers False, which aborts the handshake; the client sees
  /// unrecognized_name (SNI) or handshake_failure and the host gets no reason, so run
  /// EvaluateCredential over the credentials at startup. The check reads the chosen credential's
  /// certificate on every handshake. The admitted key is narrowed to the schemes of the rules,
  /// which are read once at construction. It keeps no other state, so it is as thread-safe as the
  /// inner resolver.
  /// </summary>
  TComplianceCredentialResolver = class sealed(TInterfacedObject, ITlsServerCredentialResolver,
    IComplianceCredentialResolver)
  strict private
  var
    FPolicy: ICompliancePolicy;
    FInner: ITlsServerCredentialResolver;
    FEnforcement: TComplianceEnforcement;
    FSchemes: TArray<TSignatureScheme>;
  public
    /// <summary>Raises EArgumentTlsLibException for a nil argument.</summary>
    constructor Create(const APolicy: ICompliancePolicy;
      const AInner: ITlsServerCredentialResolver);
    function TryResolve(const AClientHello: TTlsClientHelloInfo;
      out ACredential: TTlsCredential): Boolean;
    function Policy: ICompliancePolicy;
    function Inner: ITlsServerCredentialResolver;
  end;

implementation

resourcestring
  SNilPolicy = 'the compliance policy must not be nil';
  SNilInner = 'the inner credential resolver must not be nil';

{ TComplianceCredentialResolver }

constructor TComplianceCredentialResolver.Create(const APolicy: ICompliancePolicy;
  const AInner: ITlsServerCredentialResolver);
begin
  inherited Create;
  if APolicy = nil then
    raise EArgumentTlsLibException.CreateRes(@SNilPolicy);
  if AInner = nil then
    raise EArgumentTlsLibException.CreateRes(@SNilInner);
  FPolicy := APolicy;
  FInner := AInner;
  FEnforcement := APolicy.Enforcement;
  FSchemes := TComplianceCatalog.Schemes(APolicy.Rules.SignatureSchemes);
end;

function TComplianceCredentialResolver.TryResolve(const AClientHello: TTlsClientHelloInfo;
  out ACredential: TTlsCredential): Boolean;
var
  LCredential: TTlsCredential;
  LRefused: TArray<TComplianceFinding>;
begin
  ACredential := Default(TTlsCredential);
  Result := FInner.TryResolve(AClientHello, LCredential);
  if not Result then
    Exit;
  LCredential := TComplianceCatalog.NarrowedCredential(LCredential, FSchemes);
  LRefused := TComplianceCatalog.Refusals(FEnforcement,
    FPolicy.EvaluateCredential(LCredential).Findings);
  Result := System.Length(LRefused) = 0;
  if Result then
    ACredential := LCredential;
end;

function TComplianceCredentialResolver.Policy: ICompliancePolicy;
begin
  Result := FPolicy;
end;

function TComplianceCredentialResolver.Inner: ITlsServerCredentialResolver;
begin
  Result := FInner;
end;

end.
