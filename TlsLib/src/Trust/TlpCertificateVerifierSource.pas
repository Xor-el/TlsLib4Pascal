{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpCertificateVerifierSource;

{$I ..\Include\TlsLib.inc}

interface

uses
  TlpTrustPolicy,
  TlpICertificateTrust,
  TlpICertificateVerifierSource,
  TlpCertificateVerifier;

type
  /// <summary>
  /// The default <see cref="IServerCertificateVerifierSource" />: builds the ordered
  /// built-in PKIX verifier from the connection's trust context, so the clock and
  /// revocation posture are injected at construction. Selected whenever no whole-verifier
  /// instance is configured.
  /// </summary>
  TBuiltInServerVerifierSource = class sealed(TInterfacedObject,
    IServerCertificateVerifierSource)
  public
    function CreateServerVerifier(const AContext: TServerTrustContext)
      : IServerCertificateVerifier;
  end;

  /// <summary>
  /// A source that returns one caller-supplied verifier for every connection. The context
  /// is ignored - a pre-built instance cannot receive the connection's clock or posture,
  /// which is exactly why the OS-native delegate is installed as its own source rather than
  /// through this wrapper.
  /// </summary>
  TInstanceServerVerifierSource = class sealed(TInterfacedObject,
    IServerCertificateVerifierSource)
  strict private
    FVerifier: IServerCertificateVerifier;
  public
    constructor Create(const AVerifier: IServerCertificateVerifier);
    function CreateServerVerifier(const AContext: TServerTrustContext)
      : IServerCertificateVerifier;
  end;

  /// <summary>
  /// The default <see cref="IClientCertificateVerifierSource" />: builds the built-in PKIX
  /// verifier for the clientAuth role from the connection's client-trust context, so the clock
  /// and revocation posture are injected at construction. Selected whenever no whole-verifier
  /// instance is configured.
  /// </summary>
  TBuiltInClientVerifierSource = class sealed(TInterfacedObject,
    IClientCertificateVerifierSource)
  public
    function CreateClientVerifier(const AContext: TClientTrustContext)
      : IClientCertificateVerifier;
  end;

  /// <summary>
  /// A source that returns one caller-supplied client-certificate verifier for every
  /// connection. The context is ignored - a pre-built instance cannot receive the connection's
  /// clock or posture, which is why the OS-native delegate is installed as its own source.
  /// </summary>
  TInstanceClientVerifierSource = class sealed(TInterfacedObject,
    IClientCertificateVerifierSource)
  strict private
    FVerifier: IClientCertificateVerifier;
  public
    constructor Create(const AVerifier: IClientCertificateVerifier);
    function CreateClientVerifier(const AContext: TClientTrustContext)
      : IClientCertificateVerifier;
  end;

implementation

{ TBuiltInServerVerifierSource }

function TBuiltInServerVerifierSource.CreateServerVerifier(
  const AContext: TServerTrustContext): IServerCertificateVerifier;
var
  LVerifier: TCertificateVerifier;
begin
  LVerifier := TCertificateVerifier.Create(AContext.Provider, AContext.Clock,
    AContext.TrustStore, AContext.CheckHostName, AContext.ChainLimits,
    AContext.RevocationPosture, AContext.Dangerous,
    AContext.AsyncVerdictEnabled, AContext.Intermediates);
  LVerifier.SetChainAlgorithmPolicy(AContext.StrengthPolicy,
    AContext.AdvertisedSignatureSchemes);
  Result := LVerifier as IServerCertificateVerifier;
end;

{ TInstanceServerVerifierSource }

constructor TInstanceServerVerifierSource.Create(
  const AVerifier: IServerCertificateVerifier);
begin
  inherited Create;
  FVerifier := AVerifier;
end;

function TInstanceServerVerifierSource.CreateServerVerifier(
  const AContext: TServerTrustContext): IServerCertificateVerifier;
begin
  Result := FVerifier;
end;

{ TBuiltInClientVerifierSource }

function TBuiltInClientVerifierSource.CreateClientVerifier(
  const AContext: TClientTrustContext): IClientCertificateVerifier;
var
  LVerifier: TCertificateVerifier;
begin
  // a client certificate carries no host identity, so name checking is always off
  LVerifier := TCertificateVerifier.Create(AContext.Provider, AContext.Clock,
    AContext.TrustStore, False, AContext.ChainLimits, AContext.RevocationPosture,
    AContext.Dangerous, AContext.AsyncVerdictEnabled, AContext.Intermediates);
  LVerifier.SetChainAlgorithmPolicy(AContext.StrengthPolicy,
    AContext.AdvertisedSignatureSchemes);
  Result := LVerifier as IClientCertificateVerifier;
end;

{ TInstanceClientVerifierSource }

constructor TInstanceClientVerifierSource.Create(
  const AVerifier: IClientCertificateVerifier);
begin
  inherited Create;
  FVerifier := AVerifier;
end;

function TInstanceClientVerifierSource.CreateClientVerifier(
  const AContext: TClientTrustContext): IClientCertificateVerifier;
begin
  Result := FVerifier;
end;

end.
