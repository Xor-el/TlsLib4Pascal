{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpICertificateVerifierSource;

{$I ..\..\Include\TlsLib.inc}

interface

uses
  SysUtils,
  TlpTrustPolicy,
  TlpICertificateTrust,
  TlpITrustAnchorStore,
  TlpCertificateStrengthPolicy;

type
  /// <summary>
  /// The single way the engine obtains a server-certificate verifier: it asks a
  /// source to build one from the connection's trust context. The built-in PKIX
  /// verifier is the default source; an injected instance and the OS-native
  /// delegate are also just sources (mirrors how a server credential is obtained
  /// through <c>ITlsServerCredentialResolver</c>).
  /// </summary>
  IServerCertificateVerifierSource = interface(IInterface)
    ['{4C7E0B21-9F3A-4D58-8E16-2A7C5D9B0F31}']
    function CreateServerVerifier(const AContext: TServerTrustContext)
      : IServerCertificateVerifier;
  end;

  /// <summary>
  /// The single way an mTLS server obtains a client-certificate verifier: it asks a
  /// source to build one from the connection's client-trust context. The built-in PKIX
  /// verifier is the default source; an injected instance and the OS-native delegate (an
  /// exclusive-root chain engine over the configured client-CA anchors) are also just sources.
  /// </summary>
  IClientCertificateVerifierSource = interface(IInterface)
    ['{9D5A1C82-3E47-4B96-A0F2-7C48D6B1E395}']
    function CreateClientVerifier(const AContext: TClientTrustContext)
      : IClientCertificateVerifier;
  end;

  /// <summary>
  /// How an endpoint verifies its peer's certificate: one immutable policy of one kind. The data
  /// the kind does not use is empty, so a setting cannot be attached to a policy that would
  /// ignore it.
  /// </summary>
  ITrustVerification = interface(IInterface)
    ['{B85AB760-F4FF-4896-98B3-A0D67EE22EC4}']
    function Kind: TVerificationKind;
    /// <summary>WebPki: the trust roots. A client-role VerifierSource: its exclusive root.</summary>
    function AnchorStores: TArray<ITrustAnchorStore>;
    /// <summary>Raw PEM or DER anchor blobs, parsed by the endpoint with its PKIX provider.</summary>
    function AnchorData: TArray<TBytes>;
    /// <summary>Raw PEM or DER intermediate blobs that complete an incomplete peer chain.</summary>
    function IntermediateData: TArray<TBytes>;
    function StrengthPolicy: TCertificateStrengthPolicy;
    function RevocationPosture: TRevocationPosture;
  end;

  /// <summary>The policy a client applies to the server's certificate.</summary>
  IServerVerification = interface(ITrustVerification)
    ['{4714EEBB-BA1E-4329-A0E5-782C8D2F4C11}']
    /// <summary>The whole verifier of a Custom policy; nil for the other kinds.</summary>
    function Verifier: IServerCertificateVerifier;
    /// <summary>The source of a VerifierSource policy; nil for the other kinds.</summary>
    function Source: IServerCertificateVerifierSource;
  end;

  /// <summary>The policy a server applies to a client's certificate.</summary>
  IClientVerification = interface(ITrustVerification)
    ['{B1B91731-A5C7-4593-A344-DE8386035950}']
    function Verifier: IClientCertificateVerifier;
    function Source: IClientCertificateVerifierSource;
  end;

  /// <summary>The pipeline knobs of a WebPki or VerifierSource server policy; the anchors were
  /// fixed by the factory that made the builder. Build snapshots the draft.</summary>
  IServerVerificationBuilder = interface(IInterface)
    ['{C2A9322E-6B4C-4ECD-BBA8-3D6CA74D3F28}']
    /// <summary>Adds PEM or DER intermediates to complete a peer chain that omits them.</summary>
    function WithIntermediateCertificates(const AData: TBytes): IServerVerificationBuilder;
    /// <summary>The key-strength floors applied to the verified path.</summary>
    function WithMinimumStrength(const APolicy: TCertificateStrengthPolicy)
      : IServerVerificationBuilder;
    /// <summary>The revocation posture. Hard is usable only with a staple request or a live
    /// verdict on the endpoint, which Build of the endpoint checks.</summary>
    function WithRevocation(APosture: TRevocationPosture): IServerVerificationBuilder;
    function Build: IServerVerification;
  end;

  /// <summary>The client-role counterpart of <see cref="IServerVerificationBuilder" />.</summary>
  IClientVerificationBuilder = interface(IInterface)
    ['{A3D8BDB9-04C7-4010-BB14-512B09610A4F}']
    function WithIntermediateCertificates(const AData: TBytes): IClientVerificationBuilder;
    function WithMinimumStrength(const APolicy: TCertificateStrengthPolicy)
      : IClientVerificationBuilder;
    function WithRevocation(APosture: TRevocationPosture): IClientVerificationBuilder;
    function Build: IClientVerification;
  end;

implementation

end.
