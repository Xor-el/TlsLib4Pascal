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
  TlpIIssuerLookup,
  TlpTrustTypes,
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
    ['{2465D5CD-2A64-4D22-B4D7-62CA9632B115}']
    function Kind: TVerificationKind;
    /// <summary>WebPki: the trust roots. A client-role VerifierSource: its exclusive root.</summary>
    function AnchorStores: TArray<ITrustAnchorStore>;
    /// <summary>Raw PEM or DER anchor blobs, parsed by the endpoint with its PKIX provider.</summary>
    function AnchorData: TArray<TBytes>;
    /// <summary>Raw PEM or DER intermediate blobs that complete an incomplete peer chain.</summary>
    function IntermediateData: TArray<TBytes>;
    /// <summary>The lookup that supplies the issuers of a peer chain on demand, beside the roots
    /// above; nil when there is none.</summary>
    function IssuerLookup: IIssuerLookup;
    /// <summary>Which of the certificates IssuerLookup offers as anchors are trusted as anchors;
    /// SelfSignedOnly when there is no lookup.</summary>
    function IssuerAnchorRule: TBundleAnchorRule;
    function StrengthPolicy: TCertificateStrengthPolicy;
    function RevocationPosture: TRevocationPosture;
  end;

  /// <summary>The policy a client applies to the server's certificate.</summary>
  IServerVerification = interface(ITrustVerification)
    ['{3C0A7E52-91D4-4B68-A2F6-5D18E7B04C93}']
    /// <summary>The whole verifier of a Custom policy; nil for the other kinds.</summary>
    function Verifier: IServerCertificateVerifier;
    /// <summary>The source of a VerifierSource policy; nil for the other kinds.</summary>
    function Source: IServerCertificateVerifierSource;
  end;

  /// <summary>The policy a server applies to a client's certificate.</summary>
  IClientVerification = interface(ITrustVerification)
    ['{E7B14D86-2F93-4A5C-B0D1-6A39C85F2E17}']
    function Verifier: IClientCertificateVerifier;
    function Source: IClientCertificateVerifierSource;
  end;

  /// <summary>The pipeline knobs of a WebPki or VerifierSource server policy; the anchors were
  /// fixed by the factory that made the builder, and only an issuer lookup can add more trust
  /// here. Build snapshots the draft.</summary>
  IServerVerificationBuilder = interface(IInterface)
    ['{3361D0DE-373C-428F-8344-0A4E23DC1C9B}']
    /// <summary>Adds PEM or DER intermediates to complete a peer chain that omits them.</summary>
    function WithIntermediateCertificates(const AData: TBytes): IServerVerificationBuilder;
    /// <summary>Resolves the issuers of a peer chain from ALookup on demand during each
    /// verification, beside the roots (or alone, as the trust source). Only a self-signed
    /// certificate the lookup offers as an anchor is trusted as one. A resuming client re-verifies
    /// the stored chain through it unless WithResumeVerification set a mode, which Build refuses
    /// under Hard revocation without a live verdict and under early data beside an asynchronous
    /// verdict. A server needs WithPeerAuth for it to take effect. A later call replaces an
    /// earlier one. nil is refused.</summary>
    function WithIssuerLookup(const ALookup: IIssuerLookup): IServerVerificationBuilder; overload;
    /// <summary>As above, with ARule choosing which of the certificates the lookup offers as
    /// anchors are trusted as anchors.</summary>
    function WithIssuerLookup(const ALookup: IIssuerLookup;
      ARule: TBundleAnchorRule): IServerVerificationBuilder; overload;
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
    ['{C1A52DB6-CA92-4F0B-BFAF-8E1400D0589F}']
    function WithIntermediateCertificates(const AData: TBytes): IClientVerificationBuilder;
    function WithIssuerLookup(const ALookup: IIssuerLookup): IClientVerificationBuilder; overload;
    function WithIssuerLookup(const ALookup: IIssuerLookup;
      ARule: TBundleAnchorRule): IClientVerificationBuilder; overload;
    function WithMinimumStrength(const APolicy: TCertificateStrengthPolicy)
      : IClientVerificationBuilder;
    function WithRevocation(APosture: TRevocationPosture): IClientVerificationBuilder;
    function Build: IClientVerification;
  end;

implementation

end.
