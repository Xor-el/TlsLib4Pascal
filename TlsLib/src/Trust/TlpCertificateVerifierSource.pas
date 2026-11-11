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
  SysUtils,
  TlpArrayUtilities,
  TlpTlsLibExceptions,
  TlpTrustPolicy,
  TlpICertificateTrust,
  TlpITrustAnchorStore,
  TlpIIssuerLookup,
  TlpTrustTypes,
  TlpCertificateStrengthPolicy,
  TlpICertificateVerifierSource,
  TlpCertificateVerifier;

type
  /// <summary>The settings a verification builder collects before it is snapshotted into an
  /// immutable policy.</summary>
  TVerificationDraft = record
    Kind: TVerificationKind;
    AnchorStores: TArray<ITrustAnchorStore>;
    AnchorData: TArray<TBytes>;
    IntermediateData: TArray<TBytes>;
    IssuerLookup: IIssuerLookup;
    IssuerRule: TBundleAnchorRule;
    Strength: TCertificateStrengthPolicy;
    Posture: TRevocationPosture;
    /// <summary>A draft of AKind over the given anchors with the default floors and the Soft
    /// posture.</summary>
    class function Start(AKind: TVerificationKind;
      const AStores: TArray<ITrustAnchorStore>; const AAnchorData: TArray<TBytes>)
      : TVerificationDraft; static;
    procedure AddIntermediates(const AData: TBytes);
    /// <summary>Takes the lookup and its anchor rule, refusing nil.</summary>
    procedure SetIssuerLookup(const ALookup: IIssuerLookup; ARule: TBundleAnchorRule);
    /// <summary>Refuses a WebPki draft with neither roots nor a lookup (no silent-insecure).</summary>
    procedure RequireTrustSource;
    /// <summary>Takes the floors, refusing a non-positive RSA minimum or a maximum below it.</summary>
    procedure SetStrength(const APolicy: TCertificateStrengthPolicy);
  end;

  /// <summary>The read side shared by the server and client policies.</summary>
  TTrustVerificationDataBase = class abstract(TInterfacedObject, ITrustVerification)
  strict private
    FDraft: TVerificationDraft;
  strict protected
    constructor Create(const ADraft: TVerificationDraft);
  public
    function Kind: TVerificationKind;
    function AnchorStores: TArray<ITrustAnchorStore>;
    function AnchorData: TArray<TBytes>;
    function IntermediateData: TArray<TBytes>;
    function IssuerLookup: IIssuerLookup;
    function IssuerAnchorRule: TBundleAnchorRule;
    function StrengthPolicy: TCertificateStrengthPolicy;
    function RevocationPosture: TRevocationPosture;
  end;

  TServerVerificationPolicy = class sealed(TTrustVerificationDataBase, IServerVerification)
  strict private
    FVerifier: IServerCertificateVerifier;
    FSource: IServerCertificateVerifierSource;
  public
    constructor Create(const ADraft: TVerificationDraft;
      const AVerifier: IServerCertificateVerifier; const ASource: IServerCertificateVerifierSource);
    function Verifier: IServerCertificateVerifier;
    function Source: IServerCertificateVerifierSource;
  end;

  TClientVerificationPolicy = class sealed(TTrustVerificationDataBase, IClientVerification)
  strict private
    FVerifier: IClientCertificateVerifier;
    FSource: IClientCertificateVerifierSource;
  public
    constructor Create(const ADraft: TVerificationDraft;
      const AVerifier: IClientCertificateVerifier; const ASource: IClientCertificateVerifierSource);
    function Verifier: IClientCertificateVerifier;
    function Source: IClientCertificateVerifierSource;
  end;

  TServerVerificationBuilder = class sealed(TInterfacedObject, IServerVerificationBuilder)
  strict private
    FDraft: TVerificationDraft;
    FSource: IServerCertificateVerifierSource;
  public
    constructor Create(const ADraft: TVerificationDraft;
      const ASource: IServerCertificateVerifierSource);
    function WithIntermediateCertificates(const AData: TBytes): IServerVerificationBuilder;
    function WithIssuerLookup(const ALookup: IIssuerLookup): IServerVerificationBuilder; overload;
    function WithIssuerLookup(const ALookup: IIssuerLookup;
      ARule: TBundleAnchorRule): IServerVerificationBuilder; overload;
    function WithMinimumStrength(const APolicy: TCertificateStrengthPolicy)
      : IServerVerificationBuilder;
    function WithRevocation(APosture: TRevocationPosture): IServerVerificationBuilder;
    function Build: IServerVerification;
  end;

  TClientVerificationBuilder = class sealed(TInterfacedObject, IClientVerificationBuilder)
  strict private
    FDraft: TVerificationDraft;
    FSource: IClientCertificateVerifierSource;
  public
    constructor Create(const ADraft: TVerificationDraft;
      const ASource: IClientCertificateVerifierSource);
    function WithIntermediateCertificates(const AData: TBytes): IClientVerificationBuilder;
    function WithIssuerLookup(const ALookup: IIssuerLookup): IClientVerificationBuilder; overload;
    function WithIssuerLookup(const ALookup: IIssuerLookup;
      ARule: TBundleAnchorRule): IClientVerificationBuilder; overload;
    function WithMinimumStrength(const APolicy: TCertificateStrengthPolicy)
      : IClientVerificationBuilder;
    function WithRevocation(APosture: TRevocationPosture): IClientVerificationBuilder;
    function Build: IClientVerification;
  end;

  /// <summary>
  /// The ways a client verifies the server's certificate. The anchors are arguments of the
  /// factories, not setters on a builder, so a policy that ignores them (Custom, DangerousSkip)
  /// cannot be given any; an issuer lookup is a setter of the builders of WebPki and
  /// VerifierSource, which are the only kinds that use one.
  /// </summary>
  TServerVerification = class sealed(TObject)
  public
    /// <summary>The built-in PKIX pipeline over AStore.</summary>
    class function WebPki(const AStore: ITrustAnchorStore): IServerVerificationBuilder;
      overload; static;
    /// <summary>The built-in PKIX pipeline over PEM or DER roots.</summary>
    class function WebPki(const AAnchorData: TBytes): IServerVerificationBuilder;
      overload; static;
    /// <summary>The built-in PKIX pipeline over the union of the stores and root blobs.</summary>
    class function WebPki(const AStores: TArray<ITrustAnchorStore>;
      const AAnchorData: TArray<TBytes>): IServerVerificationBuilder; overload; static;
    /// <summary>The built-in PKIX pipeline with ALookup as its only trust source; the pipeline
    /// knobs still apply. nil is refused.</summary>
    class function WebPki(const ALookup: IIssuerLookup): IServerVerificationBuilder;
      overload; static;
    /// <summary>As above, with ARule choosing which of the certificates the lookup offers as
    /// anchors are trusted as anchors.</summary>
    class function WebPki(const ALookup: IIssuerLookup; ARule: TBundleAnchorRule)
      : IServerVerificationBuilder; overload; static;
    /// <summary>A source that owns its roots (the OS delegate); the pipeline knobs still apply.</summary>
    class function VerifierSource(const ASource: IServerCertificateVerifierSource)
      : IServerVerificationBuilder; static;
    /// <summary>A whole injected verifier; it replaces the built-in chain verification. On an
    /// Encrypted Client Hello reject it is handed the config's public_name as the host and owns
    /// that check (RFC 9849 sec. 6.1.7).</summary>
    class function Custom(const AVerifier: IServerCertificateVerifier): IServerVerification;
      overload; static;
    /// <summary>As above, with a revocation posture for a live verdict over the verifier's path.</summary>
    class function Custom(const AVerifier: IServerCertificateVerifier;
      APosture: TRevocationPosture): IServerVerification; overload; static;
    /// <summary>No verification: the handshake accepts any server certificate. Test use only; a
    /// real Encrypted Client Hello offer is refused at Build under it.</summary>
    class function DangerousSkip: IServerVerification; static;
  end;

  /// <summary>The ways a server verifies a client's certificate (see <see cref="TServerVerification" />).</summary>
  TClientVerification = class sealed(TObject)
  public
    class function WebPki(const AStore: ITrustAnchorStore): IClientVerificationBuilder;
      overload; static;
    class function WebPki(const AAnchorData: TBytes): IClientVerificationBuilder;
      overload; static;
    class function WebPki(const AStores: TArray<ITrustAnchorStore>;
      const AAnchorData: TArray<TBytes>): IClientVerificationBuilder; overload; static;
    class function WebPki(const ALookup: IIssuerLookup): IClientVerificationBuilder;
      overload; static;
    class function WebPki(const ALookup: IIssuerLookup; ARule: TBundleAnchorRule)
      : IClientVerificationBuilder; overload; static;
    /// <summary>A source that consumes the anchors as its exclusive client-CA root (the OS delegate).</summary>
    class function VerifierSource(const ASource: IClientCertificateVerifierSource;
      const AStore: ITrustAnchorStore): IClientVerificationBuilder; overload; static;
    class function VerifierSource(const ASource: IClientCertificateVerifierSource;
      const AAnchorData: TBytes): IClientVerificationBuilder; overload; static;
    class function Custom(const AVerifier: IClientCertificateVerifier): IClientVerification;
      overload; static;
    class function Custom(const AVerifier: IClientCertificateVerifier;
      APosture: TRevocationPosture): IClientVerification; overload; static;
    class function DangerousSkip: IClientVerification; static;
  end;

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
  /// A source that returns one caller-supplied verifier for every connection. A pre-built
  /// instance cannot receive the connection's clock or posture, which is exactly why the
  /// OS-native delegate is installed as its own source rather than through this wrapper. The
  /// engine, not this source, applies the verify callback.
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
  /// connection. A pre-built instance cannot receive the connection's clock or posture, which is
  /// why the OS-native delegate is installed as its own source. The engine, not this source,
  /// applies the verify callback.
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

resourcestring
  SNoTrustAnchors = 'a WebPki verification needs at least one trust store, root certificate or ' +
    'issuer lookup (no silent-insecure)';
  SNilTrustStore = 'a trust store must not be nil';
  SEmptyAnchorData = 'a trust-anchor bundle must not be empty';
  SNilVerifier = 'a verifier or verifier source must not be nil';
  SNilIssuerLookup = 'an issuer lookup must not be nil';
  SInvalidStrengthFloors = 'the minimum RSA modulus must be positive and, when a maximum is ' +
    'set (non-zero), no larger than that maximum';

{ TVerificationDraft }

class function TVerificationDraft.Start(AKind: TVerificationKind;
  const AStores: TArray<ITrustAnchorStore>; const AAnchorData: TArray<TBytes>)
  : TVerificationDraft;
var
  LI: Int32;
begin
  for LI := 0 to System.High(AStores) do
    if AStores[LI] = nil then
      raise EArgumentTlsLibException.CreateRes(@SNilTrustStore);
  for LI := 0 to System.High(AAnchorData) do
    if System.Length(AAnchorData[LI]) = 0 then
      raise EArgumentTlsLibException.CreateRes(@SEmptyAnchorData);
  Result := Default(TVerificationDraft);
  Result.Kind := AKind;
  Result.AnchorStores := System.Copy(AStores);
  Result.AnchorData := TArrayUtilities.DeepCopy<Byte>(AAnchorData);
  Result.Strength := TCertificateStrengthPolicy.Defaults;
  Result.Posture := TRevocationPosture.Soft;
end;

procedure TVerificationDraft.AddIntermediates(const AData: TBytes);
begin
  TArrayUtilities.Append<TBytes>(IntermediateData, System.Copy(AData));
end;

procedure TVerificationDraft.SetIssuerLookup(const ALookup: IIssuerLookup;
  ARule: TBundleAnchorRule);
begin
  if ALookup = nil then
    raise EArgumentTlsLibException.CreateRes(@SNilIssuerLookup);
  IssuerLookup := ALookup;
  IssuerRule := ARule;
end;

procedure TVerificationDraft.RequireTrustSource;
begin
  if (Kind = TVerificationKind.WebPki) and (System.Length(AnchorStores) = 0) and
    (System.Length(AnchorData) = 0) and (IssuerLookup = nil) then
    raise EArgumentTlsLibException.CreateRes(@SNoTrustAnchors);
end;

procedure TVerificationDraft.SetStrength(const APolicy: TCertificateStrengthPolicy);
begin
  if (APolicy.MinRsaModulusBits < 1) or ((APolicy.MaxRsaModulusBits <> 0) and
    (APolicy.MaxRsaModulusBits < APolicy.MinRsaModulusBits)) then
    raise EArgumentTlsLibException.CreateRes(@SInvalidStrengthFloors);
  Strength := APolicy;
end;

{ TTrustVerificationDataBase }

constructor TTrustVerificationDataBase.Create(const ADraft: TVerificationDraft);
begin
  inherited Create;
  FDraft := ADraft;
end;

function TTrustVerificationDataBase.Kind: TVerificationKind;
begin
  Result := FDraft.Kind;
end;

function TTrustVerificationDataBase.AnchorStores: TArray<ITrustAnchorStore>;
begin
  Result := System.Copy(FDraft.AnchorStores);
end;

function TTrustVerificationDataBase.AnchorData: TArray<TBytes>;
begin
  Result := TArrayUtilities.DeepCopy<Byte>(FDraft.AnchorData);
end;

function TTrustVerificationDataBase.IntermediateData: TArray<TBytes>;
begin
  Result := TArrayUtilities.DeepCopy<Byte>(FDraft.IntermediateData);
end;

function TTrustVerificationDataBase.IssuerLookup: IIssuerLookup;
begin
  Result := FDraft.IssuerLookup;
end;

function TTrustVerificationDataBase.IssuerAnchorRule: TBundleAnchorRule;
begin
  Result := FDraft.IssuerRule;
end;

function TTrustVerificationDataBase.StrengthPolicy: TCertificateStrengthPolicy;
begin
  Result := FDraft.Strength;
end;

function TTrustVerificationDataBase.RevocationPosture: TRevocationPosture;
begin
  Result := FDraft.Posture;
end;

{ TServerVerificationPolicy }

constructor TServerVerificationPolicy.Create(const ADraft: TVerificationDraft;
  const AVerifier: IServerCertificateVerifier; const ASource: IServerCertificateVerifierSource);
begin
  inherited Create(ADraft);
  FVerifier := AVerifier;
  FSource := ASource;
end;

function TServerVerificationPolicy.Verifier: IServerCertificateVerifier;
begin
  Result := FVerifier;
end;

function TServerVerificationPolicy.Source: IServerCertificateVerifierSource;
begin
  Result := FSource;
end;

{ TClientVerificationPolicy }

constructor TClientVerificationPolicy.Create(const ADraft: TVerificationDraft;
  const AVerifier: IClientCertificateVerifier; const ASource: IClientCertificateVerifierSource);
begin
  inherited Create(ADraft);
  FVerifier := AVerifier;
  FSource := ASource;
end;

function TClientVerificationPolicy.Verifier: IClientCertificateVerifier;
begin
  Result := FVerifier;
end;

function TClientVerificationPolicy.Source: IClientCertificateVerifierSource;
begin
  Result := FSource;
end;

{ TServerVerificationBuilder }

constructor TServerVerificationBuilder.Create(const ADraft: TVerificationDraft;
  const ASource: IServerCertificateVerifierSource);
begin
  inherited Create;
  FDraft := ADraft;
  FSource := ASource;
end;

function TServerVerificationBuilder.WithIntermediateCertificates(
  const AData: TBytes): IServerVerificationBuilder;
begin
  FDraft.AddIntermediates(AData);
  Result := Self;
end;

function TServerVerificationBuilder.WithIssuerLookup(
  const ALookup: IIssuerLookup): IServerVerificationBuilder;
begin
  Result := WithIssuerLookup(ALookup, TBundleAnchorRule.SelfSignedOnly);
end;

function TServerVerificationBuilder.WithIssuerLookup(const ALookup: IIssuerLookup;
  ARule: TBundleAnchorRule): IServerVerificationBuilder;
begin
  FDraft.SetIssuerLookup(ALookup, ARule);
  Result := Self;
end;

function TServerVerificationBuilder.WithMinimumStrength(
  const APolicy: TCertificateStrengthPolicy): IServerVerificationBuilder;
begin
  FDraft.SetStrength(APolicy);
  Result := Self;
end;

function TServerVerificationBuilder.WithRevocation(
  APosture: TRevocationPosture): IServerVerificationBuilder;
begin
  FDraft.Posture := APosture;
  Result := Self;
end;

function TServerVerificationBuilder.Build: IServerVerification;
begin
  FDraft.RequireTrustSource;
  Result := TServerVerificationPolicy.Create(FDraft, nil, FSource) as IServerVerification;
end;

{ TClientVerificationBuilder }

constructor TClientVerificationBuilder.Create(const ADraft: TVerificationDraft;
  const ASource: IClientCertificateVerifierSource);
begin
  inherited Create;
  FDraft := ADraft;
  FSource := ASource;
end;

function TClientVerificationBuilder.WithIntermediateCertificates(
  const AData: TBytes): IClientVerificationBuilder;
begin
  FDraft.AddIntermediates(AData);
  Result := Self;
end;

function TClientVerificationBuilder.WithIssuerLookup(
  const ALookup: IIssuerLookup): IClientVerificationBuilder;
begin
  Result := WithIssuerLookup(ALookup, TBundleAnchorRule.SelfSignedOnly);
end;

function TClientVerificationBuilder.WithIssuerLookup(const ALookup: IIssuerLookup;
  ARule: TBundleAnchorRule): IClientVerificationBuilder;
begin
  FDraft.SetIssuerLookup(ALookup, ARule);
  Result := Self;
end;

function TClientVerificationBuilder.WithMinimumStrength(
  const APolicy: TCertificateStrengthPolicy): IClientVerificationBuilder;
begin
  FDraft.SetStrength(APolicy);
  Result := Self;
end;

function TClientVerificationBuilder.WithRevocation(
  APosture: TRevocationPosture): IClientVerificationBuilder;
begin
  FDraft.Posture := APosture;
  Result := Self;
end;

function TClientVerificationBuilder.Build: IClientVerification;
begin
  FDraft.RequireTrustSource;
  Result := TClientVerificationPolicy.Create(FDraft, nil, FSource) as IClientVerification;
end;

{ TServerVerification }

class function TServerVerification.WebPki(const AStore: ITrustAnchorStore)
  : IServerVerificationBuilder;
begin
  Result := WebPki(TArray<ITrustAnchorStore>.Create(AStore), nil);
end;

class function TServerVerification.WebPki(const AAnchorData: TBytes): IServerVerificationBuilder;
begin
  Result := WebPki(nil, TArray<TBytes>.Create(AAnchorData));
end;

class function TServerVerification.WebPki(const AStores: TArray<ITrustAnchorStore>;
  const AAnchorData: TArray<TBytes>): IServerVerificationBuilder;
begin
  Result := TServerVerificationBuilder.Create(
    TVerificationDraft.Start(TVerificationKind.WebPki, AStores, AAnchorData), nil)
    as IServerVerificationBuilder;
end;

class function TServerVerification.WebPki(const ALookup: IIssuerLookup)
  : IServerVerificationBuilder;
begin
  Result := WebPki(ALookup, TBundleAnchorRule.SelfSignedOnly);
end;

class function TServerVerification.WebPki(const ALookup: IIssuerLookup;
  ARule: TBundleAnchorRule): IServerVerificationBuilder;
begin
  Result := WebPki(nil, TArray<TBytes>(nil)).WithIssuerLookup(ALookup, ARule);
end;

class function TServerVerification.VerifierSource(
  const ASource: IServerCertificateVerifierSource): IServerVerificationBuilder;
begin
  if ASource = nil then
    raise EArgumentTlsLibException.CreateRes(@SNilVerifier);
  Result := TServerVerificationBuilder.Create(
    TVerificationDraft.Start(TVerificationKind.VerifierSource, nil, nil), ASource)
    as IServerVerificationBuilder;
end;

class function TServerVerification.Custom(const AVerifier: IServerCertificateVerifier)
  : IServerVerification;
begin
  Result := Custom(AVerifier, TRevocationPosture.Soft);
end;

class function TServerVerification.Custom(const AVerifier: IServerCertificateVerifier;
  APosture: TRevocationPosture): IServerVerification;
var
  LDraft: TVerificationDraft;
begin
  if AVerifier = nil then
    raise EArgumentTlsLibException.CreateRes(@SNilVerifier);
  LDraft := TVerificationDraft.Start(TVerificationKind.Custom, nil, nil);
  LDraft.Posture := APosture;
  Result := TServerVerificationPolicy.Create(LDraft, AVerifier, nil) as IServerVerification;
end;

class function TServerVerification.DangerousSkip: IServerVerification;
begin
  Result := TServerVerificationPolicy.Create(
    TVerificationDraft.Start(TVerificationKind.DangerousSkip, nil, nil), nil, nil)
    as IServerVerification;
end;

{ TClientVerification }

class function TClientVerification.WebPki(const AStore: ITrustAnchorStore)
  : IClientVerificationBuilder;
begin
  Result := WebPki(TArray<ITrustAnchorStore>.Create(AStore), nil);
end;

class function TClientVerification.WebPki(const AAnchorData: TBytes): IClientVerificationBuilder;
begin
  Result := WebPki(nil, TArray<TBytes>.Create(AAnchorData));
end;

class function TClientVerification.WebPki(const AStores: TArray<ITrustAnchorStore>;
  const AAnchorData: TArray<TBytes>): IClientVerificationBuilder;
begin
  Result := TClientVerificationBuilder.Create(
    TVerificationDraft.Start(TVerificationKind.WebPki, AStores, AAnchorData), nil)
    as IClientVerificationBuilder;
end;

class function TClientVerification.WebPki(const ALookup: IIssuerLookup)
  : IClientVerificationBuilder;
begin
  Result := WebPki(ALookup, TBundleAnchorRule.SelfSignedOnly);
end;

class function TClientVerification.WebPki(const ALookup: IIssuerLookup;
  ARule: TBundleAnchorRule): IClientVerificationBuilder;
begin
  Result := WebPki(nil, TArray<TBytes>(nil)).WithIssuerLookup(ALookup, ARule);
end;

class function TClientVerification.VerifierSource(const ASource: IClientCertificateVerifierSource;
  const AStore: ITrustAnchorStore): IClientVerificationBuilder;
begin
  if ASource = nil then
    raise EArgumentTlsLibException.CreateRes(@SNilVerifier);
  Result := TClientVerificationBuilder.Create(TVerificationDraft.Start(
    TVerificationKind.VerifierSource, TArray<ITrustAnchorStore>.Create(AStore), nil), ASource)
    as IClientVerificationBuilder;
end;

class function TClientVerification.VerifierSource(const ASource: IClientCertificateVerifierSource;
  const AAnchorData: TBytes): IClientVerificationBuilder;
begin
  if ASource = nil then
    raise EArgumentTlsLibException.CreateRes(@SNilVerifier);
  Result := TClientVerificationBuilder.Create(TVerificationDraft.Start(
    TVerificationKind.VerifierSource, nil, TArray<TBytes>.Create(AAnchorData)), ASource)
    as IClientVerificationBuilder;
end;

class function TClientVerification.Custom(const AVerifier: IClientCertificateVerifier)
  : IClientVerification;
begin
  Result := Custom(AVerifier, TRevocationPosture.Soft);
end;

class function TClientVerification.Custom(const AVerifier: IClientCertificateVerifier;
  APosture: TRevocationPosture): IClientVerification;
var
  LDraft: TVerificationDraft;
begin
  if AVerifier = nil then
    raise EArgumentTlsLibException.CreateRes(@SNilVerifier);
  LDraft := TVerificationDraft.Start(TVerificationKind.Custom, nil, nil);
  LDraft.Posture := APosture;
  Result := TClientVerificationPolicy.Create(LDraft, AVerifier, nil) as IClientVerification;
end;

class function TClientVerification.DangerousSkip: IClientVerification;
begin
  Result := TClientVerificationPolicy.Create(
    TVerificationDraft.Start(TVerificationKind.DangerousSkip, nil, nil), nil, nil)
    as IClientVerification;
end;

{ TBuiltInServerVerifierSource }

function TBuiltInServerVerifierSource.CreateServerVerifier(
  const AContext: TServerTrustContext): IServerCertificateVerifier;
var
  LVerifier: TCertificateVerifier;
  LOptions: TCertificateVerifierOptions;
begin
  LOptions.ChainLimits := AContext.ChainLimits;
  LOptions.RevocationPosture := AContext.RevocationPosture;
  LOptions.Dangerous := AContext.Dangerous;
  LOptions.Deferral := AContext.Deferral;
  LOptions.Intermediates := AContext.Intermediates;
  LOptions.StatusRequestOffered := AContext.StatusRequestOffered;
  LOptions.Occasion := AContext.Occasion;
  LVerifier := TCertificateVerifier.Create(AContext.Pkix, AContext.Clock,
    AContext.TrustStore, AContext.CheckHostName, LOptions);
  LVerifier.SetChainAlgorithmPolicy(AContext.StrengthPolicy,
    AContext.AdvertisedSignatureSchemes);
  Result := LVerifier as IServerCertificateVerifier;
end;

{ TInstanceServerVerifierSource }

constructor TInstanceServerVerifierSource.Create(
  const AVerifier: IServerCertificateVerifier);
begin
  inherited Create;
  if AVerifier = nil then
    raise EArgumentTlsLibException.CreateRes(@SNilVerifier);
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
  LOptions: TCertificateVerifierOptions;
begin
  LOptions.ChainLimits := AContext.ChainLimits;
  LOptions.RevocationPosture := AContext.RevocationPosture;
  LOptions.Dangerous := AContext.Dangerous;
  LOptions.Deferral := AContext.Deferral;
  LOptions.Intermediates := AContext.Intermediates;
  // a client certificate carries no host identity, so name checking is always off; status_request
  // and occasion stay at their defaults - must-staple never binds to a client certificate
  LVerifier := TCertificateVerifier.Create(AContext.Pkix, AContext.Clock,
    AContext.TrustStore, False, LOptions);
  LVerifier.SetChainAlgorithmPolicy(AContext.StrengthPolicy,
    AContext.AdvertisedSignatureSchemes);
  Result := LVerifier as IClientCertificateVerifier;
end;

{ TInstanceClientVerifierSource }

constructor TInstanceClientVerifierSource.Create(
  const AVerifier: IClientCertificateVerifier);
begin
  inherited Create;
  if AVerifier = nil then
    raise EArgumentTlsLibException.CreateRes(@SNilVerifier);
  FVerifier := AVerifier;
end;

function TInstanceClientVerifierSource.CreateClientVerifier(
  const AContext: TClientTrustContext): IClientCertificateVerifier;
begin
  Result := FVerifier;
end;

end.
