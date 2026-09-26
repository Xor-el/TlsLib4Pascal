{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpDefaultPkixProvider;

{$I ..\..\Include\TlsLib.inc}

interface

uses
  SysUtils,
  Classes,
  Rtti,
  SyncObjs,
  Generics.Collections,
  ClpIDigest,
  ClpDigestUtilities,
  ClpBigInteger,
  ClpIAsymmetricKeyParameter,
  ClpIOpenSslPemReader,
  ClpOpenSslPemReader,
  ClpIPkcsRsaAsn1Objects,
  ClpPkcsRsaAsn1Objects,
  ClpX9ObjectIdentifiers,
  ClpSecObjectIdentifiers,
  ClpPkcsObjectIdentifiers,
  ClpNistObjectIdentifiers,
  ClpOiwObjectIdentifiers,
  ClpEdECObjectIdentifiers,
  ClpAsn1Objects,
  ClpAsn1Core,
  ClpIRsaParameters,
  ClpX509CertificateParser,
  ClpIX509CertificateParser,
  ClpIX509Certificate,
  ClpIX509Asn1Objects,
  ClpX509Asn1Objects,
  ClpIAsn1Core,
  ClpIAsn1Objects,
  ClpPkixCertPath,
  ClpPkixParameters,
  ClpPkixCertPathValidator,
  ClpPkixCertPathBuilder,
  ClpPkixBuilderParameters,
  ClpX509StoreSelectors,
  ClpIX509StoreSelectors,
  ClpCollectionStore,
  ClpIStore,
  ClpTrustAnchor,
  ClpIPkixTypes,
  ClpOcspProtocolObjects,
  ClpIOcspProtocolObjects,
  ClpOcspGenerators,
  ClpIOcspGenerators,
  ClpX509ObjectIdentifiers,
  ClpX509CrlParser,
  ClpIX509CrlParser,
  ClpIX509Crl,
  ClpIX509CrlEntry,
  ClpCryptoLibTypes,
  ClpNullable,
  ClpValueHelper,
  ClpCryptoLibExceptions,
  TlpCryptoDomainTypes,
  TlpNegotiationTypes,
  TlpPem,
  TlpBinaryPrimitives,
  TlpArrayUtilities,
  TlpIPkixProvider,
  TlpPkixDomainTypes,
  TlpTlsAlert,
  TlpDateTimeUtilities,
  TlpTlsLibExceptions;

type
  // IInspectedCertificate - one X.509 certificate decoded once, answering the
  // per-certificate queries from that single parse.
  TInspectedCertificate = class(TInterfacedObject, IInspectedCertificate)
  strict private
  const
    // PKCS#1 id-RSASSA-PSS: the restricted RSA-PSS key type (RFC 4055)
    RsaSsaPssKeyOid = '1.2.840.113549.1.1.10';
  var
    FCert: IX509Certificate;
  public
    constructor Create(const ADer: TBytes);
    function PublicKeyInfo: TBytes;
    function DnsNames: TArray<string>;
    function IpAddresses: TArray<TBytes>;
    function KeyUsagePermits(AUsage: TCertKeyUsage): TCertAnswer;
    function KeyIsRsaPss: TCertAnswer;
    function KeyKind(out AKind: TSignatureKeyKind; out AEcNamedGroup: UInt16): Boolean;
    function KeyFacts(out AFacts: TCertKeyFacts): Boolean;
    function SignatureFacts(out AFacts: TCertSignatureFacts): Boolean;
    function PeerInfo(out ASubject, AIssuer, ACommonName, ASerialHex: string): Boolean;
  end;

  // ICertificateInspector - pure, per-certificate, side-effect-free X.509 inspection.
  TCertificateInspector = class(TInterfacedObject, ICertificateInspector)
  strict private
  const
    // RFC 7633 id-pe-tlsfeature
    TlsFeatureExtensionOid = '1.3.6.1.5.5.7.1.24';
  public
    function Parse(const ADer: TBytes): IInspectedCertificate;
    function LoadChain(const AData: TBytes): TArray<TBytes>;
    function IsWellFormed(const ADer: TBytes): Boolean;
    function PublicKeyInfo(const ACertificateDer: TBytes): TBytes;
    function DnsNames(const ACertificateDer: TBytes): TArray<string>;
    function IpAddresses(const ACertificateDer: TBytes): TArray<TBytes>;
    function PeerInfo(const ACertificateDer: TBytes;
      out ASubject, AIssuer, ACommonName, ASerialHex: string): Boolean;
    function TlsFeatures(const ACert: TBytes;
      out AFeatures: TArray<UInt16>): Boolean;
    function KeyUsagePermits(const ACertificateDer: TBytes;
      AUsage: TCertKeyUsage): TCertAnswer;
    function KeyIsRsaPss(const ACertificateDer: TBytes): TCertAnswer;
    function KeyKind(const ACertificateDer: TBytes;
      out AKind: TSignatureKeyKind; out AEcNamedGroup: UInt16): Boolean;
  end;

  // ICertificatePathValidator - RFC 5280 path validation. The trust-anchor ring is a
  // class-level cache shared across the many short-lived providers.
  TCertificatePathValidator = class(TInterfacedObject, ICertificatePathValidator)
  strict private
  type
    // parsed trust anchors keyed by a digest of the anchor set, so a reused
    // config does not re-parse its (possibly large) anchor store on every verify
    TTrustAnchorRing = record
    strict private
    const
      TrustAnchorCacheSize = Int32(8);
    strict private
      FKeys: TArray<TBytes>;
      FSets: TArray<TArray<ITrustAnchor>>;
      FCount: Int32;
      FNext: Int32;
    public
      class function Init: TTrustAnchorRing; static;
      function TryGet(const AKey: TBytes;
        out AAnchors: TArray<ITrustAnchor>): Boolean;
      procedure Remember(const AKey: TBytes;
        const AAnchors: TArray<ITrustAnchor>);
    end;
  class var
    FTrustAnchors: TTrustAnchorRing;
    FTrustAnchorLock: TCriticalSection;
  strict private
    function TrustAnchorKey(const ATrustAnchors: TArray<TBytes>): TBytes;
  public
    class constructor Create;
    class destructor Destroy;
    procedure ValidateCertificatePath(const AChain, ATrustAnchors,
      AIntermediates: TArray<TBytes>; const AValidationTimeUtc: TDateTime;
      AKeyPurpose: TCertKeyPurpose; var AEffectiveChain: TArray<TBytes>);
  end;

  // IRevocationChecker - stapled-OCSP verification and the live OCSP/CRL primitives.
  TRevocationChecker = class(TInterfacedObject, IRevocationChecker)
  strict private
    /// <summary>
    /// Whether AResponse is signed by the certificate issuer itself or by a
    /// responder the issuer delegated to (RFC 6960 sec. 4.2.2.2).
    /// </summary>
    class function OcspResponseAuthorised(const AResponse: IBasicOcspResp;
      const AIssuerCert: IX509Certificate;
      const AIssuerPublicKey: IAsymmetricKeyParameter;
      AValidityDate: TDateTime): Boolean; static;
    class function OcspDelegatedResponder(const AResponderCert,
      AIssuerCert: IX509Certificate;
      const AIssuerPublicKey: IAsymmetricKeyParameter;
      AValidityDate: TDateTime): Boolean; static;
    /// <summary>
    /// Whether an issuer-signed CRL is authoritative for ALeaf (RFC 5280 6.3.3 / 5.2): a
    /// CRL of the wrong scope (other issuer, wrong shard, CA-only, partial reasons, indirect,
    /// delta, or carrying an unrecognized critical extension) says nothing about the leaf.
    /// </summary>
    class function CrlScopeCovers(const ALeaf, AIssuer: IX509Certificate;
      const ACrl: IX509Crl): Boolean; static;
    class function IdpNameMatchesLeafDistributionPoint(
      const AIdpName: IDistributionPointName; const ALeaf: IX509Certificate): Boolean; static;
    /// <summary>
    /// Reads a CRL entry's reason (RFC 5280 5.3.1); False when the entry carries a critical
    /// entry extension that cannot be processed, so the CRL is not authoritative.
    /// </summary>
    class function CrlEntryRevokes(const AEntry: IX509CrlEntry;
      out ARevoked: Boolean): Boolean; static;
  public
    function ValidateOcspStaple(const ALeafCert, AIssuerCert,
      AOcspResponseDer: TBytes; const AValidationTimeUtc: TDateTime;
      out AStatus: TOcspStatus;
      out AThisUpdate, ANextUpdate: TDateTime): Boolean;
    function BuildOcspRequest(const ALeafCert, AIssuerCert: TBytes;
      out ARequestDer: TBytes): Boolean;
    function TryGetOcspResponderUrl(const ACert: TBytes;
      out AUrl: string): Boolean;
    function TryGetCrlDistributionPoints(const ACert: TBytes;
      out AUrls: TArray<string>): Boolean;
    function CheckCrlRevocation(const ALeafCert, AIssuerCert, ACrlDer: TBytes;
      const AValidationTimeUtc: TDateTime; out ARevoked: Boolean;
      out AThisUpdate, ANextUpdate: TDateTime): Boolean;
    function TryFindIssuer(const ALeafCert: TBytes; const ACandidates: TArray<TBytes>;
      out AIssuerCert: TBytes): Boolean;
  end;

  /// <summary>
  /// A recipe for composing a PKIX provider: each nil field takes the default, each
  /// non-nil field replaces that one facet. Composing coherent facets is the composer's
  /// responsibility: any supplied facet must be thread-safe (stateless or internally
  /// synchronized), since it slots into a provider whose accessors promise thread-safety.
  /// </summary>
  TPkixProviderOverrides = record
    Inspector: ICertificateInspector;
    PathValidation: ICertificatePathValidator;
    Revocation: IRevocationChecker;
  end;

  /// <summary>
  /// The default <see cref="IPkixProvider" />. A thin composition root: it holds one
  /// instance of each facet and its accessors return them. <see cref="Create" /> is the
  /// single composition point; the facet implementations are private to this unit.
  /// </summary>
  TDefaultPkixProvider = class(TInterfacedObject, IPkixProvider)
  strict private
  class var
    FShared: IPkixProvider;
    FSharedLock: TCriticalSection;
  var
    FInspector: ICertificateInspector;
    FPathValidation: ICertificatePathValidator;
    FRevocation: IRevocationChecker;
  public
    /// <summary>The single composition point: each nil facet override is defaulted,
    /// each supplied facet is held as-is.</summary>
    constructor Create(const AOverrides: TPkixProviderOverrides); overload;
    /// <summary>An all-defaults provider (no overrides).</summary>
    constructor Create; overload;
    class constructor Create;
    class destructor Destroy;
    /// <summary>A process-wide, lazily-created all-defaults provider: the fallback when no
    /// provider is injected. It reflects no overrides - it is the all-defaults singleton.</summary>
    class function Shared: IPkixProvider; static;

    function Certificates: ICertificateInspector;
    function PathValidation: ICertificatePathValidator;
    function Revocation: IRevocationChecker;
  end;

  /// <summary>
  /// The fluent <see cref="IPkixProviderBuilder" />: accumulates facet overrides
  /// and composes through <see cref="TDefaultPkixProvider.Create" />.
  /// </summary>
  TPkixProviderBuilder = class(TInterfacedObject, IPkixProviderBuilder)
  strict private
  var
    FOverrides: TPkixProviderOverrides;
  public
    function WithInspector(const AInspector: ICertificateInspector): IPkixProviderBuilder;
    function WithPathValidation(const APathValidation: ICertificatePathValidator): IPkixProviderBuilder;
    function WithRevocation(const ARevocation: IRevocationChecker): IPkixProviderBuilder;
    function Build: IPkixProvider;
  end;

implementation

resourcestring
  SBadCertificate = 'a certificate in the chain could not be parsed';
  SCertificateExpired = 'a certificate in the chain is outside its validity window';
  SUntrustedChain = 'the certificate chain does not reach a trusted anchor';
  SWrongCertificatePurpose = 'a certificate in the chain has an extended key usage that excludes the required TLS role';
  SMalformedCertificate = 'a certificate could not be parsed as PEM or DER';
  SNoCertificatesFound = 'no certificates were found in the input';
  STrailingCertificateData = 'the DER input has bytes after the certificate (concatenated ' +
    'DER or trailing data); use PEM or PKCS#7 to load a certificate chain';

function TCertificateInspector.LoadChain(
  const AData: TBytes): TArray<TBytes>;
var
  LStream: TBytesStream;
  LReader: IOpenSslPemReader;
  LValue: TValue;
  LCert: IX509Certificate;
  LParser: IX509CertificateParser;
  LChain: TList<TBytes>;
  LDerLen, LHeaderLen: Int32;

  // for a leading DER SEQUENCE (a Certificate or a PKCS#7 ContentInfo), its total declared length
  // (tag + length + content) and, via AHeaderLen, the offset where its content (the first child)
  // starts; both -1 for a non-SEQUENCE, indefinite, or oversize header (total also -1 for an
  // indefinite length, where AHeaderLen is still 2)
  function DerElementLength(const A: TBytes; out AHeaderLen: Int32): Int32;
  var
    LOctets, LI: Int32;
    LContent: Int64;
  begin
    Result := -1;
    AHeaderLen := -1;
    if (System.Length(A) < 2) or (A[0] <> $30) then
      Exit;
    if (A[1] and $80) = 0 then
    begin
      AHeaderLen := 2;
      Result := 2 + A[1];
    end
    else
    begin
      LOctets := A[1] and $7F;
      if LOctets = 0 then
      begin
        // indefinite length (BER): content starts after the 2-byte header, total unknown
        AHeaderLen := 2;
        Exit;
      end;
      if (LOctets > 4) or (2 + LOctets > System.Length(A)) then
        Exit;
      LContent := 0;
      for LI := 0 to LOctets - 1 do
        LContent := (LContent shl 8) or A[2 + LI]; // Int64: 4 octets cannot overflow
      // a first element longer than the whole buffer is malformed/truncated, not "trailing bytes"
      if LContent > System.Length(A) then
        Exit;
      AHeaderLen := 2 + LOctets;
      Result := AHeaderLen + Int32(LContent);
    end;
  end;

begin
  // PEM may carry a whole chain/bundle (leaf first); DER is a single certificate or a PKCS#7
  // bundle. Either way the result is the ordered list of raw DER certificates.
  Result := nil;
  try
    if TPem.IsArmored(AData) then
    begin
      LChain := TList<TBytes>.Create;
      try
        LStream := TBytesStream.Create(AData);
        try
          LReader := TOpenSslPemReader.Create(LStream);
          try
            while True do
            begin
              LValue := LReader.ReadObject;
              if LValue.IsEmpty then
                Break;
              if LValue.TryGetAsType<IX509Certificate>(LCert) then
                LChain.Add(LCert.GetEncoded);
            end;
          finally
            LReader := nil;
          end;
        finally
          LStream.Free;
        end;
        Result := LChain.ToArray;
      finally
        LChain.Free;
      end;
    end
    else
    begin
      LParser := TX509CertificateParser.Create;
      LDerLen := DerElementLength(AData, LHeaderLen);
      // bytes after the leading definite-length element (a Certificate or a PKCS#7 ContentInfo) are
      // a non-standard concatenated-DER bundle or garbage - reject rather than silently drop them
      // (an indefinite-length BER container has no declared length here and is bounded by the parser)
      if (LDerLen > 0) and (LDerLen < System.Length(AData)) then
        raise EArgumentTlsLibException.CreateRes(@STrailingCertificateData);
      // a PKCS#7 / CMS ContentInfo (RFC 5652) is the standard DER certificate bundle: its first
      // inner element is an OID (0x06) where a bare Certificate's is a SEQUENCE (0x30). Load every
      // certificate from the bag; a bare certificate loads as the single element it is.
      if (LHeaderLen > 0) and (LHeaderLen < System.Length(AData)) and
        (AData[LHeaderLen] = $06) then
      begin
        LChain := TList<TBytes>.Create;
        try
          for LCert in LParser.ReadCertificates(AData) do
            LChain.Add(LCert.GetEncoded);
          Result := LChain.ToArray;
        finally
          LChain.Free;
        end;
      end
      else
      begin
        LCert := LParser.ReadCertificate(AData);
        // empty / not a DER certificate parses to nil
        if LCert = nil then
          raise EArgumentTlsLibException.CreateRes(@SNoCertificatesFound);
        Result := TArray<TBytes>.Create(LCert.GetEncoded);
      end;
    end;
  except
    on E: ECryptoLibException do
      raise EArgumentTlsLibException.CreateRes(@SMalformedCertificate);
  end;
  if System.Length(Result) = 0 then
    raise EArgumentTlsLibException.CreateRes(@SNoCertificatesFound);
end;

function TCertificateInspector.Parse(const ADer: TBytes): IInspectedCertificate;
begin
  Result := TInspectedCertificate.Create(ADer) as IInspectedCertificate;
end;

function TCertificateInspector.IsWellFormed(
  const ADer: TBytes): Boolean;
begin
  Result := False;
  if System.Length(ADer) = 0 then
    Exit;
  try
    Parse(ADer);
    Result := True;
  except
    Result := False;
  end;
end;

function TCertificateInspector.PublicKeyInfo(
  const ACertificateDer: TBytes): TBytes;
begin
  Result := Parse(ACertificateDer).PublicKeyInfo;
end;

function TCertificateInspector.DnsNames(
  const ACertificateDer: TBytes): TArray<string>;
begin
  Result := Parse(ACertificateDer).DnsNames;
end;

function TCertificateInspector.IpAddresses(
  const ACertificateDer: TBytes): TArray<TBytes>;
begin
  Result := Parse(ACertificateDer).IpAddresses;
end;

constructor TInspectedCertificate.Create(const ADer: TBytes);
var
  LParser: IX509CertificateParser;
begin
  inherited Create;
  LParser := TX509CertificateParser.Create;
  FCert := LParser.ReadCertificate(ADer);
  if FCert = nil then
    raise EArgumentTlsLibException.CreateRes(@SMalformedCertificate);
end;

function TInspectedCertificate.PublicKeyInfo: TBytes;
begin
  Result := FCert.GetSubjectPublicKeyInfo.GetDerEncoded;
end;

function TInspectedCertificate.DnsNames: TArray<string>;
var
  LGeneralNames: IGeneralNames;
  LNames: TArray<IGeneralName>;
  LString: IAsn1String;
  LI, LCount: Int32;
begin
  Result := nil;
  LGeneralNames := FCert.GetSubjectAlternativeNameExtension;
  if LGeneralNames = nil then
    Exit;
  LNames := LGeneralNames.GetNames;
  SetLength(Result, System.Length(LNames));
  LCount := 0;
  for LI := 0 to System.Length(LNames) - 1 do
    if (LNames[LI].TagNo = TGeneralName.DnsName) and
      Supports(LNames[LI].GetName, IAsn1String, LString) then
    begin
      Result[LCount] := LString.GetString;
      Inc(LCount);
    end;
  SetLength(Result, LCount);
end;

function TInspectedCertificate.IpAddresses: TArray<TBytes>;
var
  LGeneralNames: IGeneralNames;
  LNames: TArray<IGeneralName>;
  LOctets: IAsn1OctetString;
  LI, LCount: Int32;
begin
  Result := nil;
  LGeneralNames := FCert.GetSubjectAlternativeNameExtension;
  if LGeneralNames = nil then
    Exit;
  LNames := LGeneralNames.GetNames;
  SetLength(Result, System.Length(LNames));
  LCount := 0;
  for LI := 0 to System.Length(LNames) - 1 do
    if (LNames[LI].TagNo = TGeneralName.IPAddress) and
      Supports(LNames[LI].GetName, IAsn1OctetString, LOctets) then
    begin
      Result[LCount] := LOctets.GetOctets;
      Inc(LCount);
    end;
  SetLength(Result, LCount);
end;

class function TCertificatePathValidator.TTrustAnchorRing.Init: TTrustAnchorRing;
begin
  SetLength(Result.FKeys, TrustAnchorCacheSize);
  SetLength(Result.FSets, TrustAnchorCacheSize);
  Result.FCount := 0;
  Result.FNext := 0;
end;

function TCertificatePathValidator.TTrustAnchorRing.TryGet(const AKey: TBytes;
  out AAnchors: TArray<ITrustAnchor>): Boolean;
var
  LI: Int32;
begin
  AAnchors := nil;
  for LI := 0 to FCount - 1 do
    if TArrayUtilities.AreEqual(FKeys[LI], AKey) then
    begin
      AAnchors := FSets[LI];
      Exit(True);
    end;
  Result := False;
end;

procedure TCertificatePathValidator.TTrustAnchorRing.Remember(const AKey: TBytes;
  const AAnchors: TArray<ITrustAnchor>);
begin
  FKeys[FNext] := AKey;
  FSets[FNext] := AAnchors;
  FNext := (FNext + 1) mod TrustAnchorCacheSize;
  if FCount < TrustAnchorCacheSize then
    Inc(FCount);
end;

class constructor TCertificatePathValidator.Create;
begin
  FTrustAnchors := TTrustAnchorRing.Init;
  FTrustAnchorLock := TCriticalSection.Create;
end;

class destructor TCertificatePathValidator.Destroy;
begin
  FTrustAnchorLock.Free;
end;

function TCertificatePathValidator.TrustAnchorKey(
  const ATrustAnchors: TArray<TBytes>): TBytes;
var
  LDigest: IDigest;
  LI, LN: Int32;
  LLen: TBytes;
begin
  LDigest := TDigestUtilities.GetDigest('SHA-256');
  System.SetLength(LLen, 4);
  for LI := 0 to System.High(ATrustAnchors) do
  begin
    // length-prefix each anchor so distinct groupings cannot alias one another
    LN := System.Length(ATrustAnchors[LI]);
    TBinaryPrimitives.WriteUInt32LittleEndian(LLen, 0, UInt32(LN));
    LDigest.BlockUpdate(LLen, 0, 4);
    if LN > 0 then
      LDigest.BlockUpdate(ATrustAnchors[LI], 0, LN);
  end;
  Result := LDigest.DoFinal;
end;

procedure TCertificatePathValidator.ValidateCertificatePath(const AChain,
  ATrustAnchors, AIntermediates: TArray<TBytes>; const AValidationTimeUtc: TDateTime;
  AKeyPurpose: TCertKeyPurpose; var AEffectiveChain: TArray<TBytes>);

  // the anchor is identified the way the path validator identifies it - by subject name and
  // public key, not by exact encoding - so a re-encoded or re-issued same-key root the peer
  // presents is recognised as the anchor (RFC 5280 6.1.1(d): anchor information is input, not a
  // validated path edge) and is exempt from the TLS-layer algorithm/EKU policy rather than policed
  // as an ordinary path certificate.
  function SameAnchorIdentity(const ACert, AAnchor: IX509Certificate): Boolean;
  begin
    Result := (AAnchor <> nil) and ACert.SubjectDN.Equivalent(AAnchor.SubjectDN, True) and
      TArrayUtilities.AreEqual(ACert.GetSubjectPublicKeyInfo.GetDerEncoded,
      AAnchor.GetSubjectPublicKeyInfo.GetDerEncoded);
  end;

  // the configured DER of the resolved anchor: the exact stored bytes, not a re-encoding, so the
  // downstream chain-algorithm policy (which exempts the anchor by exact bytes) recognises it even
  // when the stored root is not canonical DER
  function ResolvedAnchorDer(const AAnchor: IX509Certificate;
    const AParsedAnchors: TArray<ITrustAnchor>): TBytes;
  var
    LJ: Int32;
  begin
    Result := nil;
    if AAnchor = nil then
      Exit;
    for LJ := 0 to High(AParsedAnchors) do
      if TArrayUtilities.AreEqual(AParsedAnchors[LJ].TrustedCert.GetEncoded,
        AAnchor.GetEncoded) then
        Exit(ATrustAnchors[LJ]);
    Result := AAnchor.GetEncoded; // resolved anchor not among the stored set: fall back to its DER
  end;

  // build the effective chain leaf-first from the validated path, ending at the trust anchor the
  // validator resolved. Any copy of that anchor the peer included (possibly re-encoded) is dropped
  // and replaced by the configured DER, so the chain ends at the configured anchor exactly once -
  // what a key-pin over the validated path and an OS delegate both expect.
  procedure EmitPath(const APath: TArray<IX509Certificate>;
    const AAnchorCert: IX509Certificate; const AAnchorDer: TBytes);
  var
    LI, LN: Int32;
  begin
    AEffectiveChain := nil;
    SetLength(AEffectiveChain, System.Length(APath) + 1);
    LN := 0;
    for LI := 0 to High(APath) do
    begin
      // keep the leaf always; drop an anchor-identical copy the peer placed above it
      if (LI > 0) and SameAnchorIdentity(APath[LI], AAnchorCert) then
        Continue;
      AEffectiveChain[LN] := APath[LI].GetEncoded;
      Inc(LN);
    end;
    // append the configured anchor, unless the path is a directly-trusted (pinned) leaf that is
    // itself the anchor
    if (AAnchorCert <> nil) and
      not ((LN = 1) and SameAnchorIdentity(APath[0], AAnchorCert)) then
    begin
      AEffectiveChain[LN] := AAnchorDer;
      Inc(LN);
    end;
    SetLength(AEffectiveChain, LN);
  end;

  // RFC 5280 4.2.1.12 extendedKeyUsage, enforced over the validated path (leaf + every
  // intermediate, never the trust anchor): a certificate carrying an EKU extension must
  // include the role's purpose; one with no EKU extension is unrestricted. anyExtendedKeyUsage
  // is not accepted as a substitute, and a present-but-empty EKU is rejected.
  procedure EnforcePurpose(const APath: TArray<IX509Certificate>;
    const AAnchorCert: IX509Certificate);
  var
    LRequired: IDerObjectIdentifier;
    LI, LJ: Int32;
    LEkus: TArray<IDerObjectIdentifier>;
    LFound: Boolean;
    LCert: IX509Certificate;
  begin
    if AKeyPurpose = TCertKeyPurpose.ServerAuth then
      LRequired := TKeyPurposeId.IdKpServerAuth
    else
      LRequired := TKeyPurposeId.IdKpClientAuth;
    for LI := 0 to High(APath) do
    begin
      LCert := APath[LI];
      // a trust anchor is trusted by configuration, not by its own extensions, so its EKU is
      // not processed - but the end-entity at index 0 always is, even when it is itself the
      // pinned anchor (a directly-trusted leaf must still carry the required TLS role)
      if (LI > 0) and SameAnchorIdentity(LCert, AAnchorCert) then
        Continue;
      if LCert.GetExtensionValue(TX509Extensions.ExtendedKeyUsage) = nil then
        Continue; // no EKU extension -> unrestricted
      try
        LEkus := LCert.GetExtendedKeyUsage;
      except
        // a present-but-unparsable EKU (not a SEQUENCE OF OID) is a malformed certificate,
        // not an internal fault
        on E: ECryptoLibException do
          raise EFatalAlertTlsLibException.CreateRes(
            TTlsAlertDescription.BadCertificate, @SBadCertificate);
      end;
      LFound := False;
      for LJ := 0 to System.High(LEkus) do
        if LRequired.Equals(LEkus[LJ]) then
        begin
          LFound := True;
          Break;
        end;
      if not LFound then
        raise EFatalAlertTlsLibException.CreateRes(
          TTlsAlertDescription.UnsupportedCertificate, @SWrongCertificatePurpose);
    end;
  end;

const
  // the builder only reconstructs an INCOMPLETE chain, which is inherently shallow (a real
  // hierarchy is a leaf plus at most a few intermediates). Capping the built path's length
  // keeps a hostile peer that pads its chain with many like-named certificates from driving
  // the depth-first search into an expensive fan-out; depth 4 over a small pool is the real bound
  MaxBuiltPathLength = 4;
var
  LParser: IX509CertificateParser;
  LCerts, LPool, LInter: TArray<IX509Certificate>;
  LAnchors: TArray<ITrustAnchor>;
  LBuilt: TArray<IX509Certificate>;
  LAnchorKey: TBytes;
  LHit: Boolean;
  LTarget: IX509CertStoreSelector;
  LBuilderParams: IPkixBuilderParameters;
  LPoolStore: IStore<IX509Certificate>;
  LBuilder: IPkixCertPathBuilder;
  LBuildResult: IPkixCertPathBuilderResult;
  LI: Int32;
begin
  // by default the effective chain is the one the peer presented; a successful path build
  // (below) replaces it with the assembled leaf-to-anchor path
  AEffectiveChain := AChain;

  LParser := TX509CertificateParser.Create;
  try
    SetLength(LCerts, System.Length(AChain));
    for LI := 0 to High(AChain) do
      LCerts[LI] := LParser.ReadCertificate(AChain[LI]);
  except
    on E: ECryptoLibException do
      raise EFatalAlertTlsLibException.CreateRes(
        TTlsAlertDescription.BadCertificate, @SBadCertificate);
  end;

  if System.Length(ATrustAnchors) = 0 then
    raise EFatalAlertTlsLibException.CreateRes(
      TTlsAlertDescription.UnknownCa, @SUntrustedChain);

  // parsing the anchor store dominates a reused-config verify, so memoise the
  // parsed anchors keyed by a digest of the anchor set; the parse itself runs
  // outside the lock so concurrent cold verifies do not serialise on it
  LAnchorKey := TrustAnchorKey(ATrustAnchors);
  FTrustAnchorLock.Acquire;
  try
    LHit := FTrustAnchors.TryGet(LAnchorKey, LAnchors);
  finally
    FTrustAnchorLock.Release;
  end;

  if not LHit then
  begin
    try
      SetLength(LAnchors, System.Length(ATrustAnchors));
      for LI := 0 to High(ATrustAnchors) do
        LAnchors[LI] := TTrustAnchor.Create(
          LParser.ReadCertificate(ATrustAnchors[LI]), nil);
    except
      on E: ECryptoLibException do
        raise EFatalAlertTlsLibException.CreateRes(
          TTlsAlertDescription.UnknownCa, @SUntrustedChain);
    end;
    FTrustAnchorLock.Acquire;
    try
      FTrustAnchors.Remember(LAnchorKey, LAnchors);
    finally
      FTrustAnchorLock.Release;
    end;
  end;

  // parse any configured intermediates; they pool with the presented certificates so an
  // incomplete chain can still be completed to an anchor (the sans-IO stand-in for AIA fetching).
  // An out-of-window intermediate is left for the builder's path-time check, not pre-rejected:
  // a bundle may carry an unused stale entry that an otherwise-buildable path never touches.
  try
    SetLength(LInter, System.Length(AIntermediates));
    for LI := 0 to High(AIntermediates) do
      LInter[LI] := LParser.ReadCertificate(AIntermediates[LI]);
  except
    on E: ECryptoLibException do
      raise EFatalAlertTlsLibException.CreateRes(
        TTlsAlertDescription.UnknownCa, @SUntrustedChain);
  end;

  // one pool, one path: the presented certificates and the configured intermediates seed a
  // leaf-up build to a trusted anchor, so extraneous, misordered, expired-but-unused or
  // already-trusted extra certificates are simply left out of the built path rather than failing
  // an otherwise valid chain (RFC 8446 4.4.2 tolerates extraneous certificates and arbitrary order)
  SetLength(LPool, System.Length(LCerts) + System.Length(LInter));
  for LI := 0 to High(LCerts) do
    LPool[LI] := LCerts[LI];
  for LI := 0 to High(LInter) do
    LPool[System.Length(LCerts) + LI] := LInter[LI];

  try
    // the build targets the leaf the peer presented (index 0); the DFS is depth-capped so a
    // hostile pool of like-named fillers cannot fan it out
    LTarget := TX509CertStoreSelector.Create;
    LTarget.SetCertificate(LCerts[0]);
    LBuilderParams := TPkixBuilderParameters.Create(LAnchors, LTarget);
    LBuilderParams.SetIsRevocationEnabled(False);
    LBuilderParams.SetDate(AValidationTimeUtc);
    LBuilderParams.SetMaxPathLength(MaxBuiltPathLength);
    LPoolStore := TCollectionStore<IX509Certificate>.Create(LPool);
    LBuilderParams.AddStoreCert(LPoolStore);
    LBuilder := TPkixCertPathBuilder.Create as IPkixCertPathBuilder;
    LBuildResult := LBuilder.Build(LBuilderParams);
  except
    on E: ECryptoLibException do
    begin
      // the leaf is on every candidate path, so its own window decides expiry; an expired
      // certificate higher up is reported as expiry when no path built without it (the
      // transitional-chain case), otherwise nothing chained to a trusted anchor
      for LI := 0 to High(LCerts) do
        if not LCerts[LI].IsValid(AValidationTimeUtc) then
          raise EFatalAlertTlsLibException.CreateRes(
            TTlsAlertDescription.CertificateExpired, @SCertificateExpired);
      raise EFatalAlertTlsLibException.CreateRes(
        TTlsAlertDescription.UnknownCa, @SUntrustedChain);
    end;
  end;

  // the assembled path is leaf-first and excludes the anchor (EmitPath appends it), and must
  // start at the presented leaf - a path rooted at some other presented certificate is not a
  // validation of this peer's leaf
  LBuilt := LBuildResult.CertPath.Certificates;
  if (System.Length(LBuilt) = 0) or (LBuilt[0] <> LCerts[0]) then
    raise EFatalAlertTlsLibException.CreateRes(
      TTlsAlertDescription.UnknownCa, @SUntrustedChain);
  EnforcePurpose(LBuilt, LBuildResult.TrustAnchor.TrustedCert);
  EmitPath(LBuilt, LBuildResult.TrustAnchor.TrustedCert,
    ResolvedAnchorDer(LBuildResult.TrustAnchor.TrustedCert, LAnchors));
end;

class function TRevocationChecker.OcspDelegatedResponder(const AResponderCert,
  AIssuerCert: IX509Certificate; const AIssuerPublicKey: IAsymmetricKeyParameter;
  AValidityDate: TDateTime): Boolean;
var
  LKeyPurposes: TArray<IDerObjectIdentifier>;
  LI: Int32;
begin
  Result := False;
  // the delegation only holds if the issuer itself issued the responder certificate
  if not AResponderCert.IssuerDN.Equivalent(AIssuerCert.SubjectDN, True) then
    Exit;
  try
    AResponderCert.CheckValidity(AValidityDate);
    AResponderCert.Verify(AIssuerPublicKey);
    LKeyPurposes := AResponderCert.GetExtendedKeyUsage;
  except
    // a responder certificate that is out of date, does not verify against the
    // issuer, or exposes no extended key usage delegates nothing
    Exit;
  end;
  for LI := 0 to System.High(LKeyPurposes) do
    if TKeyPurposeId.IdKpOcspSigning.Equals(LKeyPurposes[LI]) then
    begin
      Result := True;
      Exit;
    end;
end;

class function TRevocationChecker.OcspResponseAuthorised(
  const AResponse: IBasicOcspResp; const AIssuerCert: IX509Certificate;
  const AIssuerPublicKey: IAsymmetricKeyParameter; AValidityDate: TDateTime): Boolean;
var
  LCerts: TArray<IX509Certificate>;
  LI: Int32;
begin
  Result := False;
  try
    if AResponse.Verify(AIssuerPublicKey) then
    begin
      Result := True;
      Exit;
    end;
  except
    // a signature this key cannot even be applied to is simply not the issuer's
  end;

  LCerts := AResponse.GetCerts;
  for LI := 0 to System.High(LCerts) do
  begin
    if not OcspDelegatedResponder(LCerts[LI], AIssuerCert, AIssuerPublicKey,
      AValidityDate) then
      Continue;
    try
      if AResponse.Verify(LCerts[LI].GetPublicKey) then
      begin
        Result := True;
        Exit;
      end;
    except
      // a delegated responder whose signature does not verify is not authoritative
    end;
  end;
end;

function TRevocationChecker.ValidateOcspStaple(const ALeafCert, AIssuerCert,
  AOcspResponseDer: TBytes; const AValidationTimeUtc: TDateTime;
  out AStatus: TOcspStatus; out AThisUpdate, ANextUpdate: TDateTime): Boolean;
var
  LParser: IX509CertificateParser;
  LLeaf, LIssuer: IX509Certificate;
  LResp: IOcspResp;
  LBasic: IBasicOcspResp;
  LSingles: TArray<ISingleResp>;
  LSingle: ISingleResp;
  LCertId: ICertificateID;
  LStatus: ICertificateStatus;
  LValidity: TDateTime;
  LI: Int32;
begin
  Result := False;
  AStatus := TOcspStatus.Unknown;
  AThisUpdate := 0;
  ANextUpdate := 0;
  if (System.Length(ALeafCert) = 0) or (System.Length(AIssuerCert) = 0) or
    (System.Length(AOcspResponseDer) = 0) then
    Exit;

  try
    LParser := TX509CertificateParser.Create;
    LLeaf := LParser.ReadCertificate(ALeafCert);
    LIssuer := LParser.ReadCertificate(AIssuerCert);

    LResp := TOcspResp.Create(AOcspResponseDer) as IOcspResp;
    if LResp.Status <> TOcspRespStatus.Successful then
      Exit;
    LBasic := LResp.GetResponseObject;
    if LBasic = nil then
      Exit;

    LValidity := AValidationTimeUtc;
    LSingles := LBasic.GetResponses;
    for LI := 0 to System.High(LSingles) do
    begin
      LSingle := LSingles[LI];
      LCertId := LSingle.GetCertID;
      // the staple must be about this leaf: matching serial and issuer name/key hash
      if not LLeaf.SerialNumber.Equals(LCertId.SerialNumber) then
        Continue;
      if not LCertId.MatchesIssuer(LIssuer) then
        Continue;
      // and it must be authoritative for that leaf
      if not OcspResponseAuthorised(LBasic, LIssuer, LIssuer.GetPublicKey,
        LValidity) then
        Exit;

      AThisUpdate := LSingle.ThisUpdate;
      // an omitted nextUpdate leaves no upper bound; 0 signals that to the caller
      if LSingle.NextUpdate.HasValue then
        ANextUpdate := LSingle.NextUpdate.Value
      else
        ANextUpdate := 0;

      LStatus := LSingle.GetCertStatus;
      if LStatus = nil then
        AStatus := TOcspStatus.Good
      else if Supports(LStatus, IRevokedStatus) then
        AStatus := TOcspStatus.Revoked
      else
        AStatus := TOcspStatus.Unknown;
      Result := True;
      Exit;
    end;
  except
    // a response that cannot be parsed leaves the status indeterminate, never raises
    Result := False;
    AStatus := TOcspStatus.Unknown;
    AThisUpdate := 0;
    ANextUpdate := 0;
  end;
end;

function TRevocationChecker.BuildOcspRequest(const ALeafCert,
  AIssuerCert: TBytes; out ARequestDer: TBytes): Boolean;
var
  LParser: IX509CertificateParser;
  LLeaf, LIssuer: IX509Certificate;
  LCertId: ICertificateID;
  LGen: IOcspReqGenerator;
begin
  Result := False;
  ARequestDer := nil;
  if (System.Length(ALeafCert) = 0) or (System.Length(AIssuerCert) = 0) then
    Exit;
  try
    LParser := TX509CertificateParser.Create;
    LLeaf := LParser.ReadCertificate(ALeafCert);
    LIssuer := LParser.ReadCertificate(AIssuerCert);
    // the CertID is the SHA-1 issuer name/key hash plus the leaf serial (RFC 6960 4.1.1)
    LCertId := TCertificateID.Create(TCertificateID.DigestSha1, LIssuer,
      LLeaf.SerialNumber) as ICertificateID;
    LGen := TOcspReqGenerator.Create as IOcspReqGenerator;
    LGen.AddRequest(LCertId);
    ARequestDer := LGen.Generate.GetEncoded;
    Result := System.Length(ARequestDer) > 0;
  except
    // a malformed input leaves no request; never raise a backend exception
    Result := False;
    ARequestDer := nil;
  end;
end;

function TRevocationChecker.TryGetOcspResponderUrl(const ACert: TBytes;
  out AUrl: string): Boolean;
var
  LParser: IX509CertificateParser;
  LCert: IX509Certificate;
  LExt: IAsn1OctetString;
  LAia: IAuthorityInformationAccess;
  LDescs: TCryptoLibGenericArray<IAccessDescription>;
  LLoc: IGeneralName;
  LIa5: IDerIA5String;
  LI: Int32;
begin
  Result := False;
  AUrl := '';
  if System.Length(ACert) = 0 then
    Exit;
  try
    LParser := TX509CertificateParser.Create;
    LCert := LParser.ReadCertificate(ACert);
    LExt := LCert.GetExtensionValue(TX509Extensions.AuthorityInfoAccess);
    if LExt = nil then
      Exit;
    LAia := TAuthorityInformationAccess.GetInstance(LExt.GetOctets);
    if LAia = nil then
      Exit;
    LDescs := LAia.GetAccessDescriptions;
    for LI := 0 to System.High(LDescs) do
      if TX509ObjectIdentifiers.IdADOcsp.Equals(LDescs[LI].GetAccessMethod) then
      begin
        LLoc := LDescs[LI].GetAccessLocation;
        if (LLoc <> nil) and (LLoc.GetTagNo = TGeneralName.UniformResourceIdentifier) and
          Supports(LLoc.GetName, IDerIA5String, LIa5) then
        begin
          AUrl := LIa5.GetString;
          if AUrl <> '' then
            Exit(True);
        end;
      end;
  except
    Result := False;
    AUrl := '';
  end;
end;

function TRevocationChecker.TryGetCrlDistributionPoints(const ACert: TBytes;
  out AUrls: TArray<string>): Boolean;
var
  LParser: IX509CertificateParser;
  LCert: IX509Certificate;
  LExt: IAsn1OctetString;
  LCdp: ICrlDistPoint;
  LPoints: TCryptoLibGenericArray<IDistributionPoint>;
  LDpn: IDistributionPointName;
  LGns: IGeneralNames;
  LNames: TCryptoLibGenericArray<IGeneralName>;
  LIa5: IDerIA5String;
  LI, LJ: Int32;
begin
  Result := False;
  AUrls := nil;
  if System.Length(ACert) = 0 then
    Exit;
  try
    LParser := TX509CertificateParser.Create;
    LCert := LParser.ReadCertificate(ACert);
    LExt := LCert.GetExtensionValue(TX509Extensions.CrlDistributionPoints);
    if LExt = nil then
      Exit;
    LCdp := TCrlDistPoint.GetInstance(LExt.GetOctets);
    if LCdp = nil then
      Exit;
    LPoints := LCdp.GetDistributionPoints;
    for LI := 0 to System.High(LPoints) do
    begin
      // a point naming a separate cRLIssuer yields an indirect CRL, which the scope check
      // never accepts (RFC 5280 6.3.3 (b)(1)), so fetching it would be wasted
      if LPoints[LI].GetCrlIssuer <> nil then
        Continue;
      LDpn := LPoints[LI].GetDistributionPointName;
      if (LDpn = nil) or (LDpn.GetType <> TDistributionPointName.FullName) then
        Continue;
      if not Supports(LDpn.GetName, IGeneralNames, LGns) then
        Continue;
      LNames := LGns.GetNames;
      for LJ := 0 to System.High(LNames) do
        if (LNames[LJ].GetTagNo = TGeneralName.UniformResourceIdentifier) and
          Supports(LNames[LJ].GetName, IDerIA5String, LIa5) and
          (LIa5.GetString <> '') then
          TArrayUtilities.Append<string>(AUrls, LIa5.GetString);
    end;
    Result := System.Length(AUrls) > 0;
  except
    Result := False;
    AUrls := nil;
  end;
end;

class function TRevocationChecker.IdpNameMatchesLeafDistributionPoint(
  const AIdpName: IDistributionPointName; const ALeaf: IX509Certificate): Boolean;
var
  LGns: IGeneralNames;
  LIdpNames, LDpNames: TCryptoLibGenericArray<IGeneralName>;
  LExt: IAsn1OctetString;
  LCdp: ICrlDistPoint;
  LPoints: TCryptoLibGenericArray<IDistributionPoint>;
  LDpn: IDistributionPointName;
  LI, LJ, LK: Int32;
begin
  Result := False;
  if not Supports(AIdpName.GetName, IGeneralNames, LGns) then
    Exit;
  LIdpNames := LGns.GetNames;
  LExt := ALeaf.GetExtensionValue(TX509Extensions.CrlDistributionPoints);
  if LExt = nil then
    Exit;
  LCdp := TCrlDistPoint.GetInstance(LExt.GetOctets);
  if LCdp = nil then
    Exit;
  LPoints := LCdp.GetDistributionPoints;
  for LI := 0 to System.High(LPoints) do
  begin
    // RFC 5280 6.3.3 (b)(1): a point that names a separate cRLIssuer or covers only some
    // reasons does not designate this issuer's complete CRL
    if (LPoints[LI].GetCrlIssuer <> nil) or (LPoints[LI].GetReasons <> nil) then
      Continue;
    LDpn := LPoints[LI].GetDistributionPointName;
    if (LDpn = nil) or (LDpn.GetType <> TDistributionPointName.FullName) then
      Continue;
    if not Supports(LDpn.GetName, IGeneralNames, LGns) then
      Continue;
    LDpNames := LGns.GetNames;
    for LJ := 0 to System.High(LIdpNames) do
      for LK := 0 to System.High(LDpNames) do
        if TArrayUtilities.AreEqual(LIdpNames[LJ].GetEncoded,
          LDpNames[LK].GetEncoded) then
          Exit(True);
  end;
end;

class function TRevocationChecker.CrlScopeCovers(const ALeaf,
  AIssuer: IX509Certificate; const ACrl: IX509Crl): Boolean;
const
  // RFC 5280 4.2.1.3 keyUsage bit order: cRLSign is bit 6
  CrlSignBit = 6;
var
  LKeyUsage: TCryptoLibBooleanArray;
  LCritical: TCryptoLibStringArray;
  LExt: IAsn1OctetString;
  LIdp: IIssuingDistributionPoint;
  LDpn: IDistributionPointName;
  LLeafIsCa: Boolean;
  LI: Int32;
begin
  Result := False;
  // RFC 5280 6.3.3 (b): a CRL not issued by the certificate's issuer says nothing about it
  if not ACrl.IssuerDN.Equivalent(ALeaf.IssuerDN, True) then
    Exit;
  // RFC 5280 6.3.3 (f): when the issuer restricts its key usage it must permit cRLSign; a
  // bit past the encoded length is an omitted trailing zero, i.e. not asserted
  LKeyUsage := AIssuer.GetKeyUsage;
  if (LKeyUsage <> nil) and
    ((CrlSignBit > System.High(LKeyUsage)) or (not LKeyUsage[CrlSignBit])) then
    Exit;
  // RFC 5280 5.2: a critical extension this check cannot process makes the CRL unusable
  LCritical := ACrl.GetCriticalExtensionOids;
  for LI := 0 to System.High(LCritical) do
    if (LCritical[LI] <> TX509Extensions.IssuingDistributionPoint.ID) and
      (LCritical[LI] <> TX509Extensions.AuthorityKeyIdentifier.ID) then
      Exit;
  // RFC 5280 5.2.4: a delta CRL is never complete on its own
  if ACrl.GetExtensionValue(TX509Extensions.DeltaCrlIndicator) <> nil then
    Exit;
  LExt := ACrl.GetExtensionValue(TX509Extensions.IssuingDistributionPoint);
  if LExt = nil then
    Exit(True);
  LIdp := TIssuingDistributionPoint.GetInstance(LExt.GetOctets);
  if LIdp = nil then
    Exit;
  // RFC 5280 6.3.3 (b)(2): an indirect, attribute-certificate or partial-reasons CRL is
  // not the complete CRL for this leaf
  if LIdp.IsIndirectCrl or LIdp.OnlyContainsAttributeCerts or
    (LIdp.OnlySomeReasons <> nil) then
    Exit;
  LLeafIsCa := ALeaf.GetBasicConstraints >= 0;
  if LIdp.OnlyContainsCACerts and (not LLeafIsCa) then
    Exit;
  if LIdp.OnlyContainsUserCerts and LLeafIsCa then
    Exit;
  LDpn := LIdp.DistributionPoint;
  // no distribution point: the CRL covers the issuer's whole scope
  if LDpn = nil then
    Exit(True);
  // RFC 5280 6.3.3 (b)(2)(i): the IDP must name a point the leaf's own CRL distribution
  // points designate; a relative name cannot be matched against a leaf full name
  if LDpn.GetType <> TDistributionPointName.FullName then
    Exit;
  Result := IdpNameMatchesLeafDistributionPoint(LDpn, ALeaf);
end;

class function TRevocationChecker.CrlEntryRevokes(const AEntry: IX509CrlEntry;
  out ARevoked: Boolean): Boolean;
var
  LExts: IX509Extensions;
  LReason: IAsn1OctetString;
  LEnum: IDerEnumerated;
begin
  Result := False;
  ARevoked := False;
  LExts := AEntry.CrlEntry.Extensions;
  // RFC 5280 5.3: no critical entry extension is processed here, so any makes the entry
  // (and thus the CRL) unusable for this leaf
  if (LExts <> nil) and (System.Length(LExts.GetCriticalExtensionOids) > 0) then
    Exit;
  ARevoked := True;
  LReason := AEntry.GetExtensionValue(TX509Extensions.ReasonCode);
  if LReason <> nil then
  begin
    try
      LEnum := TDerEnumerated.GetInstance(LReason.GetOctets);
      // RFC 5280 5.3.1: removeFromCRL lifts a certificateHold; every other reason, including
      // certificateHold itself and an absent reason, is a revocation
      if (LEnum <> nil) and LEnum.HasValue(TCrlReason.RemoveFromCrl) then
        ARevoked := False;
    except
      // a malformed reasonCode does not un-list a listed entry: it stays revoked
      on E: ECryptoLibException do
        ARevoked := True;
    end;
  end;
  Result := True;
end;

function TRevocationChecker.CheckCrlRevocation(const ALeafCert, AIssuerCert,
  ACrlDer: TBytes; const AValidationTimeUtc: TDateTime; out ARevoked: Boolean;
  out AThisUpdate, ANextUpdate: TDateTime): Boolean;
var
  LParser: IX509CertificateParser;
  LLeaf, LIssuer: IX509Certificate;
  LCrlParser: IX509CrlParser;
  LCrl: IX509Crl;
  LEntry: IX509CrlEntry;
  LNowMs: Int64;
begin
  Result := False;
  ARevoked := False;
  AThisUpdate := 0;
  ANextUpdate := 0;
  if (System.Length(ALeafCert) = 0) or (System.Length(AIssuerCert) = 0) or
    (System.Length(ACrlDer) = 0) then
    Exit;
  try
    LParser := TX509CertificateParser.Create;
    LLeaf := LParser.ReadCertificate(ALeafCert);
    LIssuer := LParser.ReadCertificate(AIssuerCert);
    LCrlParser := TX509CrlParser.Create;
    LCrl := LCrlParser.ReadCrl(ACrlDer);
    if LCrl = nil then
      Exit;
    // the CRL must be signed by the leaf's issuer to be authoritative
    if not LCrl.IsSignatureValid(LIssuer.GetPublicKey) then
      Exit;
    // a validly signed CRL of the wrong scope (another shard, CA-only, indirect, delta...) is
    // not authoritative: a substituted one would otherwise read as a silent Good
    if not CrlScopeCovers(LLeaf, LIssuer, LCrl) then
      Exit;
    AThisUpdate := LCrl.ThisUpdate;
    if LCrl.NextUpdate.HasValue then
      ANextUpdate := LCrl.NextUpdate.Value;
    // honor the CRL validity window at the injected validation time (mirrors the OCSP
    // thisUpdate/nextUpdate check): a validly signed but not-yet-valid or expired CRL is never
    // authoritative - a MITM could otherwise replay an old, legitimately-signed CRL predating
    // the revocation. Out of window -> False (indeterminate), never a silent Good.
    LNowMs := TDateTimeUtilities.DateTimeToUnixMs(AValidationTimeUtc);
    if LNowMs < TDateTimeUtilities.DateTimeToUnixMs(AThisUpdate) then
      Exit;
    if LCrl.NextUpdate.HasValue and
      (LNowMs >= TDateTimeUtilities.DateTimeToUnixMs(ANextUpdate)) then
      Exit;
    LEntry := LCrl.GetRevokedCertificate(LLeaf.SerialNumber);
    if LEntry = nil then
      ARevoked := False
    else if not CrlEntryRevokes(LEntry, ARevoked) then
      Exit;
    Result := True;
  except
    // an unparseable or unverifiable CRL is indeterminate, never a raise
    Result := False;
    ARevoked := False;
    AThisUpdate := 0;
    ANextUpdate := 0;
  end;
end;

function TRevocationChecker.TryFindIssuer(const ALeafCert: TBytes;
  const ACandidates: TArray<TBytes>; out AIssuerCert: TBytes): Boolean;
var
  LParser: IX509CertificateParser;
  LLeaf, LCandidate: IX509Certificate;
  LI: Int32;
begin
  Result := False;
  AIssuerCert := nil;
  if System.Length(ALeafCert) = 0 then
    Exit;
  try
    LParser := TX509CertificateParser.Create;
    LLeaf := LParser.ReadCertificate(ALeafCert);
    for LI := 0 to System.High(ACandidates) do
    begin
      if System.Length(ACandidates[LI]) = 0 then
        Continue;
      LCandidate := LParser.ReadCertificate(ACandidates[LI]);
      // name match is a prefilter only; the candidate is the issuer solely when its key verifies the
      // leaf's signature, so a same-name/wrong-key candidate is rejected - that keeps the OCSP CertID
      // issuerKeyHash bound to the true signer (a wrong pick could otherwise mis-key the request)
      if not LLeaf.IssuerDN.Equivalent(LCandidate.SubjectDN, True) then
        Continue;
      try
        LLeaf.Verify(LCandidate.GetPublicKey);
      except
        // this candidate did not sign the leaf; keep looking
        Continue;
      end;
      AIssuerCert := ACandidates[LI];
      Result := True;
      Exit;
    end;
  except
    // a malformed leaf or candidate leaves the issuer unresolved, never raises
    Result := False;
    AIssuerCert := nil;
  end;
end;

function TCertificateInspector.PeerInfo(const ACertificateDer: TBytes;
  out ASubject, AIssuer, ACommonName, ASerialHex: string): Boolean;
begin
  try
    Result := Parse(ACertificateDer).PeerInfo(ASubject, AIssuer, ACommonName,
      ASerialHex);
  except
    Result := False;
    ASubject := '';
    AIssuer := '';
    ACommonName := '';
    ASerialHex := '';
  end;
end;

function TCertificateInspector.TlsFeatures(const ACert: TBytes;
  out AFeatures: TArray<UInt16>): Boolean;
var
  LParser: IX509CertificateParser;
  LCert: IX509Certificate;
  LExtValue: IAsn1OctetString;
  LObj: IAsn1Object;
  LSeq: IAsn1Sequence;
  LInt: IDerInteger;
  LI, LValue: Int32;
begin
  Result := False;
  AFeatures := nil;
  try
    LParser := TX509CertificateParser.Create;
    LCert := LParser.ReadCertificate(ACert);
    LExtValue := LCert.GetExtensionValue(
      TDerObjectIdentifier.Create(TlsFeatureExtensionOid) as IDerObjectIdentifier);
    if LExtValue = nil then
    begin
      // an absent extension is well-formed with no features
      Result := True;
      Exit;
    end;

    LObj := TAsn1Object.FromByteArray(LExtValue.GetOctets);
    if not Supports(LObj, IAsn1Sequence, LSeq) then
      // present but not a SEQUENCE: malformed TLS Feature
      Exit;

    SetLength(AFeatures, LSeq.Count);
    for LI := 0 to LSeq.Count - 1 do
    begin
      if not Supports(LSeq.Items[LI], IDerInteger, LInt) then
      begin
        AFeatures := nil;
        Exit;
      end;
      if (not LInt.TryGetIntValueExact(LValue)) or (LValue < 0) or
        (LValue > $FFFF) then
      begin
        AFeatures := nil;
        Exit;
      end;
      AFeatures[LI] := UInt16(LValue);
    end;
    Result := True;
  except
    // a present-but-unparseable TLS Feature value is malformed
    AFeatures := nil;
    Result := False;
  end;
end;

function TCertificateInspector.KeyUsagePermits(
  const ACertificateDer: TBytes; AUsage: TCertKeyUsage): TCertAnswer;
begin
  try
    Result := Parse(ACertificateDer).KeyUsagePermits(AUsage);
  except
    // an unparseable certificate cannot be determined; imposes no restriction
    Result := TCertAnswer.Undetermined;
  end;
end;

function TCertificateInspector.KeyIsRsaPss(
  const ACertificateDer: TBytes): TCertAnswer;
begin
  try
    Result := Parse(ACertificateDer).KeyIsRsaPss;
  except
    // an unparseable certificate cannot be determined
    Result := TCertAnswer.Undetermined;
  end;
end;

function TCertificateInspector.KeyKind(const ACertificateDer: TBytes;
  out AKind: TSignatureKeyKind; out AEcNamedGroup: UInt16): Boolean;
begin
  try
    Result := Parse(ACertificateDer).KeyKind(AKind, AEcNamedGroup);
  except
    // an unparseable certificate cannot be classified
    AKind := TSignatureKeyKind.Rsa;
    AEcNamedGroup := 0;
    Result := False;
  end;
end;

function TInspectedCertificate.KeyUsagePermits(AUsage: TCertKeyUsage): TCertAnswer;
var
  LBits: TArray<Boolean>;
  LIndex: Int32;
begin
  try
    LBits := FCert.GetKeyUsage; // nil when the keyUsage extension is absent
  except
    Exit(TCertAnswer.Undetermined);
  end;
  // an absent extension imposes no restriction
  if LBits = nil then
    Exit(TCertAnswer.Yes);
  // RFC 5280 4.2.1.3 bit order: digitalSignature(0), keyEncipherment(2), keyAgreement(4)
  case AUsage of
    TCertKeyUsage.DigitalSignature:
      LIndex := 0;
    TCertKeyUsage.KeyEncipherment:
      LIndex := 2;
    TCertKeyUsage.KeyAgreement:
      LIndex := 4;
  else
    LIndex := -1;
  end;
  // the extension is present, so the bit must be asserted; a bit past the encoded
  // length is an omitted trailing zero, i.e. not asserted
  if (LIndex >= 0) and (LIndex <= High(LBits)) and LBits[LIndex] then
    Result := TCertAnswer.Yes
  else
    Result := TCertAnswer.No;
end;

function TInspectedCertificate.KeyIsRsaPss: TCertAnswer;
begin
  try
    if FCert.GetSubjectPublicKeyInfo.GetAlgorithm.GetAlgorithm.GetID
      = RsaSsaPssKeyOid then
      Result := TCertAnswer.Yes
    else
      Result := TCertAnswer.No;
  except
    Result := TCertAnswer.Undetermined;
  end;
end;

function TInspectedCertificate.PeerInfo(out ASubject, AIssuer, ACommonName,
  ASerialHex: string): Boolean;
var
  LCns: TCryptoLibStringArray;
begin
  ASubject := '';
  AIssuer := '';
  ACommonName := '';
  ASerialHex := '';
  try
    ASubject := FCert.SubjectDN.ToString;
    AIssuer := FCert.IssuerDN.ToString;
    LCns := FCert.SubjectDN.GetValueList(TX509Name.CN);
    if System.Length(LCns) > 0 then
      ACommonName := LCns[0];
    ASerialHex := FCert.SerialNumber.ToString(16);
    Result := True;
  except
    Result := False;
    ASubject := '';
    AIssuer := '';
    ACommonName := '';
    ASerialHex := '';
  end;
end;

function TInspectedCertificate.KeyKind(out AKind: TSignatureKeyKind;
  out AEcNamedGroup: UInt16): Boolean;
var
  LAlg: IAlgorithmIdentifier;
  LOid, LCurve: IDerObjectIdentifier;
begin
  AKind := TSignatureKeyKind.Rsa; // ignored unless Result is True
  AEcNamedGroup := 0;
  try
    LAlg := FCert.GetSubjectPublicKeyInfo.GetAlgorithm;
    LOid := LAlg.Algorithm;
  except
    Exit(False);
  end;
  Result := True;
  if LOid.Equals(TPkcsObjectIdentifiers.RsaEncryption) or
    (LOid.GetID = RsaSsaPssKeyOid) then
    AKind := TSignatureKeyKind.Rsa
  else if LOid.Equals(TEdECObjectIdentifiers.IdEd25519) then
    AKind := TSignatureKeyKind.Ed25519
  else if LOid.Equals(TEdECObjectIdentifiers.IdEd448) then
    AKind := TSignatureKeyKind.Ed448
  else if LOid.Equals(TX9ObjectIdentifiers.IdECPublicKey) and (LAlg.Parameters <> nil) and
    Supports(LAlg.Parameters.ToAsn1Object, IDerObjectIdentifier, LCurve) then
  begin
    AKind := TSignatureKeyKind.Ecdsa;
    // the leaf's named curve as an IANA supported_groups code; 0 when unrecognized
    if LCurve.Equals(TX9ObjectIdentifiers.Prime256v1) then
      AEcNamedGroup := TNamedGroupCatalog.Secp256r1
    else if LCurve.Equals(TSecObjectIdentifiers.SecP384r1) then
      AEcNamedGroup := TNamedGroupCatalog.Secp384r1
    else if LCurve.Equals(TSecObjectIdentifiers.SecP521r1) then
      AEcNamedGroup := TNamedGroupCatalog.Secp521r1;
  end
  else
    // a parseable certificate whose key algorithm we do not model is not classified
    Result := False;
end;

function TInspectedCertificate.KeyFacts(out AFacts: TCertKeyFacts): Boolean;
var
  LRsa: IRsaKeyParameters;
begin
  AFacts.Bits := 0;
  if not KeyKind(AFacts.Kind, AFacts.EcNamedGroup) then
    Exit(False);
  try
    case AFacts.Kind of
      TSignatureKeyKind.Rsa:
        if Supports(FCert.GetPublicKey, IRsaKeyParameters, LRsa) then
          AFacts.Bits := LRsa.Modulus.BitLength
        else
          Exit(False);
      TSignatureKeyKind.Ecdsa:
        // field size follows the recognised named curve; an unrecognised curve stays 0
        case AFacts.EcNamedGroup of
          TNamedGroupCatalog.Secp256r1:
            AFacts.Bits := 256;
          TNamedGroupCatalog.Secp384r1:
            AFacts.Bits := 384;
          TNamedGroupCatalog.Secp521r1:
            AFacts.Bits := 521;
        end;
    end;
    Result := True;
  except
    Result := False;
  end;
end;

function TInspectedCertificate.SignatureFacts(out AFacts: TCertSignatureFacts): Boolean;
var
  LSig: IAlgorithmIdentifier;
  LOid: IDerObjectIdentifier;

  function HashOf(const AOid: IDerObjectIdentifier;
    out AHash: TCertSignatureHash): Boolean;
  begin
    Result := True;
    if AOid.Equals(TOiwObjectIdentifiers.IdSha1) then
      AHash := TCertSignatureHash.Sha1
    else if AOid.Equals(TNistObjectIdentifiers.IdSha224) then
      AHash := TCertSignatureHash.Sha224
    else if AOid.Equals(TNistObjectIdentifiers.IdSha256) then
      AHash := TCertSignatureHash.Sha256
    else if AOid.Equals(TNistObjectIdentifiers.IdSha384) then
      AHash := TCertSignatureHash.Sha384
    else if AOid.Equals(TNistObjectIdentifiers.IdSha512) then
      AHash := TCertSignatureHash.Sha512
    else
      Result := False;
  end;

  function DigestLen(AHash: TCertSignatureHash): Int32;
  begin
    case AHash of
      TCertSignatureHash.Sha1:
        Result := 20;
      TCertSignatureHash.Sha224:
        Result := 28;
      TCertSignatureHash.Sha256:
        Result := 32;
      TCertSignatureHash.Sha384:
        Result := 48;
      TCertSignatureHash.Sha512:
        Result := 64;
    else
      Result := 0;
    end;
  end;

  function FillPss(const APss: IAlgorithmIdentifier): Boolean;
  var
    LParams: IRsassaPssParameters;
    LMgfHash: IAlgorithmIdentifier;
  begin
    AFacts.Family := TCertSignatureFamily.RsaPss;
    AFacts.PssCanonical := False;
    // RFC 4055: absent parameters default every field to SHA-1
    if APss.Parameters = nil then
    begin
      AFacts.Hash := TCertSignatureHash.Sha1;
      Exit(True);
    end;
    LParams := TRsassaPssParameters.GetInstance(APss.Parameters.ToAsn1Object);
    if not HashOf(LParams.HashAlgorithm.Algorithm, AFacts.Hash) then
      Exit(False);
    // canonical iff MGF1 is over the same hash and the salt length equals the digest length;
    // anything else leaves PssCanonical False so the chain-algorithm filter rejects it
    if LParams.MaskGenAlgorithm.Algorithm.Equals(TPkcsObjectIdentifiers.IdMgf1) then
    begin
      LMgfHash := TAlgorithmIdentifier.GetInstance(
        LParams.MaskGenAlgorithm.Parameters.ToAsn1Object);
      AFacts.PssCanonical := LMgfHash.Algorithm.Equals(LParams.HashAlgorithm.Algorithm) and
        (LParams.SaltLength <> nil) and
        LParams.SaltLength.Value.Equals(TBigInteger.ValueOf(DigestLen(AFacts.Hash)));
    end;
    Result := True;
  end;

begin
  AFacts.Family := TCertSignatureFamily.RsaPkcs1;
  AFacts.Hash := TCertSignatureHash.Sha256;
  AFacts.PssCanonical := False;
  try
    LSig := FCert.GetSignatureAlgorithm;
    LOid := LSig.Algorithm;
    Result := True;
    if LOid.Equals(TPkcsObjectIdentifiers.Sha256WithRsaEncryption) then
      AFacts.Hash := TCertSignatureHash.Sha256
    else if LOid.Equals(TPkcsObjectIdentifiers.Sha384WithRsaEncryption) then
      AFacts.Hash := TCertSignatureHash.Sha384
    else if LOid.Equals(TPkcsObjectIdentifiers.Sha512WithRsaEncryption) then
      AFacts.Hash := TCertSignatureHash.Sha512
    else if LOid.Equals(TPkcsObjectIdentifiers.Sha224WithRsaEncryption) then
      AFacts.Hash := TCertSignatureHash.Sha224
    else if LOid.Equals(TPkcsObjectIdentifiers.Sha1WithRsaEncryption) then
      AFacts.Hash := TCertSignatureHash.Sha1
    else if LOid.Equals(TPkcsObjectIdentifiers.MD5WithRsaEncryption) then
      AFacts.Hash := TCertSignatureHash.Md5
    else if LOid.Equals(TX9ObjectIdentifiers.ECDsaWithSha256) then
    begin
      AFacts.Family := TCertSignatureFamily.Ecdsa;
      AFacts.Hash := TCertSignatureHash.Sha256;
    end
    else if LOid.Equals(TX9ObjectIdentifiers.ECDsaWithSha384) then
    begin
      AFacts.Family := TCertSignatureFamily.Ecdsa;
      AFacts.Hash := TCertSignatureHash.Sha384;
    end
    else if LOid.Equals(TX9ObjectIdentifiers.ECDsaWithSha512) then
    begin
      AFacts.Family := TCertSignatureFamily.Ecdsa;
      AFacts.Hash := TCertSignatureHash.Sha512;
    end
    else if LOid.Equals(TX9ObjectIdentifiers.ECDsaWithSha224) then
    begin
      AFacts.Family := TCertSignatureFamily.Ecdsa;
      AFacts.Hash := TCertSignatureHash.Sha224;
    end
    else if LOid.Equals(TX9ObjectIdentifiers.ECDsaWithSha1) then
    begin
      AFacts.Family := TCertSignatureFamily.Ecdsa;
      AFacts.Hash := TCertSignatureHash.Sha1;
    end
    else if LOid.Equals(TEdECObjectIdentifiers.IdEd25519) then
    begin
      AFacts.Family := TCertSignatureFamily.Ed25519;
      AFacts.Hash := TCertSignatureHash.Implicit;
    end
    else if LOid.Equals(TEdECObjectIdentifiers.IdEd448) then
    begin
      AFacts.Family := TCertSignatureFamily.Ed448;
      AFacts.Hash := TCertSignatureHash.Implicit;
    end
    else if LOid.Equals(TPkcsObjectIdentifiers.IdRsassaPss) then
      Result := FillPss(LSig)
    else
      Result := False;
  except
    Result := False;
  end;
end;

{ TDefaultPkixProvider }

constructor TDefaultPkixProvider.Create(const AOverrides: TPkixProviderOverrides);
begin
  inherited Create;
  if AOverrides.Inspector <> nil then
    FInspector := AOverrides.Inspector
  else
    FInspector := TCertificateInspector.Create as ICertificateInspector;

  if AOverrides.PathValidation <> nil then
    FPathValidation := AOverrides.PathValidation
  else
    FPathValidation := TCertificatePathValidator.Create as ICertificatePathValidator;

  if AOverrides.Revocation <> nil then
    FRevocation := AOverrides.Revocation
  else
    FRevocation := TRevocationChecker.Create as IRevocationChecker;
end;

constructor TDefaultPkixProvider.Create;
var
  LOverrides: TPkixProviderOverrides;
begin
  LOverrides := Default(TPkixProviderOverrides);
  Create(LOverrides);
end;

class constructor TDefaultPkixProvider.Create;
begin
  FSharedLock := TCriticalSection.Create;
end;

class destructor TDefaultPkixProvider.Destroy;
begin
  FShared := nil;
  FSharedLock.Free;
end;

class function TDefaultPkixProvider.Shared: IPkixProvider;
begin
  FSharedLock.Acquire;
  try
    if FShared = nil then
      FShared := TDefaultPkixProvider.Create as IPkixProvider;
    Result := FShared;
  finally
    FSharedLock.Release;
  end;
end;

function TDefaultPkixProvider.Certificates: ICertificateInspector;
begin
  Result := FInspector;
end;

function TDefaultPkixProvider.PathValidation: ICertificatePathValidator;
begin
  Result := FPathValidation;
end;

function TDefaultPkixProvider.Revocation: IRevocationChecker;
begin
  Result := FRevocation;
end;

{ TPkixProviderBuilder }

function TPkixProviderBuilder.WithInspector(
  const AInspector: ICertificateInspector): IPkixProviderBuilder;
begin
  FOverrides.Inspector := AInspector;
  Result := Self;
end;

function TPkixProviderBuilder.WithPathValidation(
  const APathValidation: ICertificatePathValidator): IPkixProviderBuilder;
begin
  FOverrides.PathValidation := APathValidation;
  Result := Self;
end;

function TPkixProviderBuilder.WithRevocation(
  const ARevocation: IRevocationChecker): IPkixProviderBuilder;
begin
  FOverrides.Revocation := ARevocation;
  Result := Self;
end;

function TPkixProviderBuilder.Build: IPkixProvider;
begin
  Result := TDefaultPkixProvider.Create(FOverrides) as IPkixProvider;
end;

end.
