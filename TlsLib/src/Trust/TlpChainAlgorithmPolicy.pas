{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpChainAlgorithmPolicy;

{$I ..\Include\TlsLib.inc}

interface

uses
  SysUtils,
  TlpArrayUtilities,
  TlpCryptoDomainTypes,
  TlpPkixDomainTypes,
  TlpIPkixProvider,
  TlpNegotiationTypes,
  TlpCertificateStrengthPolicy,
  TlpTlsAlert;

type
  /// <summary>
  /// Enforces the chain-algorithm policy over an already path-validated peer chain: every leaf
  /// and intermediate must be signed with a signature scheme the endpoint advertised (RFC 9846
  /// 4.5.1.2, RFC 5246 7.4.2 / 7.4.4 / 7.4.6), an MD5-signed certificate is refused
  /// outright and a SHA-1-signed one unless the policy admits it (RFC 9846 4.5.1.3), and each
  /// subject key must meet the configured minimum-strength floors. A configured trust anchor is
  /// exempt (its self-signature is not a validated edge and its key is the operator's trust)
  /// unless the policy's AnchorKeyFloors holds its key to the floors; the leaf never is exempt.
  /// It only decides accept/reject and the alert, reading facts from the provider's certificate
  /// inspector so no ASN.1 is handled here.
  /// </summary>
  TChainAlgorithmPolicy = class sealed(TObject)
  strict private
    class function IsAnchor(const ADer: TBytes; const ARoots: TArray<TBytes>): Boolean; static;
    class function LegacySha1Scheme(AFamily: TCertSignatureFamily): UInt16; static;
    class function CheckCertificate(const AInspector: ICertificateInspector;
      const ADer: TBytes; AIssuerKeyIsPss: Boolean;
      const APolicy: TCertificateStrengthPolicy; AFilterSchemes: Boolean;
      const AAdvertised: TArray<UInt16>; out AAlert: TTlsAlertDescription): Boolean; static;
    class function CheckKey(const ACert: IInspectedCertificate;
      const APolicy: TCertificateStrengthPolicy; AUnreadable: TTlsAlertDescription;
      out AAlert: TTlsAlertDescription): Boolean; static;
    class function CheckAnchorKey(const AInspector: ICertificateInspector;
      const ADer: TBytes; const APolicy: TCertificateStrengthPolicy;
      out AAlert: TTlsAlertDescription): Boolean; static;
    class function Walk(const AInspector: ICertificateInspector;
      const AChain, ARoots: TArray<TBytes>;
      const APolicy: TCertificateStrengthPolicy; AFilterSchemes: Boolean;
      const AAdvertised: TArray<UInt16>; out AAlert: TTlsAlertDescription): Boolean; static;
  public
    /// <summary>
    /// The one signature scheme that can have signed a certificate with this family and hash, or 0
    /// when none can: a non-canonical RSA-PSS signature, a hash no scheme names, or a family
    /// outside the schemes. The hash is ignored for EdDSA. A canonical RSA-PSS signature under a
    /// PSS-restricted issuer key (AIssuerKeyIsPss) is an rsa_pss_pss_* scheme, otherwise
    /// rsa_pss_rsae_*; ECDSA is keyed on the hash alone, whatever the issuer curve.
    /// </summary>
    class function RequiredScheme(AFamily: TCertSignatureFamily;
      AHash: TCertSignatureHash; APssCanonical: Boolean;
      AIssuerKeyIsPss: Boolean): UInt16; static;
    class function Check(const AInspector: ICertificateInspector;
      const AChain, ARoots: TArray<TBytes>;
      const APolicy: TCertificateStrengthPolicy;
      const AAdvertised: TArray<UInt16>; out AAlert: TTlsAlertDescription): Boolean; static;
    /// <summary>
    /// The always-on floor for a verifier with no advertised-scheme set: the MD5/SHA-1 refusal and
    /// the default key-strength floors, without the advertised-scheme filter.
    /// </summary>
    class function CheckBaseline(const AInspector: ICertificateInspector;
      const AChain, ARoots: TArray<TBytes>;
      out AAlert: TTlsAlertDescription): Boolean; static;
    /// <summary>
    /// Whether every anchor's key meets the key-strength floors; True when APolicy does not set
    /// AnchorKeyFloors or AAnchors is empty. An anchor that cannot be parsed is bad_certificate;
    /// one whose key cannot be described or is below the floors is unsupported_certificate.
    /// </summary>
    class function AnchorsMeetKeyFloors(const AInspector: ICertificateInspector;
      const AAnchors: TArray<TBytes>; const APolicy: TCertificateStrengthPolicy;
      out AAlert: TTlsAlertDescription): Boolean; static;
    /// <summary>
    /// Whether we may send AChain: no certificate other than a self-signed one (verifies under its
    /// own key, RFC 5280 3.2; treated as a path start, as RFC 9846 4.3.3 does) is signed with MD5,
    /// or with SHA-1 the peer did not advertise in APeerCertSchemes (RFC 9846 4.5.1.2; MD5
    /// inferred from 4.5.1.3). A certificate whose signature cannot be determined is not refused.
    /// </summary>
    class function SendableTo(const AInspector: ICertificateInspector;
      const AChain: TArray<TBytes>; const APeerCertSchemes: TArray<UInt16>): Boolean; static;
  end;

  /// <summary>
  /// The end-entity rule over a validated path, shared by the built-in verifier and the OS
  /// delegates: the certificate at index 0 must not assert basicConstraints cA=TRUE (RFC 5280
  /// 4.2.1.9), so a sub-CA certificate cannot be served as a server or client identity. The one
  /// exception is a leaf that is itself a configured trust anchor (a directly trusted
  /// self-signed certificate, which many generators mark as a CA). An
  /// undeterminable answer is refused.
  /// </summary>
  TEndEntityPolicy = class sealed(TObject)
  public
    class function Admits(const AInspector: ICertificateInspector;
      const APath, ARoots: TArray<TBytes>; out AAlert: TTlsAlertDescription): Boolean; static;
  end;

implementation

{ TChainAlgorithmPolicy }

class function TChainAlgorithmPolicy.IsAnchor(const ADer: TBytes;
  const ARoots: TArray<TBytes>): Boolean;
var
  LI: Int32;
begin
  Result := False;
  for LI := 0 to System.Length(ARoots) - 1 do
    if TArrayUtilities.AreEqual(ADer, ARoots[LI]) then
      Exit(True);
end;

class function TChainAlgorithmPolicy.RequiredScheme(AFamily: TCertSignatureFamily;
  AHash: TCertSignatureHash; APssCanonical: Boolean;
  AIssuerKeyIsPss: Boolean): UInt16;
begin
  Result := 0; // 0 = no advertised scheme can satisfy this signature
  case AFamily of
    TCertSignatureFamily.RsaPkcs1:
      case AHash of
        TCertSignatureHash.Sha256:
          Result := TSignatureSchemes.RsaPkcs1Sha256;
        TCertSignatureHash.Sha384:
          Result := TSignatureSchemes.RsaPkcs1Sha384;
        TCertSignatureHash.Sha512:
          Result := TSignatureSchemes.RsaPkcs1Sha512;
      end;
    TCertSignatureFamily.RsaPss:
      // a non-canonical PSS (wrong MGF/salt, or absent params defaulting to SHA-1) has no match;
      // a PSS-restricted issuer key signs with rsa_pss_pss_*, an rsaEncryption issuer with rsae
      if APssCanonical then
        if AIssuerKeyIsPss then
          case AHash of
            TCertSignatureHash.Sha256:
              Result := TSignatureSchemes.RsaPssPssSha256;
            TCertSignatureHash.Sha384:
              Result := TSignatureSchemes.RsaPssPssSha384;
            TCertSignatureHash.Sha512:
              Result := TSignatureSchemes.RsaPssPssSha512;
          end
        else
          case AHash of
            TCertSignatureHash.Sha256:
              Result := TSignatureSchemes.RsaPssRsaeSha256;
            TCertSignatureHash.Sha384:
              Result := TSignatureSchemes.RsaPssRsaeSha384;
            TCertSignatureHash.Sha512:
              Result := TSignatureSchemes.RsaPssRsaeSha512;
          end;
    TCertSignatureFamily.Ecdsa:
      // curve-agnostic: an ECDSA chain signature is keyed on its hash, not the issuer curve
      case AHash of
        TCertSignatureHash.Sha256:
          Result := TSignatureSchemes.EcdsaSecp256r1Sha256;
        TCertSignatureHash.Sha384:
          Result := TSignatureSchemes.EcdsaSecp384r1Sha384;
        TCertSignatureHash.Sha512:
          Result := TSignatureSchemes.EcdsaSecp521r1Sha512;
      end;
    TCertSignatureFamily.Ed25519:
      Result := TSignatureSchemes.Ed25519;
    TCertSignatureFamily.Ed448:
      Result := TSignatureSchemes.Ed448;
  end;
end;

class function TChainAlgorithmPolicy.LegacySha1Scheme(AFamily: TCertSignatureFamily): UInt16;
begin
  Result := 0; // 0 = no codepoint names a SHA-1 signature of this family (PSS has none)
  case AFamily of
    TCertSignatureFamily.RsaPkcs1:
      Result := TSignatureSchemes.RsaPkcs1Sha1;
    TCertSignatureFamily.Ecdsa:
      Result := TSignatureSchemes.EcdsaSha1;
  end;
end;

class function TChainAlgorithmPolicy.SendableTo(const AInspector: ICertificateInspector;
  const AChain: TArray<TBytes>; const APeerCertSchemes: TArray<UInt16>): Boolean;
var
  LI: Int32;
  LCert: IInspectedCertificate;
  LSig: TCertSignatureFacts;
  LScheme: UInt16;
  LSendable: Boolean;
begin
  Result := True;
  for LI := 0 to System.High(AChain) do
  begin
    try
      LCert := AInspector.Parse(AChain[LI]);
    except
      Continue;
    end;
    if not LCert.SignatureFacts(LSig) then
      Continue;
    LSendable := True;
    case LSig.Hash.Standing of
      TCertSignatureHashStanding.Forbidden:
        LSendable := False;
      TCertSignatureHashStanding.Deprecated:
        begin
          LScheme := LegacySha1Scheme(LSig.Family);
          LSendable := (LScheme <> 0) and
            (TArrayUtilities.Contains<UInt16>(APeerCertSchemes, LScheme));
        end;
    end;
    // a self-signed certificate (verifies under its own key, RFC 5280 3.2) starts the path
    if not LSendable and (LCert.IsSelfSigned <> TCertAnswer.Yes) then
      Exit(False);
  end;
end;

class function TChainAlgorithmPolicy.CheckCertificate(
  const AInspector: ICertificateInspector; const ADer: TBytes;
  AIssuerKeyIsPss: Boolean; const APolicy: TCertificateStrengthPolicy;
  AFilterSchemes: Boolean; const AAdvertised: TArray<UInt16>;
  out AAlert: TTlsAlertDescription): Boolean;
var
  LCert: IInspectedCertificate;
  LSig: TCertSignatureFacts;
  LRequired: UInt16;
  LStanding: TCertSignatureHashStanding;
  LAdmitted: Boolean;
begin
  try
    LCert := AInspector.Parse(ADer);
  except
    AAlert := TTlsAlertDescription.BadCertificate;
    Exit(False);
  end;
  if not LCert.SignatureFacts(LSig) then
  begin
    AAlert := TTlsAlertDescription.BadCertificate;
    Exit(False);
  end;
  // RFC 9846 4.5.1.3: a forbidden hash (MD5) is never accepted, a deprecated one (SHA-1) only
  // when the policy admits it
  LStanding := LSig.Hash.Standing;
  LAdmitted := (LStanding = TCertSignatureHashStanding.Deprecated) and
    (LSig.Hash in APolicy.AllowedDeprecatedHashes);
  if (LStanding = TCertSignatureHashStanding.Forbidden) or
    ((LStanding = TCertSignatureHashStanding.Deprecated) and not LAdmitted) then
  begin
    AAlert := TTlsAlertDescription.BadCertificate;
    Exit(False);
  end;
  // an admitted hash stands in for an advertised scheme, none of which names a deprecated
  // certificate signature; a PSS signature must still be canonical
  if AFilterSchemes and not (LAdmitted and
    ((LSig.Family <> TCertSignatureFamily.RsaPss) or LSig.PssCanonical)) then
  begin
    LRequired := RequiredScheme(LSig.Family, LSig.Hash, LSig.PssCanonical, AIssuerKeyIsPss);
    if (LRequired = 0) or not (TArrayUtilities.Contains<UInt16>(AAdvertised, LRequired)) then
    begin
      AAlert := TTlsAlertDescription.UnsupportedCertificate;
      Exit(False);
    end;
  end;
  Result := CheckKey(LCert, APolicy, TTlsAlertDescription.BadCertificate, AAlert);
end;

class function TChainAlgorithmPolicy.CheckKey(const ACert: IInspectedCertificate;
  const APolicy: TCertificateStrengthPolicy; AUnreadable: TTlsAlertDescription;
  out AAlert: TTlsAlertDescription): Boolean;
var
  LKey: TCertKeyFacts;
begin
  if not ACert.KeyFacts(LKey) then
  begin
    AAlert := AUnreadable;
    Exit(False);
  end;
  if not APolicy.AdmitsKey(LKey) then
  begin
    AAlert := TTlsAlertDescription.UnsupportedCertificate;
    Exit(False);
  end;
  Result := True;
end;

class function TChainAlgorithmPolicy.CheckAnchorKey(const AInspector: ICertificateInspector;
  const ADer: TBytes; const APolicy: TCertificateStrengthPolicy;
  out AAlert: TTlsAlertDescription): Boolean;
var
  LCert: IInspectedCertificate;
begin
  try
    LCert := AInspector.Parse(ADer);
  except
    AAlert := TTlsAlertDescription.BadCertificate;
    Exit(False);
  end;
  // a key of a kind the inspector cannot describe is as unusable as a weak one
  Result := CheckKey(LCert, APolicy, TTlsAlertDescription.UnsupportedCertificate, AAlert);
end;

class function TChainAlgorithmPolicy.AnchorsMeetKeyFloors(const AInspector: ICertificateInspector;
  const AAnchors: TArray<TBytes>; const APolicy: TCertificateStrengthPolicy;
  out AAlert: TTlsAlertDescription): Boolean;
var
  LI: Int32;
begin
  AAlert := TTlsAlertDescription.BadCertificate;
  if not APolicy.AnchorKeyFloors then
    Exit(True);
  for LI := 0 to System.High(AAnchors) do
    if not CheckAnchorKey(AInspector, AAnchors[LI], APolicy, AAlert) then
      Exit(False);
  Result := True;
end;

class function TChainAlgorithmPolicy.Check(const AInspector: ICertificateInspector;
  const AChain, ARoots: TArray<TBytes>;
  const APolicy: TCertificateStrengthPolicy;
  const AAdvertised: TArray<UInt16>; out AAlert: TTlsAlertDescription): Boolean;
begin
  Result := Walk(AInspector, AChain, ARoots, APolicy, True, AAdvertised, AAlert);
end;

class function TChainAlgorithmPolicy.CheckBaseline(const AInspector: ICertificateInspector;
  const AChain, ARoots: TArray<TBytes>; out AAlert: TTlsAlertDescription): Boolean;
begin
  Result := Walk(AInspector, AChain, ARoots, TCertificateStrengthPolicy.Defaults, False,
    nil, AAlert);
end;

class function TChainAlgorithmPolicy.Walk(const AInspector: ICertificateInspector;
  const AChain, ARoots: TArray<TBytes>;
  const APolicy: TCertificateStrengthPolicy; AFilterSchemes: Boolean;
  const AAdvertised: TArray<UInt16>; out AAlert: TTlsAlertDescription): Boolean;
var
  LI: Int32;
  LIssuerKeyIsPss: Boolean;
begin
  Result := True;
  AAlert := TTlsAlertDescription.BadCertificate;
  for LI := 0 to System.Length(AChain) - 1 do
  begin
    // a configured trust anchor is not a validated edge (RFC 9846 4.3.3), so at most its key is
    // held to the floors; the leaf is always checked in full
    if (LI > 0) and IsAnchor(AChain[LI], ARoots) then
    begin
      if APolicy.AnchorKeyFloors and
        not CheckAnchorKey(AInspector, AChain[LI], APolicy, AAlert) then
        Exit(False);
      Continue;
    end;
    // the signature on this certificate was made by its issuer (the next element); a PSS-restricted
    // issuer key means a rsa_pss_pss_* signature. A missing issuer resolves conservatively to False.
    LIssuerKeyIsPss := (LI + 1 < System.Length(AChain)) and
      (AInspector.KeyIsRsaPss(AChain[LI + 1]) = TCertAnswer.Yes);
    if not CheckCertificate(AInspector, AChain[LI], LIssuerKeyIsPss, APolicy,
      AFilterSchemes, AAdvertised, AAlert) then
      Exit(False);
  end;
end;

{ TEndEntityPolicy }

class function TEndEntityPolicy.Admits(const AInspector: ICertificateInspector;
  const APath, ARoots: TArray<TBytes>; out AAlert: TTlsAlertDescription): Boolean;
var
  LI: Int32;
begin
  AAlert := TTlsAlertDescription.BadCertificate;
  Result := False;
  if System.Length(APath) = 0 then
    Exit;
  case AInspector.IsCertificateAuthority(APath[0]) of
    TCertAnswer.No:
      Result := True;
    TCertAnswer.Yes:
      for LI := 0 to System.High(ARoots) do
        if TArrayUtilities.AreEqual(APath[0], ARoots[LI]) then
          Exit(True);
  end;
end;

end.
