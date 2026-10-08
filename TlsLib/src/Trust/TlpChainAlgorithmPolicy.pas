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
  /// and intermediate must be signed with a signature scheme the endpoint advertised (RFC 8446
  /// 4.4.2.2 / 4.4.2.3, RFC 5246 7.4.2 / 7.4.4 / 7.4.6), an MD5-signed certificate is refused
  /// outright and a SHA-1-signed one unless the policy admits it (RFC 8446 4.4.2.4), and each
  /// subject key must meet the configured minimum-strength floors. A configured trust anchor is
  /// exempt (its self-signature is not a validated edge and its key
  /// is the operator's trust); the leaf never is. Verdict-only: it decides accept/reject and the
  /// alert, reading facts from the provider's certificate inspector so no ASN.1 is handled here.
  /// </summary>
  TChainAlgorithmPolicy = class sealed(TObject)
  strict private
    class function IsAnchor(const ADer: TBytes; const ARoots: TArray<TBytes>): Boolean; static;
    class function RequiredScheme(AFamily: TCertSignatureFamily;
      AHash: TCertSignatureHash; APssCanonical: Boolean;
      AIssuerKeyIsPss: Boolean): UInt16; static;
    class function KeyMeetsPolicy(const AFacts: TCertKeyFacts;
      const APolicy: TCertificateStrengthPolicy): Boolean; static;
    class function CheckCertificate(const AInspector: ICertificateInspector;
      const ADer: TBytes; AIssuerKeyIsPss: Boolean;
      const APolicy: TCertificateStrengthPolicy; AFilterSchemes: Boolean;
      const AAdvertised: TArray<UInt16>; out AAlert: TTlsAlertDescription): Boolean; static;
    class function Walk(const AInspector: ICertificateInspector;
      const AChain, ARoots: TArray<TBytes>;
      const APolicy: TCertificateStrengthPolicy; AFilterSchemes: Boolean;
      const AAdvertised: TArray<UInt16>; out AAlert: TTlsAlertDescription): Boolean; static;
  public
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

class function TChainAlgorithmPolicy.KeyMeetsPolicy(const AFacts: TCertKeyFacts;
  const APolicy: TCertificateStrengthPolicy): Boolean;
begin
  case AFacts.Kind of
    TSignatureKeyKind.Rsa:
      Result := (AFacts.Bits >= APolicy.MinRsaModulusBits) and
        ((APolicy.MaxRsaModulusBits = 0) or (AFacts.Bits <= APolicy.MaxRsaModulusBits));
    TSignatureKeyKind.Ecdsa:
      // an empty allowlist admits any curve the provider recognises (a code of 0 is unknown)
      if System.Length(APolicy.AllowedEcCurves) = 0 then
        Result := AFacts.EcNamedGroup <> 0
      else
        Result := TArrayUtilities.Contains<UInt16>(APolicy.AllowedEcCurves,
          AFacts.EcNamedGroup);
    TSignatureKeyKind.Ed25519, TSignatureKeyKind.Ed448:
      Result := APolicy.AllowEdDsa;
  else
    Result := False;
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
  LKey: TCertKeyFacts;
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
  // RFC 8446 4.4.2.4: a forbidden hash (MD5) is never accepted, a deprecated one (SHA-1) only
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
  if not LCert.KeyFacts(LKey) then
  begin
    AAlert := TTlsAlertDescription.BadCertificate;
    Exit(False);
  end;
  if not KeyMeetsPolicy(LKey, APolicy) then
  begin
    AAlert := TTlsAlertDescription.UnsupportedCertificate;
    Exit(False);
  end;
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
    // a configured trust anchor is not a validated edge (RFC 8446 4.2.3); the leaf never is
    if (LI > 0) and IsAnchor(AChain[LI], ARoots) then
      Continue;
    // the signature on this certificate was made by its issuer (the next element); a PSS-restricted
    // issuer key means a rsa_pss_pss_* signature. A missing issuer resolves conservatively to False.
    LIssuerKeyIsPss := (LI + 1 < System.Length(AChain)) and
      (AInspector.KeyIsRsaPss(AChain[LI + 1]) = TCertAnswer.Yes);
    if not CheckCertificate(AInspector, AChain[LI], LIssuerKeyIsPss, APolicy,
      AFilterSchemes, AAdvertised, AAlert) then
      Exit(False);
  end;
end;

end.
