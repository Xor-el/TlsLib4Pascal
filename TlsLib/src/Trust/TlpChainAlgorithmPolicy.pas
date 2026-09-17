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
  TlpICryptoProvider,
  TlpNegotiationTypes,
  TlpTrustPolicy,
  TlpTlsAlert;

type
  /// <summary>
  /// Enforces the chain-algorithm policy over an already path-validated peer chain: every leaf
  /// and intermediate must be signed with a signature scheme the endpoint advertised (RFC 8446
  /// 4.4.2.2 / RFC 5246 7.4.2), an MD5- or SHA-1-signed certificate is refused outright (RFC
  /// 8446 4.4.2), and each subject key must meet the configured minimum-strength floors. A
  /// configured trust anchor is exempt (its self-signature is not a validated edge and its key
  /// is the operator's trust); the leaf never is. Verdict-only: it decides accept/reject and the
  /// alert, reading facts from the provider's certificate inspector so no ASN.1 is handled here.
  /// </summary>
  TChainAlgorithmPolicy = class sealed(TObject)
  strict private
    class function IsAnchor(const ADer: TBytes; const ARoots: TArray<TBytes>): Boolean; static;
    class function RequiredScheme(AFamily: TCertSignatureFamily;
      AHash: TCertSignatureHash; APssCanonical: Boolean): UInt16; static;
    class function KeyMeetsPolicy(const AFacts: TCertKeyFacts;
      const APolicy: TCertificateStrengthPolicy): Boolean; static;
    class function CheckCertificate(const AInspector: ICertificateInspector;
      const ADer: TBytes; const APolicy: TCertificateStrengthPolicy;
      const AAdvertised: TArray<UInt16>; out AAlert: TTlsAlertDescription): Boolean; static;
  public
    class function Check(const AInspector: ICertificateInspector;
      const AChain, ARoots: TArray<TBytes>;
      const APolicy: TCertificateStrengthPolicy;
      const AAdvertised: TArray<UInt16>; out AAlert: TTlsAlertDescription): Boolean; static;
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
  AHash: TCertSignatureHash; APssCanonical: Boolean): UInt16;
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
      // a non-canonical PSS (wrong MGF/salt, or absent params defaulting to SHA-1) has no match
      if APssCanonical then
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
    TCertKeyKind.Rsa:
      Result := (AFacts.Bits >= APolicy.MinRsaModulusBits) and
        ((APolicy.MaxRsaModulusBits = 0) or (AFacts.Bits <= APolicy.MaxRsaModulusBits));
    TCertKeyKind.Ecdsa:
      // an empty allowlist admits any curve the provider recognises (a code of 0 is unknown)
      if System.Length(APolicy.AllowedEcCurves) = 0 then
        Result := AFacts.EcNamedGroup <> 0
      else
        Result := TArrayUtilities.Contains<UInt16>(APolicy.AllowedEcCurves,
          AFacts.EcNamedGroup);
    TCertKeyKind.Ed25519, TCertKeyKind.Ed448:
      Result := APolicy.AllowEdDsa;
  else
    Result := False;
  end;
end;

class function TChainAlgorithmPolicy.CheckCertificate(
  const AInspector: ICertificateInspector; const ADer: TBytes;
  const APolicy: TCertificateStrengthPolicy; const AAdvertised: TArray<UInt16>;
  out AAlert: TTlsAlertDescription): Boolean;
var
  LCert: IInspectedCertificate;
  LSig: TCertSignatureFacts;
  LKey: TCertKeyFacts;
  LRequired: UInt16;
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
  // RFC 8446 4.4.2: refuse an MD5 (MUST) or SHA-1 (RECOMMENDED) chain signature outright
  if LSig.Hash in [TCertSignatureHash.Md5, TCertSignatureHash.Sha1] then
  begin
    AAlert := TTlsAlertDescription.BadCertificate;
    Exit(False);
  end;
  LRequired := RequiredScheme(LSig.Family, LSig.Hash, LSig.PssCanonical);
  if (LRequired = 0) or not (TArrayUtilities.Contains<UInt16>(AAdvertised, LRequired)) then
  begin
    AAlert := TTlsAlertDescription.UnsupportedCertificate;
    Exit(False);
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
var
  LI: Int32;
begin
  Result := True;
  AAlert := TTlsAlertDescription.BadCertificate;
  for LI := 0 to System.Length(AChain) - 1 do
  begin
    // a configured trust anchor is not a validated edge (RFC 8446 4.2.3); the leaf never is
    if (LI > 0) and IsAnchor(AChain[LI], ARoots) then
      Continue;
    if not CheckCertificate(AInspector, AChain[LI], APolicy, AAdvertised, AAlert) then
      Exit(False);
  end;
end;

end.
