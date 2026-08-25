{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpCertificateVerify;

{$I ..\Include\TlsLib.inc}

interface

uses
  SysUtils,
  TlpTlsAlert,
  TlpTlsLibExceptions,
  TlpCryptoAlgorithms,
  TlpICryptoProvider;

type
  /// <summary>
  /// Builds the CertificateVerify to-be-signed content (RFC 8446 4.4.3): 64 octets
  /// of 0x20, the role context string, a 0x00 separator, then the transcript hash
  /// through the Certificate message. Both the signer (server) and the verifier
  /// (client) construct the identical bytes.
  /// </summary>
  TCertificateVerify = class sealed(TObject)
  strict private
  const
    ServerContext = 'TLS 1.3, server CertificateVerify';
    ClientContext = 'TLS 1.3, client CertificateVerify';
  strict private
    class function EcdsaSchemeNamedGroup(const AScheme: TSignatureScheme): UInt16; static;
  public
    /// <summary>The signed content for AServerSide's CertificateVerify over ATranscriptHash.</summary>
    class function SignatureContent(AServerSide: Boolean;
      const ATranscriptHash: TBytes): TBytes; static;
    /// <summary>Enforces the peer leaf's signing policy before verifying a handshake
    /// signature (a CertificateVerify, or a 1.2 ServerKeyExchange): the leaf must permit
    /// digitalSignature if it carries keyUsage (RFC 5280 4.2.1.3), and an rsa_pss_rsae_*
    /// scheme must not be produced by an id-RSASSA-PSS leaf key (RFC 8446 4.2.3). When
    /// ABindEcdsaCurve is set (TLS 1.3), an ecdsa_* scheme additionally requires the leaf
    /// EC key to be on the scheme's named curve (RFC 8446 4.2.3) - TLS 1.2 leaves the curve
    /// to the supported_groups list, so it passes False. Applies symmetrically to a client
    /// verifying the server leaf and a server verifying the client leaf.</summary>
    class procedure EnforceSigningLeafPolicy(const AProvider: ICryptoProvider;
      const ALeafCertificate: TBytes; const AScheme: TSignatureScheme;
      ABindEcdsaCurve: Boolean); static;
    /// <summary>Rejects a peer leaf that is not a well-formed X.509 certificate with a
    /// decode_error alert, before it reaches signature verification or the trust pipeline.
    /// Applies to a received server or client leaf.</summary>
    class procedure EnsureWellFormedLeaf(const AProvider: ICryptoProvider;
      const ALeafCertificate: TBytes); static;
  end;

implementation

resourcestring
  SLeafKeyUsageForbidsSigning =
    'the peer certificate keyUsage does not permit digitalSignature';
  SPssLeafKeyUnsupported =
    'an rsa_pss_rsae_* signature requires an rsaEncryption leaf key, not id-RSASSA-PSS';
  SEcdsaSchemeCurveMismatch =
    'the ecdsa_* signature scheme requires a leaf key on the scheme''s named curve';
  SUnparseableLeafCertificate =
    'the peer leaf is not a well-formed X.509 certificate';

{ TCertificateVerify }

class procedure TCertificateVerify.EnsureWellFormedLeaf(
  const AProvider: ICryptoProvider; const ALeafCertificate: TBytes);
var
  LSubject, LIssuer, LCommonName, LSerialHex: string;
begin
  // CertificatePeerInfo parses the whole certificate and never raises: False means the DER
  // is not a well-formed X.509 certificate, so reject it before any downstream cert use.
  if not AProvider.Certificates.PeerInfo(ALeafCertificate, LSubject, LIssuer,
    LCommonName, LSerialHex) then
    raise EDecodeErrorTlsLibException.CreateRes(@SUnparseableLeafCertificate);
end;

class function TCertificateVerify.SignatureContent(AServerSide: Boolean;
  const ATranscriptHash: TBytes): TBytes;
var
  LContext: TBytes;
  LPos: Int32;
begin
  if AServerSide then
    LContext := TEncoding.ASCII.GetBytes(ServerContext)
  else
    LContext := TEncoding.ASCII.GetBytes(ClientContext);

  SetLength(Result, 64 + System.Length(LContext) + 1 +
    System.Length(ATranscriptHash));
  FillChar(Result[0], 64, $20);
  LPos := 64;
  if System.Length(LContext) > 0 then
    Move(LContext[0], Result[LPos], System.Length(LContext));
  Inc(LPos, System.Length(LContext));
  Result[LPos] := $00;
  Inc(LPos);
  if System.Length(ATranscriptHash) > 0 then
    Move(ATranscriptHash[0], Result[LPos], System.Length(ATranscriptHash));
end;

class function TCertificateVerify.EcdsaSchemeNamedGroup(
  const AScheme: TSignatureScheme): UInt16;
begin
  // the IANA supported_groups code the ecdsa_* scheme's curve maps to; 0 when not ecdsa
  case AScheme of
    TSignatureScheme.ECDSA_SECP256R1_SHA256: Result := $0017;
    TSignatureScheme.ECDSA_SECP384R1_SHA384: Result := $0018;
    TSignatureScheme.ECDSA_SECP521R1_SHA512: Result := $0019;
  else
    Result := 0;
  end;
end;

class procedure TCertificateVerify.EnforceSigningLeafPolicy(
  const AProvider: ICryptoProvider; const ALeafCertificate: TBytes;
  const AScheme: TSignatureScheme; ABindEcdsaCurve: Boolean);
var
  LPermitted, LIsRsaPss: Boolean;
  LKind: TCertKeyKind;
  LCertGroup, LSchemeGroup: UInt16;
begin
  if AProvider.Certificates.KeyUsagePermits(ALeafCertificate,
    TCertKeyUsage.DigitalSignature, LPermitted) and not LPermitted then
    raise EFatalAlertTlsLibException.CreateRes(
      TTlsAlertDescription.BadCertificate, @SLeafKeyUsageForbidsSigning);
  if AScheme.IsRsaPssRsae and
    AProvider.Certificates.HasRsaPssKey(ALeafCertificate, LIsRsaPss) and LIsRsaPss then
    raise EFatalAlertTlsLibException.CreateRes(
      TTlsAlertDescription.IllegalParameter, @SPssLeafKeyUnsupported);
  // TLS 1.3 binds the ECDSA curve to the signature scheme: an ecdsa_secp384r1_sha384
  // signature made by a P-256 leaf key is a wrong-signature-type (RFC 8446 4.2.3)
  if ABindEcdsaCurve then
  begin
    LSchemeGroup := EcdsaSchemeNamedGroup(AScheme);
    if (LSchemeGroup <> 0) and
      AProvider.Certificates.KeyKind(ALeafCertificate, LKind, LCertGroup) and
      (LKind = TCertKeyKind.Ecdsa) and (LCertGroup <> LSchemeGroup) then
      raise EFatalAlertTlsLibException.CreateRes(
        TTlsAlertDescription.IllegalParameter, @SEcdsaSchemeCurveMismatch);
  end;
end;

end.
