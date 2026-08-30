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
    class procedure EnforceSigningLeafPolicy(const ALeaf: IInspectedCertificate;
      const AScheme: TSignatureScheme; ABindEcdsaCurve: Boolean); static;
    /// <summary>Parses a peer leaf, rejecting one that is not a well-formed X.509
    /// certificate with a decode_error alert before it reaches signature verification or
    /// the trust pipeline, and returns the parsed handle so the caller reuses the single
    /// decode. Applies to a received server or client leaf.</summary>
    class function ParseWellFormedLeaf(const AProvider: ICryptoProvider;
      const ALeafCertificate: TBytes): IInspectedCertificate; static;
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

class function TCertificateVerify.ParseWellFormedLeaf(
  const AProvider: ICryptoProvider;
  const ALeafCertificate: TBytes): IInspectedCertificate;
var
  LSubject, LIssuer, LCommonName, LSerialHex: string;
begin
  // the catch-all except covers uncaught backend exception types from the ASN.1 decode
  try
    Result := AProvider.Certificates.Parse(ALeafCertificate);
  except
    raise EDecodeErrorTlsLibException.CreateRes(@SUnparseableLeafCertificate);
  end;
  // PeerInfo probes the whole certificate and never raises: False means a field is not a
  // well-formed X.509 structure, so reject it before any downstream cert use.
  if not Result.PeerInfo(LSubject, LIssuer, LCommonName, LSerialHex) then
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
  const ALeaf: IInspectedCertificate; const AScheme: TSignatureScheme;
  ABindEcdsaCurve: Boolean);
var
  LKind: TCertKeyKind;
  LCertGroup, LSchemeGroup: UInt16;
begin
  // the caller passes the leaf already parsed by ParseWellFormedLeaf, answering all three
  // signing-policy queries from that one decode; only a definite No/Yes trips the raise,
  // an Undetermined field passes (fail-open per check)
  if ALeaf.KeyUsagePermits(TCertKeyUsage.DigitalSignature) = TCertAnswer.No then
    raise EFatalAlertTlsLibException.CreateRes(
      TTlsAlertDescription.BadCertificate, @SLeafKeyUsageForbidsSigning);
  if AScheme.IsRsaPssRsae and (ALeaf.KeyIsRsaPss = TCertAnswer.Yes) then
    raise EFatalAlertTlsLibException.CreateRes(
      TTlsAlertDescription.IllegalParameter, @SPssLeafKeyUnsupported);
  // TLS 1.3 binds the ECDSA curve to the signature scheme: an ecdsa_secp384r1_sha384
  // signature made by a P-256 leaf key is a wrong-signature-type (RFC 8446 4.2.3)
  if ABindEcdsaCurve then
  begin
    LSchemeGroup := EcdsaSchemeNamedGroup(AScheme);
    if (LSchemeGroup <> 0) and ALeaf.KeyKind(LKind, LCertGroup) and
      (LKind = TCertKeyKind.Ecdsa) and (LCertGroup <> LSchemeGroup) then
      raise EFatalAlertTlsLibException.CreateRes(
        TTlsAlertDescription.IllegalParameter, @SEcdsaSchemeCurveMismatch);
  end;
end;

end.
