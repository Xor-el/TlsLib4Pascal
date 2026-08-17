{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpHandshakeMessages;

{$I ..\Include\TlsLib.inc}

interface

uses
  SysUtils,
  TlpTlsVersion,
  TlpTlsAlert,
  TlpTlsLibExceptions,
  TlpWireReader,
  TlpWireVectorMarker,
  TlpIWireWriter,
  TlpWireWriter;

type
  /// <summary>A ClientHello. The extension block is kept as its raw wire vector
  /// (2-byte length + entries) so the extension layer owns its own parsing.</summary>
  TTlsClientHello = record
    /// <summary>The legacy_version field. A modern client sets it to 0x0303 and lists its
    /// real versions in supported_versions; a pre-1.2 client without that extension carries
    /// its version here, letting the server map an unsupported floor to protocol_version.</summary>
    LegacyVersion: UInt16;
    Random: TBytes;
    LegacySessionId: TBytes;
    CipherSuites: TArray<UInt16>;
    /// <summary>The raw legacy_compression_methods list. A well-formed offer includes the
    /// null method; a TLS 1.3 ClientHello carries only that single byte (RFC 8446 4.1.2).
    /// Kept verbatim so the version-specific rule is applied once the version is known.</summary>
    CompressionMethods: TBytes;
    Extensions: TBytes;
  end;

  /// <summary>A ServerHello (raw extension vector, as above).</summary>
  TTlsServerHello = record
    /// <summary>The legacy_version field. A negotiated TLS 1.3 sets it to 0x0303 and carries
    /// the real version in supported_versions; a server that selected 1.2 or below carries
    /// its version here. Read verbatim so the client can map an unsupported selection to a
    /// protocol_version alert rather than a decode error (RFC 8446 4.2.1).</summary>
    LegacyVersion: UInt16;
    Random: TBytes;
    LegacySessionIdEcho: TBytes;
    CipherSuite: UInt16;
    Extensions: TBytes;
  end;

  /// <summary>One entry of a Certificate message's certificate_list.</summary>
  TTlsCertificateEntry = record
    CertData: TBytes;
    Extensions: TBytes;
  end;

  /// <summary>A 1.3 Certificate message.</summary>
  TTlsCertificate = record
    RequestContext: TBytes;
    Entries: TArray<TTlsCertificateEntry>;
  end;

  /// <summary>A CertificateVerify: the signature scheme and the signature bytes.</summary>
  TTlsCertificateVerify = record
    Algorithm: UInt16;
    Signature: TBytes;
  end;

  /// <summary>A CompressedCertificate (RFC 8879): the algorithm, the declared
  /// uncompressed length, and the compressed Certificate-message bytes.</summary>
  TTlsCompressedCertificate = record
    Algorithm: UInt16;
    UncompressedLength: Int32;
    Compressed: TBytes;
  end;

  /// <summary>
  /// A TLS 1.2 ECDHE ServerKeyExchange (RFC 4492 / RFC 8422 5.4): the named-curve
  /// server params and the digitally-signed proof over client_random + server_random
  /// + those params. Only the named_curve curve_type is modelled (the hardened profile).
  /// </summary>
  TTlsServerKeyExchangeEcdhe = record
    NamedCurve: UInt16;
    PublicKey: TBytes;
    SignatureScheme: UInt16;
    Signature: TBytes;
  end;

  /// <summary>A TLS 1.2 ECDHE ClientKeyExchange (RFC 4492 5.7): the client ephemeral
  /// EC point.</summary>
  TTlsClientKeyExchangeEcdhe = record
    PublicKey: TBytes;
  end;

  /// <summary>A TLS 1.3 CertificateRequest (RFC 8446 4.3.2): the request context and
  /// the raw extension block (signature_algorithms lives inside it).</summary>
  TTlsCertificateRequest13 = record
    RequestContext: TBytes;
    Extensions: TBytes;
  end;

  /// <summary>A TLS 1.2 CertificateRequest (RFC 5246 7.4.4): the accepted client
  /// certificate types, signature algorithms, and the DER-encoded DistinguishedName
  /// certificate_authorities (empty when the server names no acceptable issuer).</summary>
  TTlsCertificateRequest12 = record
    CertificateTypes: TBytes;
    SupportedSignatureAlgorithms: TArray<UInt16>;
    CertificateAuthorities: TArray<TBytes>;
  end;

  /// <summary>A TLS 1.3 NewSessionTicket (RFC 8446 4.6.1): the lifetime, the age
  /// obfuscator, the ticket nonce, the opaque ticket, and a raw extension block
  /// (early_data's max_early_data_size lives inside it).</summary>
  TTlsNewSessionTicket = record
    TicketLifetime: UInt32;
    TicketAgeAdd: UInt32;
    TicketNonce: TBytes;
    Ticket: TBytes;
    Extensions: TBytes;
  end;

  /// <summary>A TLS 1.2 NewSessionTicket (RFC 5077 3.3): a lifetime hint and the
  /// opaque ticket, with none of the 1.3 nonce/age/extension machinery.</summary>
  TTls12NewSessionTicket = record
    TicketLifetimeHint: UInt32;
    Ticket: TBytes;
  end;

  /// <summary>
  /// Encodes and decodes the bodies of the TLS 1.3 handshake messages (RFC 8446 4).
  /// It handles only a message body - the type and uint24 length framing is the
  /// handshake message layer's job - and treats each extension block as opaque
  /// wire bytes for the extension codec to interpret.
  /// </summary>
  THandshakeMessages = class sealed(TObject)
  strict private
    class function ReadUInt16Vector(var AReader: TWireReader): TArray<UInt16>; static;
    class procedure WriteUInt16Vector(const AWriter: IWireWriter;
      const AValues: TArray<UInt16>); static;
    class function ReadVectorRaw(var AReader: TWireReader;
      ALenBytes: Int32): TBytes; static;
    class function CompressionOffersNull(const AMethods: TBytes): Boolean; static;
  public
    class function EncodeClientHello(const AMsg: TTlsClientHello): TBytes; static;
    class function DecodeClientHello(const ABody: TBytes): TTlsClientHello; static;
    class function EncodeServerHello(const AMsg: TTlsServerHello): TBytes; static;
    class function DecodeServerHello(const ABody: TBytes): TTlsServerHello; static;
    /// <summary>The version a ServerHello selected via its supported_versions extension
    /// (RFC 8446 4.2.1), or 0 when the extension is absent - a server that negotiated TLS 1.2
    /// or below, whose version is then the legacy_version field.</summary>
    class function ServerHelloSelectedVersion(const AExtensions: TBytes): UInt16; static;
    /// <summary>True when legacy_compression_methods is exactly the single null byte - the
    /// only form a TLS 1.3 ClientHello may carry (RFC 8446 4.1.2). A lower version accepts a
    /// longer list, so this is enforced only once the negotiated version is known to be 1.3.</summary>
    class function IsNullOnlyCompression(const AMethods: TBytes): Boolean; static;
    /// <summary>The body is exactly the raw extensions vector.</summary>
    class function EncodeEncryptedExtensions(const AExtensions: TBytes): TBytes; static;
    class function DecodeEncryptedExtensions(const ABody: TBytes): TBytes; static;
    class function EncodeCertificate(const AMsg: TTlsCertificate): TBytes; static;
    class function DecodeCertificate(const ABody: TBytes): TTlsCertificate; static;
    /// <summary>A CertificateStatus message body (RFC 6066 8): status_type ocsp(1)
    /// followed by the DER OCSPResponse as a 3-byte vector.</summary>
    class function EncodeCertificateStatus(const AResponse: TBytes): TBytes; static;
    /// <summary>The DER OCSPResponse carried by a CertificateStatus body; raises
    /// decode_error on a wrong status_type or an empty response.</summary>
    class function DecodeCertificateStatus(const ABody: TBytes): TBytes; static;
    /// <summary>The raw per-entry extensions vector for a leaf CertificateEntry carrying
    /// a single status_request extension whose body is the CertificateStatus (RFC 8446
    /// 4.4.2.1) - the TLS 1.3 stapled OCSP form.</summary>
    class function EncodeLeafStapleExtensions(const AResponse: TBytes): TBytes; static;
    /// <summary>Extracts the stapled DER OCSPResponse from a leaf CertificateEntry's raw
    /// extensions vector. False when no status_request extension is present; raises
    /// decode_error when one is present but malformed.</summary>
    class function TryExtractLeafStaple(const AExtensions: TBytes;
      out AResponse: TBytes): Boolean; static;
    /// <summary>The extension types present in a CertificateEntry's raw extensions vector,
    /// in order. Used to reject unsolicited/unknown leaf extensions (RFC 8446 4.4.2).</summary>
    class function CertificateEntryExtensionTypes(
      const AExtensions: TBytes): TArray<UInt16>; static;
    class function EncodeCertificateVerify(const AMsg: TTlsCertificateVerify): TBytes;
      static;
    class function DecodeCertificateVerify(const ABody: TBytes): TTlsCertificateVerify;
      static;
    class function EncodeCompressedCertificate(
      const AMsg: TTlsCompressedCertificate): TBytes; static;
    class function DecodeCompressedCertificate(
      const ABody: TBytes): TTlsCompressedCertificate; static;
    /// <summary>The body is exactly the verify_data.</summary>
    class function EncodeFinished(const AVerifyData: TBytes): TBytes; static;
    class function DecodeFinished(const ABody: TBytes): TBytes; static;

    /// <summary>A TLS 1.2 Certificate: the bare certificate_list (each cert a 3-byte
    /// vector), no request context and no per-certificate extensions.</summary>
    class function EncodeCertificate12(const AChain: TArray<TBytes>): TBytes; static;
    class function DecodeCertificate12(const ABody: TBytes): TArray<TBytes>; static;
    /// <summary>The signed ECDHE server params: curve_type(named_curve) || named_curve
    /// || ECPoint. This is the exact byte-run the ServerKeyExchange signature covers,
    /// after client_random + server_random.</summary>
    class function EcdheServerParams(ANamedCurve: UInt16;
      const APublicKey: TBytes): TBytes; static;
    class function EncodeServerKeyExchangeEcdhe(
      const AMsg: TTlsServerKeyExchangeEcdhe): TBytes; static;
    class function DecodeServerKeyExchangeEcdhe(
      const ABody: TBytes): TTlsServerKeyExchangeEcdhe; static;
    class function EncodeClientKeyExchangeEcdhe(
      const AMsg: TTlsClientKeyExchangeEcdhe): TBytes; static;
    class function DecodeClientKeyExchangeEcdhe(
      const ABody: TBytes): TTlsClientKeyExchangeEcdhe; static;
    class function EncodeCertificateRequest13(
      const AMsg: TTlsCertificateRequest13): TBytes; static;
    class function DecodeCertificateRequest13(
      const ABody: TBytes): TTlsCertificateRequest13; static;
    class function EncodeCertificateRequest12(
      const AMsg: TTlsCertificateRequest12): TBytes; static;
    class function DecodeCertificateRequest12(
      const ABody: TBytes): TTlsCertificateRequest12; static;
    class function EncodeNewSessionTicket(
      const AMsg: TTlsNewSessionTicket): TBytes; static;
    class function DecodeNewSessionTicket(
      const ABody: TBytes): TTlsNewSessionTicket; static;
    class function EncodeTls12NewSessionTicket(
      const AMsg: TTls12NewSessionTicket): TBytes; static;
    class function DecodeTls12NewSessionTicket(
      const ABody: TBytes): TTls12NewSessionTicket; static;
  end;

const
  EcCurveTypeNamedCurve = Byte(3); // RFC 4492 5.4 ECCurveType.named_curve
  LegacyCompressionNull = Byte(0);
  ClientHelloRandomLength = Int32(32);
  MaxLegacySessionIdLength = Int32(32); // legacy_session_id<0..32> (RFC 8446 4.1.2)
  CertificateStatusTypeOcsp = Byte(1); // RFC 6066 8 CertificateStatusType.ocsp
  StatusRequestExtensionCode = UInt16(5); // IANA TLS ExtensionType status_request
  SctExtensionCode = UInt16(18); // IANA TLS ExtensionType signed_certificate_timestamp
  // "Servers MUST NOT use any value greater than 604800 seconds (7 days)" (RFC 8446 4.6.1)
  MaxTicketLifetimeSeconds = UInt32(604800);

implementation

uses
  TlpCoreExtensions;

resourcestring
  SNoNullCompression =
    'legacy_compression_methods does not offer the null method';
  SServerCompressionNotNull =
    'the server selected a non-null legacy_compression_method';
  SSessionIdTooLong = 'legacy_session_id exceeds the 32-byte maximum';
  SEmptySessionTicket = 'a NewSessionTicket carries an empty ticket';
  SBadCurveType = 'unsupported ECCurveType in ServerKeyExchange (named_curve only)';
  SBadCertificateStatusType = 'a CertificateStatus carries an unsupported status_type';
  SEmptyOcspResponse = 'a CertificateStatus carries an empty OCSP response';
  SEmptyCertRequestSigAlgs = 'a CertificateRequest names no supported_signature_algorithms ' +
    '(RFC 5246 7.4.4 requires at least one)';
  SEmptyDistinguishedName12 = 'a CertificateRequest certificate_authorities entry is a ' +
    'zero-length DistinguishedName (RFC 5246 7.4.4)';

{ THandshakeMessages }

class function THandshakeMessages.ReadUInt16Vector(
  var AReader: TWireReader): TArray<UInt16>;
var
  LVec: TWireReader;
  LCount: Int32;
begin
  Result := nil;
  LVec := AReader.OpenVector(2);
  LCount := 0;
  while not LVec.EndReached do
  begin
    SetLength(Result, LCount + 1);
    Result[LCount] := LVec.ReadUInt16;
    Inc(LCount);
  end;
end;

class procedure THandshakeMessages.WriteUInt16Vector(const AWriter: IWireWriter;
  const AValues: TArray<UInt16>);
var
  LMarker: TWireVectorMarker;
  LValue: UInt16;
begin
  LMarker := AWriter.OpenVector(2);
  for LValue in AValues do
    AWriter.WriteUInt16(LValue);
  AWriter.CloseVector(LMarker);
end;

class function THandshakeMessages.ReadVectorRaw(var AReader: TWireReader;
  ALenBytes: Int32): TBytes;
var
  LVec: TWireReader;
  LContent: TBytes;
  LWriter: IWireWriter;
  LMarker: TWireVectorMarker;
begin
  Result := nil;
  LVec := AReader.OpenVector(ALenBytes);
  LContent := LVec.ReadBytes(LVec.Remaining);
  // rebuild the length prefix + content so the block round-trips verbatim
  LWriter := TWireWriter.Create;
  LMarker := LWriter.OpenVector(ALenBytes);
  LWriter.WriteBytes(LContent);
  LWriter.CloseVector(LMarker);
  Result := LWriter.ToBytes;
end;

class function THandshakeMessages.CompressionOffersNull(
  const AMethods: TBytes): Boolean;
var
  LIndex: Int32;
begin
  for LIndex := 0 to System.Length(AMethods) - 1 do
    if AMethods[LIndex] = LegacyCompressionNull then
      Exit(True);
  Result := False;
end;

class function THandshakeMessages.IsNullOnlyCompression(
  const AMethods: TBytes): Boolean;
begin
  Result := (System.Length(AMethods) = 1) and
    (AMethods[0] = LegacyCompressionNull);
end;

class function THandshakeMessages.EncodeClientHello(
  const AMsg: TTlsClientHello): TBytes;
var
  LWriter: IWireWriter;
  LMarker: TWireVectorMarker;
begin
  Result := nil;
  LWriter := TWireWriter.Create;
  LWriter.WriteUInt16(TlsWireVersionTls12); // legacy_version
  LWriter.WriteBytes(AMsg.Random, 0, ClientHelloRandomLength);
  LMarker := LWriter.OpenVector(1); // legacy_session_id
  LWriter.WriteBytes(AMsg.LegacySessionId);
  LWriter.CloseVector(LMarker);
  WriteUInt16Vector(LWriter, AMsg.CipherSuites);
  LMarker := LWriter.OpenVector(1); // legacy_compression_methods
  LWriter.WriteUInt8(LegacyCompressionNull);
  LWriter.CloseVector(LMarker);
  LWriter.WriteBytes(AMsg.Extensions);
  Result := LWriter.ToBytes;
end;

class function THandshakeMessages.DecodeClientHello(
  const ABody: TBytes): TTlsClientHello;
var
  LReader, LSession, LComp: TWireReader;
begin
  LReader := TWireReader.Create(ABody);
  // legacy_version is not authoritative for version negotiation (supported_versions is, RFC
  // 8446 4.1.2 / 4.2.1) but is kept: a pre-1.2 client without supported_versions carries its
  // version here, which the server maps to a protocol_version alert rather than proceeding.
  Result.LegacyVersion := LReader.ReadUInt16;
  Result.Random := LReader.ReadBytes(ClientHelloRandomLength);
  LSession := LReader.OpenVector(1);
  Result.LegacySessionId := LSession.ReadBytes(LSession.Remaining);
  if System.Length(Result.LegacySessionId) > MaxLegacySessionIdLength then
    raise EDecodeErrorTlsLibException.CreateRes(@SSessionIdTooLong);
  Result.CipherSuites := ReadUInt16Vector(LReader);
  LComp := LReader.OpenVector(1);
  Result.CompressionMethods := LComp.ReadBytes(LComp.Remaining);
  // legacy_compression_methods must offer the null method (both versions); a list without it
  // selects only compression this endpoint will never support. The list is a well-formed byte
  // vector with an unacceptable value, so this is an illegal_parameter, not a decode error
  // (RFC 8446 4.1.2 / RFC 5246 7.4.1.2). The stricter TLS 1.3 "exactly one null byte" rule is
  // version-specific and enforced once the negotiated version is known.
  if not CompressionOffersNull(Result.CompressionMethods) then
    raise EFatalAlertTlsLibException.CreateRes(
      TTlsAlertDescription.IllegalParameter, @SNoNullCompression);
  Result.Extensions := LReader.ReadBytes(LReader.Remaining);
end;

class function THandshakeMessages.EncodeServerHello(
  const AMsg: TTlsServerHello): TBytes;
var
  LWriter: IWireWriter;
  LMarker: TWireVectorMarker;
begin
  Result := nil;
  LWriter := TWireWriter.Create;
  LWriter.WriteUInt16(TlsWireVersionTls12); // legacy_version
  LWriter.WriteBytes(AMsg.Random, 0, ClientHelloRandomLength);
  LMarker := LWriter.OpenVector(1); // legacy_session_id_echo
  LWriter.WriteBytes(AMsg.LegacySessionIdEcho);
  LWriter.CloseVector(LMarker);
  LWriter.WriteUInt16(AMsg.CipherSuite);
  LWriter.WriteUInt8(LegacyCompressionNull); // legacy_compression_method
  LWriter.WriteBytes(AMsg.Extensions);
  Result := LWriter.ToBytes;
end;

class function THandshakeMessages.DecodeServerHello(
  const ABody: TBytes): TTlsServerHello;
var
  LReader, LSession: TWireReader;
  LCompression: Byte;
begin
  LReader := TWireReader.Create(ABody);
  // legacy_version is read verbatim, not rejected: a server that selected TLS 1.2 or below
  // carries its version here (supported_versions absent), and the client maps an unsupported
  // selection to a protocol_version alert during version negotiation (RFC 8446 4.2.1)
  Result.LegacyVersion := LReader.ReadUInt16;
  Result.Random := LReader.ReadBytes(ClientHelloRandomLength);
  LSession := LReader.OpenVector(1);
  Result.LegacySessionIdEcho := LSession.ReadBytes(LSession.Remaining);
  if System.Length(Result.LegacySessionIdEcho) > MaxLegacySessionIdLength then
    raise EDecodeErrorTlsLibException.CreateRes(@SSessionIdTooLong);
  Result.CipherSuite := LReader.ReadUInt16;
  LCompression := LReader.ReadUInt8;
  Result.Extensions := LReader.ReadBytes(LReader.Remaining);
  // legacy_compression_method MUST be the null method. In TLS 1.3 it is a fixed structural byte
  // whose only legal value is 0, so a non-zero is a field out of the specified range - a
  // decode_error (RFC 8446 4.1.3 / 6.2). In TLS 1.2 the compression_method is a negotiated
  // selection, so an unacceptable value is an illegal_parameter (RFC 5246 7.4.1.3). The selected
  // version is read from supported_versions, which a 1.3 server (a HelloRetryRequest included)
  // always sends; its absence means the server negotiated 1.2 or below.
  if LCompression <> LegacyCompressionNull then
  begin
    if ServerHelloSelectedVersion(Result.Extensions) = TlsWireVersionTls13 then
      raise EDecodeErrorTlsLibException.CreateRes(@SServerCompressionNotNull)
    else
      raise EFatalAlertTlsLibException.CreateRes(
        TTlsAlertDescription.IllegalParameter, @SServerCompressionNotNull);
  end;
end;

class function THandshakeMessages.ServerHelloSelectedVersion(
  const AExtensions: TBytes): UInt16;
var
  LReader, LOuter, LData: TWireReader;
  LType: UInt16;
begin
  Result := 0;
  // an omitted extensions field (a TLS 1.2 ServerHello may end after compression_method)
  // carries no supported_versions, so the selected version is the legacy one (0)
  if System.Length(AExtensions) = 0 then
    Exit;
  LReader := TWireReader.Create(AExtensions);
  LOuter := LReader.OpenVector(2);
  while not LOuter.EndReached do
  begin
    LType := LOuter.ReadUInt16;
    LData := LOuter.OpenVector(2);
    if LType = TExtensionTypes.SupportedVersions then
      // a ServerHello supported_versions carries the single selected uint16 version
      Exit(LData.ReadUInt16);
    LData.ReadBytes(LData.Remaining);
  end;
end;

class function THandshakeMessages.EncodeEncryptedExtensions(
  const AExtensions: TBytes): TBytes;
begin
  Result := System.Copy(AExtensions);
end;

class function THandshakeMessages.DecodeEncryptedExtensions(
  const ABody: TBytes): TBytes;
begin
  Result := System.Copy(ABody);
end;

class function THandshakeMessages.EncodeCertificate(
  const AMsg: TTlsCertificate): TBytes;
var
  LWriter: IWireWriter;
  LContext, LList, LCert: TWireVectorMarker;
  LEntry: TTlsCertificateEntry;
begin
  Result := nil;
  LWriter := TWireWriter.Create;
  LContext := LWriter.OpenVector(1);
  LWriter.WriteBytes(AMsg.RequestContext);
  LWriter.CloseVector(LContext);
  LList := LWriter.OpenVector(3);
  for LEntry in AMsg.Entries do
  begin
    LCert := LWriter.OpenVector(3);
    LWriter.WriteBytes(LEntry.CertData);
    LWriter.CloseVector(LCert);
    LWriter.WriteBytes(LEntry.Extensions);
  end;
  LWriter.CloseVector(LList);
  Result := LWriter.ToBytes;
end;

class function THandshakeMessages.DecodeCertificate(
  const ABody: TBytes): TTlsCertificate;
var
  LReader, LContext, LList, LCert: TWireReader;
  LEntry: TTlsCertificateEntry;
  LCount: Int32;
begin
  LReader := TWireReader.Create(ABody);
  LContext := LReader.OpenVector(1);
  Result.RequestContext := LContext.ReadBytes(LContext.Remaining);
  Result.Entries := nil;
  LList := LReader.OpenVector(3);
  LReader.ExpectEnd;
  LCount := 0;
  while not LList.EndReached do
  begin
    LCert := LList.OpenVector(3);
    LEntry.CertData := LCert.ReadBytes(LCert.Remaining);
    LEntry.Extensions := ReadVectorRaw(LList, 2);
    SetLength(Result.Entries, LCount + 1);
    Result.Entries[LCount] := LEntry;
    Inc(LCount);
  end;
end;

class function THandshakeMessages.EncodeCertificateStatus(
  const AResponse: TBytes): TBytes;
var
  LWriter: IWireWriter;
  LMarker: TWireVectorMarker;
begin
  Result := nil;
  LWriter := TWireWriter.Create;
  LWriter.WriteUInt8(CertificateStatusTypeOcsp);
  LMarker := LWriter.OpenVector(3); // OCSPResponse<1..2^24-1>
  LWriter.WriteBytes(AResponse);
  LWriter.CloseVector(LMarker);
  Result := LWriter.ToBytes;
end;

class function THandshakeMessages.DecodeCertificateStatus(
  const ABody: TBytes): TBytes;
var
  LReader, LVec: TWireReader;
begin
  Result := nil;
  LReader := TWireReader.Create(ABody);
  if LReader.ReadUInt8 <> CertificateStatusTypeOcsp then
    raise EDecodeErrorTlsLibException.CreateRes(@SBadCertificateStatusType);
  LVec := LReader.OpenVector(3);
  Result := LVec.ReadBytes(LVec.Remaining);
  LReader.ExpectEnd;
  if System.Length(Result) = 0 then
    raise EDecodeErrorTlsLibException.CreateRes(@SEmptyOcspResponse);
end;

class function THandshakeMessages.EncodeLeafStapleExtensions(
  const AResponse: TBytes): TBytes;
var
  LWriter: IWireWriter;
  LOuter, LExt: TWireVectorMarker;
begin
  Result := nil;
  LWriter := TWireWriter.Create;
  LOuter := LWriter.OpenVector(2); // extensions<0..2^16-1>
  LWriter.WriteUInt16(StatusRequestExtensionCode);
  LExt := LWriter.OpenVector(2); // extension_data<0..2^16-1>
  LWriter.WriteBytes(EncodeCertificateStatus(AResponse));
  LWriter.CloseVector(LExt);
  LWriter.CloseVector(LOuter);
  Result := LWriter.ToBytes;
end;

class function THandshakeMessages.TryExtractLeafStaple(const AExtensions: TBytes;
  out AResponse: TBytes): Boolean;
var
  LReader, LEntries, LData: TWireReader;
  LType: UInt16;
  LBody: TBytes;
begin
  Result := False;
  AResponse := nil;
  if System.Length(AExtensions) = 0 then
    Exit;
  LReader := TWireReader.Create(AExtensions);
  LEntries := LReader.OpenVector(2);
  LReader.ExpectEnd;
  while not LEntries.EndReached do
  begin
    LType := LEntries.ReadUInt16;
    LData := LEntries.OpenVector(2);
    LBody := LData.ReadBytes(LData.Remaining);
    if LType = StatusRequestExtensionCode then
    begin
      AResponse := DecodeCertificateStatus(LBody);
      Result := True;
      Exit;
    end;
  end;
end;

class function THandshakeMessages.CertificateEntryExtensionTypes(
  const AExtensions: TBytes): TArray<UInt16>;
var
  LReader, LEntries, LData: TWireReader;
  LCount: Int32;
begin
  Result := nil;
  LCount := 0;
  if System.Length(AExtensions) = 0 then
    Exit;
  LReader := TWireReader.Create(AExtensions);
  LEntries := LReader.OpenVector(2);
  LReader.ExpectEnd;
  while not LEntries.EndReached do
  begin
    SetLength(Result, LCount + 1);
    Result[LCount] := LEntries.ReadUInt16;
    Inc(LCount);
    LData := LEntries.OpenVector(2);
    LData.ReadBytes(LData.Remaining);
  end;
end;

class function THandshakeMessages.EncodeCertificateVerify(
  const AMsg: TTlsCertificateVerify): TBytes;
var
  LWriter: IWireWriter;
  LMarker: TWireVectorMarker;
begin
  Result := nil;
  LWriter := TWireWriter.Create;
  LWriter.WriteUInt16(AMsg.Algorithm);
  LMarker := LWriter.OpenVector(2);
  LWriter.WriteBytes(AMsg.Signature);
  LWriter.CloseVector(LMarker);
  Result := LWriter.ToBytes;
end;

class function THandshakeMessages.DecodeCertificateVerify(
  const ABody: TBytes): TTlsCertificateVerify;
var
  LReader, LSig: TWireReader;
begin
  LReader := TWireReader.Create(ABody);
  Result.Algorithm := LReader.ReadUInt16;
  LSig := LReader.OpenVector(2);
  Result.Signature := LSig.ReadBytes(LSig.Remaining);
  LReader.ExpectEnd;
end;

class function THandshakeMessages.EncodeCompressedCertificate(
  const AMsg: TTlsCompressedCertificate): TBytes;
var
  LWriter: IWireWriter;
  LMarker: TWireVectorMarker;
begin
  Result := nil;
  LWriter := TWireWriter.Create;
  LWriter.WriteUInt16(AMsg.Algorithm);
  LWriter.WriteUInt24(UInt32(AMsg.UncompressedLength));
  LMarker := LWriter.OpenVector(3);
  LWriter.WriteBytes(AMsg.Compressed);
  LWriter.CloseVector(LMarker);
  Result := LWriter.ToBytes;
end;

class function THandshakeMessages.DecodeCompressedCertificate(
  const ABody: TBytes): TTlsCompressedCertificate;
var
  LReader, LVec: TWireReader;
begin
  LReader := TWireReader.Create(ABody);
  Result.Algorithm := LReader.ReadUInt16;
  Result.UncompressedLength := Int32(LReader.ReadUInt24);
  LVec := LReader.OpenVector(3);
  Result.Compressed := LVec.ReadBytes(LVec.Remaining);
  LReader.ExpectEnd;
end;

class function THandshakeMessages.EncodeFinished(
  const AVerifyData: TBytes): TBytes;
begin
  Result := System.Copy(AVerifyData);
end;

class function THandshakeMessages.DecodeFinished(const ABody: TBytes): TBytes;
begin
  Result := System.Copy(ABody);
end;

class function THandshakeMessages.EncodeCertificate12(
  const AChain: TArray<TBytes>): TBytes;
var
  LWriter: IWireWriter;
  LList, LCert: TWireVectorMarker;
  LEntry: TBytes;
begin
  Result := nil;
  LWriter := TWireWriter.Create;
  LList := LWriter.OpenVector(3);
  for LEntry in AChain do
  begin
    LCert := LWriter.OpenVector(3);
    LWriter.WriteBytes(LEntry);
    LWriter.CloseVector(LCert);
  end;
  LWriter.CloseVector(LList);
  Result := LWriter.ToBytes;
end;

class function THandshakeMessages.DecodeCertificate12(
  const ABody: TBytes): TArray<TBytes>;
var
  LReader, LList, LCert: TWireReader;
  LCount: Int32;
begin
  Result := nil;
  LReader := TWireReader.Create(ABody);
  LList := LReader.OpenVector(3);
  LReader.ExpectEnd;
  LCount := 0;
  while not LList.EndReached do
  begin
    LCert := LList.OpenVector(3);
    SetLength(Result, LCount + 1);
    Result[LCount] := LCert.ReadBytes(LCert.Remaining);
    Inc(LCount);
  end;
end;

class function THandshakeMessages.EcdheServerParams(ANamedCurve: UInt16;
  const APublicKey: TBytes): TBytes;
var
  LWriter: IWireWriter;
  LPoint: TWireVectorMarker;
begin
  Result := nil;
  LWriter := TWireWriter.Create;
  LWriter.WriteUInt8(EcCurveTypeNamedCurve);
  LWriter.WriteUInt16(ANamedCurve);
  LPoint := LWriter.OpenVector(1);
  LWriter.WriteBytes(APublicKey);
  LWriter.CloseVector(LPoint);
  Result := LWriter.ToBytes;
end;

class function THandshakeMessages.EncodeServerKeyExchangeEcdhe(
  const AMsg: TTlsServerKeyExchangeEcdhe): TBytes;
var
  LWriter: IWireWriter;
  LSig: TWireVectorMarker;
begin
  Result := nil;
  LWriter := TWireWriter.Create;
  LWriter.WriteBytes(EcdheServerParams(AMsg.NamedCurve, AMsg.PublicKey));
  LWriter.WriteUInt16(AMsg.SignatureScheme);
  LSig := LWriter.OpenVector(2);
  LWriter.WriteBytes(AMsg.Signature);
  LWriter.CloseVector(LSig);
  Result := LWriter.ToBytes;
end;

class function THandshakeMessages.DecodeServerKeyExchangeEcdhe(
  const ABody: TBytes): TTlsServerKeyExchangeEcdhe;
var
  LReader, LPoint, LSig: TWireReader;
begin
  LReader := TWireReader.Create(ABody);
  if LReader.ReadUInt8 <> EcCurveTypeNamedCurve then
    raise EDecodeErrorTlsLibException.CreateRes(@SBadCurveType);
  Result.NamedCurve := LReader.ReadUInt16;
  LPoint := LReader.OpenVector(1);
  Result.PublicKey := LPoint.ReadBytes(LPoint.Remaining);
  Result.SignatureScheme := LReader.ReadUInt16;
  LSig := LReader.OpenVector(2);
  Result.Signature := LSig.ReadBytes(LSig.Remaining);
  LReader.ExpectEnd;
end;

class function THandshakeMessages.EncodeClientKeyExchangeEcdhe(
  const AMsg: TTlsClientKeyExchangeEcdhe): TBytes;
var
  LWriter: IWireWriter;
  LPoint: TWireVectorMarker;
begin
  Result := nil;
  LWriter := TWireWriter.Create;
  LPoint := LWriter.OpenVector(1);
  LWriter.WriteBytes(AMsg.PublicKey);
  LWriter.CloseVector(LPoint);
  Result := LWriter.ToBytes;
end;

class function THandshakeMessages.DecodeClientKeyExchangeEcdhe(
  const ABody: TBytes): TTlsClientKeyExchangeEcdhe;
var
  LReader, LPoint: TWireReader;
begin
  LReader := TWireReader.Create(ABody);
  LPoint := LReader.OpenVector(1);
  Result.PublicKey := LPoint.ReadBytes(LPoint.Remaining);
  LReader.ExpectEnd;
end;

class function THandshakeMessages.EncodeCertificateRequest13(
  const AMsg: TTlsCertificateRequest13): TBytes;
var
  LWriter: IWireWriter;
  LContext: TWireVectorMarker;
begin
  Result := nil;
  LWriter := TWireWriter.Create;
  LContext := LWriter.OpenVector(1);
  LWriter.WriteBytes(AMsg.RequestContext);
  LWriter.CloseVector(LContext);
  // the extension block already carries its own 2-byte length prefix
  LWriter.WriteBytes(AMsg.Extensions);
  Result := LWriter.ToBytes;
end;

class function THandshakeMessages.DecodeCertificateRequest13(
  const ABody: TBytes): TTlsCertificateRequest13;
var
  LReader, LContext: TWireReader;
begin
  LReader := TWireReader.Create(ABody);
  LContext := LReader.OpenVector(1);
  Result.RequestContext := LContext.ReadBytes(LContext.Remaining);
  Result.Extensions := LReader.ReadBytes(LReader.Remaining);
end;

class function THandshakeMessages.EncodeCertificateRequest12(
  const AMsg: TTlsCertificateRequest12): TBytes;
var
  LWriter: IWireWriter;
  LTypes, LCas, LDn: TWireVectorMarker;
  LName: TBytes;
begin
  Result := nil;
  LWriter := TWireWriter.Create;
  LTypes := LWriter.OpenVector(1);
  LWriter.WriteBytes(AMsg.CertificateTypes);
  LWriter.CloseVector(LTypes);
  WriteUInt16Vector(LWriter, AMsg.SupportedSignatureAlgorithms);
  // certificate_authorities<0..2^16-1>, each DistinguishedName opaque<1..2^16-1>
  LCas := LWriter.OpenVector(2);
  for LName in AMsg.CertificateAuthorities do
  begin
    LDn := LWriter.OpenVector(2);
    LWriter.WriteBytes(LName);
    LWriter.CloseVector(LDn);
  end;
  LWriter.CloseVector(LCas);
  Result := LWriter.ToBytes;
end;

class function THandshakeMessages.DecodeCertificateRequest12(
  const ABody: TBytes): TTlsCertificateRequest12;
var
  LReader, LTypes, LCas, LDn: TWireReader;
  LCaCount: Int32;
begin
  LReader := TWireReader.Create(ABody);
  LTypes := LReader.OpenVector(1);
  Result.CertificateTypes := LTypes.ReadBytes(LTypes.Remaining);
  Result.SupportedSignatureAlgorithms := ReadUInt16Vector(LReader);
  // the list must name at least one algorithm (RFC 5246 7.4.4 <2..2^16-1>); an empty
  // supported_signature_algorithms is a decode error
  if System.Length(Result.SupportedSignatureAlgorithms) = 0 then
    raise EDecodeErrorTlsLibException.CreateRes(@SEmptyCertRequestSigAlgs);
  // certificate_authorities<0..2^16-1>: each DistinguishedName opaque<1..2^16-1> is
  // parsed and surfaced; the profile does not pin issuers but the peer may inspect them.
  Result.CertificateAuthorities := nil;
  LCas := LReader.OpenVector(2);
  LCaCount := 0;
  while not LCas.EndReached do
  begin
    LDn := LCas.OpenVector(2);
    if LDn.Remaining = 0 then
      raise EDecodeErrorTlsLibException.CreateRes(@SEmptyDistinguishedName12);
    SetLength(Result.CertificateAuthorities, LCaCount + 1);
    Result.CertificateAuthorities[LCaCount] := LDn.ReadBytes(LDn.Remaining);
    Inc(LCaCount);
  end;
  LReader.ExpectEnd; // no trailing data after the CertificateRequest structure
end;

class function THandshakeMessages.EncodeNewSessionTicket(
  const AMsg: TTlsNewSessionTicket): TBytes;
var
  LWriter: IWireWriter;
  LMarker: TWireVectorMarker;
begin
  Result := nil;
  LWriter := TWireWriter.Create;
  LWriter.WriteUInt32(AMsg.TicketLifetime);
  LWriter.WriteUInt32(AMsg.TicketAgeAdd);
  LMarker := LWriter.OpenVector(1); // ticket_nonce<0..255>
  LWriter.WriteBytes(AMsg.TicketNonce);
  LWriter.CloseVector(LMarker);
  LMarker := LWriter.OpenVector(2); // ticket<1..2^16-1>
  LWriter.WriteBytes(AMsg.Ticket);
  LWriter.CloseVector(LMarker);
  // Extensions is the raw extension vector (2-byte length + entries)
  LWriter.WriteBytes(AMsg.Extensions);
  Result := LWriter.ToBytes;
end;

class function THandshakeMessages.DecodeNewSessionTicket(
  const ABody: TBytes): TTlsNewSessionTicket;
var
  LReader, LNonce, LTicket: TWireReader;
begin
  LReader := TWireReader.Create(ABody);
  Result.TicketLifetime := LReader.ReadUInt32;
  Result.TicketAgeAdd := LReader.ReadUInt32;
  LNonce := LReader.OpenVector(1);
  Result.TicketNonce := LNonce.ReadBytes(LNonce.Remaining);
  LTicket := LReader.OpenVector(2);
  Result.Ticket := LTicket.ReadBytes(LTicket.Remaining);
  // ticket is opaque ticket<1..2^16-1> (RFC 8446 4.6.1): an empty ticket is malformed
  if System.Length(Result.Ticket) = 0 then
    raise EDecodeErrorTlsLibException.CreateRes(@SEmptySessionTicket);
  // keep the extension block raw for the extension codec (early_data)
  Result.Extensions := ReadVectorRaw(LReader, 2);
  LReader.ExpectEnd; // no trailing data after the NewSessionTicket structure
end;

class function THandshakeMessages.EncodeTls12NewSessionTicket(
  const AMsg: TTls12NewSessionTicket): TBytes;
var
  LWriter: IWireWriter;
  LMarker: TWireVectorMarker;
begin
  Result := nil;
  LWriter := TWireWriter.Create;
  LWriter.WriteUInt32(AMsg.TicketLifetimeHint);
  LMarker := LWriter.OpenVector(2); // ticket<0..2^16-1>
  LWriter.WriteBytes(AMsg.Ticket);
  LWriter.CloseVector(LMarker);
  Result := LWriter.ToBytes;
end;

class function THandshakeMessages.DecodeTls12NewSessionTicket(
  const ABody: TBytes): TTls12NewSessionTicket;
var
  LReader, LTicket: TWireReader;
begin
  LReader := TWireReader.Create(ABody);
  Result.TicketLifetimeHint := LReader.ReadUInt32;
  LTicket := LReader.OpenVector(2);
  Result.Ticket := LTicket.ReadBytes(LTicket.Remaining);
  LReader.ExpectEnd; // no trailing data after the NewSessionTicket structure (RFC 5077 3.3)
end;

end.
