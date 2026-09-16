{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit HandshakeMessagesTests;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  SysUtils,
  Classes,
{$IFDEF FPC}
  fpcunit,
  testregistry,
{$ELSE}
  TestFramework,
{$ENDIF FPC}
  TlpTlsLibExceptions,
  TlpNegotiationTypes,
  TlpHandshakeMessage,
  TlpHandshakeMessages,
  TlsLibTestBase;

type
  TTestHandshakeMessages = class(TTlsLibAlgorithmTestCase)
  private
    FVec: TStringList;
    function Body(const AName: string): TBytes;
  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestClientHelloDecodeAndRoundTrip;
    procedure TestServerHelloDecodeAndRoundTrip;
    procedure TestEncryptedExtensionsRoundTrip;
    procedure TestCertificateDecodeAndRoundTrip;
    procedure TestCertificateVerifyDecodeAndRoundTrip;
    procedure TestCertificateRequest12CertificateAuthoritiesRoundTrip;
    procedure TestFinishedRoundTrip;
    procedure TestTruncatedClientHelloIsDecodeError;
    procedure TestOverlongSessionIdIsDecodeError;
    procedure TestEmptyOrTrailingNewSessionTicketIsDecodeError;
  end;

implementation

{ TTestHandshakeMessages }

procedure TTestHandshakeMessages.SetUp;
begin
  inherited SetUp;
  FVec := LoadVectorFields('Rfc8448/HandshakeMessages.txt');
end;

procedure TTestHandshakeMessages.TearDown;
begin
  FVec.Free;
  inherited TearDown;
end;

function TTestHandshakeMessages.Body(const AName: string): TBytes;
var
  LReader: THandshakeMessageReader;
  LMessage: TTlsHandshakeMessage;
  LWhole: TBytes;
begin
  Result := nil;
  LWhole := DecodeHex(FVec.Values[AName]);
  LReader := THandshakeMessageReader.Create;
  try
    LReader.Append(LWhole, 0, System.Length(LWhole));
    CheckTrue(LReader.NextMessage(LMessage), AName + ' frames');
    Result := LMessage.Body;
  finally
    LReader.Free;
  end;
end;

procedure TTestHandshakeMessages.TestClientHelloDecodeAndRoundTrip;
var
  LBody: TBytes;
  LMsg: TTlsClientHello;
begin
  LBody := Body('client_hello');
  LMsg := THandshakeMessages.DecodeClientHello(LBody);
  CheckEquals(32, System.Length(LMsg.Random), 'random is 32 bytes');
  CheckEquals(0, System.Length(LMsg.LegacySessionId), 'RFC 8448 CH session_id is empty');
  CheckEquals(3, System.Length(LMsg.CipherSuites), 'three offered suites');
  CheckEquals(TCipherSuites13.Aes128GcmSha256, LMsg.CipherSuites[0], 'AES-128-GCM first');
  CheckEquals(TCipherSuites13.ChaCha20Poly1305Sha256, LMsg.CipherSuites[1], 'ChaCha second');
  CheckEquals(TCipherSuites13.Aes256GcmSha384, LMsg.CipherSuites[2], 'AES-256-GCM third');
  CheckEqualBytes('ClientHello round-trips byte-exact', LBody,
    THandshakeMessages.EncodeClientHello(LMsg));
end;

procedure TTestHandshakeMessages.TestServerHelloDecodeAndRoundTrip;
var
  LBody: TBytes;
  LMsg: TTlsServerHello;
begin
  LBody := Body('server_hello');
  LMsg := THandshakeMessages.DecodeServerHello(LBody);
  CheckEquals(32, System.Length(LMsg.Random), 'random is 32 bytes');
  CheckEquals(TCipherSuites13.Aes128GcmSha256, LMsg.CipherSuite, 'selected AES-128-GCM');
  CheckEqualBytes('ServerHello round-trips byte-exact', LBody,
    THandshakeMessages.EncodeServerHello(LMsg));
end;

procedure TTestHandshakeMessages.TestEncryptedExtensionsRoundTrip;
var
  LBody: TBytes;
begin
  LBody := Body('encrypted_ext');
  CheckEqualBytes('EncryptedExtensions round-trips', LBody,
    THandshakeMessages.EncodeEncryptedExtensions(
    THandshakeMessages.DecodeEncryptedExtensions(LBody)));
end;

procedure TTestHandshakeMessages.TestCertificateDecodeAndRoundTrip;
var
  LBody: TBytes;
  LMsg: TTlsCertificate;
begin
  LBody := Body('certificate');
  LMsg := THandshakeMessages.DecodeCertificate(LBody);
  CheckEquals(0, System.Length(LMsg.RequestContext), 'empty request context');
  CheckEquals(1, System.Length(LMsg.Entries), 'one certificate');
  CheckTrue(System.Length(LMsg.Entries[0].CertData) > 0, 'cert data present');
  CheckEqualBytes('Certificate round-trips byte-exact', LBody,
    THandshakeMessages.EncodeCertificate(LMsg));
end;

procedure TTestHandshakeMessages.TestCertificateVerifyDecodeAndRoundTrip;
var
  LBody: TBytes;
  LMsg: TTlsCertificateVerify;
begin
  LBody := Body('cert_verify');
  LMsg := THandshakeMessages.DecodeCertificateVerify(LBody);
  CheckEquals(TSignatureSchemes.RsaPssRsaeSha256, LMsg.Algorithm, 'rsa_pss_rsae_sha256');
  CheckEquals(128, System.Length(LMsg.Signature), '1024-bit signature');
  CheckEqualBytes('CertificateVerify round-trips byte-exact', LBody,
    THandshakeMessages.EncodeCertificateVerify(LMsg));
end;

procedure TTestHandshakeMessages.TestCertificateRequest12CertificateAuthoritiesRoundTrip;
var
  LReq, LDecoded: TTlsCertificateRequest12;
begin
  // certificate_authorities is a vector of DER DistinguishedName opaque<1..2^16-1>
  // (RFC 5246 7.4.4); the named issuers must round-trip in order
  LReq.CertificateTypes := TBytes.Create(64, 1);
  LReq.SupportedSignatureAlgorithms := TArray<UInt16>.Create(
    TSignatureSchemes.EcdsaSecp256r1Sha256, TSignatureSchemes.RsaPssRsaeSha256);
  LReq.CertificateAuthorities := TArray<TBytes>.Create(
    TBytes.Create($30, $0A, $31, $08), TBytes.Create($30, $05, $31, $03, $02, $01, $07));
  LDecoded := THandshakeMessages.DecodeCertificateRequest12(
    THandshakeMessages.EncodeCertificateRequest12(LReq));
  CheckEquals(2, System.Length(LDecoded.CertificateAuthorities),
    'two certificate_authorities round-trip');
  CheckEqualBytes('first authority round-trips', LReq.CertificateAuthorities[0],
    LDecoded.CertificateAuthorities[0]);
  CheckEqualBytes('second authority round-trips', LReq.CertificateAuthorities[1],
    LDecoded.CertificateAuthorities[1]);

  // an empty certificate_authorities list (RFC 5246 7.4.4 <0..2^16-1>: naming no
  // acceptable issuer) round-trips as empty
  LReq := Default(TTlsCertificateRequest12);
  LReq.CertificateTypes := TBytes.Create(64, 1);
  LReq.SupportedSignatureAlgorithms := TArray<UInt16>.Create(
    TSignatureSchemes.EcdsaSecp256r1Sha256, TSignatureSchemes.RsaPssRsaeSha256);
  LDecoded := THandshakeMessages.DecodeCertificateRequest12(
    THandshakeMessages.EncodeCertificateRequest12(LReq));
  CheckEquals(0, System.Length(LDecoded.CertificateAuthorities),
    'an empty certificate_authorities list round-trips as empty');
end;

procedure TTestHandshakeMessages.TestFinishedRoundTrip;
var
  LBody: TBytes;
begin
  LBody := Body('server_finished');
  CheckEquals(32, System.Length(LBody), 'SHA-256 verify_data is 32 bytes');
  CheckEqualBytes('Finished round-trips', LBody,
    THandshakeMessages.EncodeFinished(THandshakeMessages.DecodeFinished(LBody)));
end;

procedure TTestHandshakeMessages.TestTruncatedClientHelloIsDecodeError;
var
  LBody: TBytes;
  LRaised: Boolean;
begin
  LBody := System.Copy(Body('client_hello'), 0, 10); // header + a few bytes only
  LRaised := False;
  try
    THandshakeMessages.DecodeClientHello(LBody);
  except
    on E: EDecodeErrorTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a truncated ClientHello is a decode_error, not an over-read');
end;

procedure TTestHandshakeMessages.TestOverlongSessionIdIsDecodeError;

  function Rejects(const ABody: TBytes): Boolean;
  begin
    Result := False;
    try
      THandshakeMessages.DecodeClientHello(ABody);
    except
      on E: EDecodeErrorTlsLibException do
        Result := True;
    end;
  end;

var
  LClient: TTlsClientHello;
  LServer: TTlsServerHello;
  LRaised: Boolean;
begin
  // legacy_session_id / legacy_session_id_echo are <0..32> (RFC 8446 4.1.2/4.1.3): a
  // 33-byte value must be a decode_error, not silently accepted
  LClient := THandshakeMessages.DecodeClientHello(Body('client_hello'));
  SetLength(LClient.LegacySessionId, 33);
  CheckTrue(Rejects(THandshakeMessages.EncodeClientHello(LClient)),
    'a 33-byte ClientHello legacy_session_id is a decode_error');

  LServer := THandshakeMessages.DecodeServerHello(Body('server_hello'));
  SetLength(LServer.LegacySessionIdEcho, 33);
  LRaised := False;
  try
    THandshakeMessages.DecodeServerHello(THandshakeMessages.EncodeServerHello(LServer));
  except
    on E: EDecodeErrorTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a 33-byte ServerHello legacy_session_id_echo is a decode_error');
end;

procedure TTestHandshakeMessages.TestEmptyOrTrailingNewSessionTicketIsDecodeError;

  function Rejects(const ABody: TBytes): Boolean;
  begin
    Result := False;
    try
      THandshakeMessages.DecodeNewSessionTicket(ABody);
    except
      on E: EDecodeErrorTlsLibException do
        Result := True;
    end;
  end;

var
  LNst: TTlsNewSessionTicket;
  LGood, LTrailing: TBytes;
begin
  LNst.TicketLifetime := 100;
  LNst.TicketAgeAdd := 0;
  LNst.TicketNonce := nil;
  LNst.Ticket := TBytes.Create($AA, $BB, $CC, $DD);
  LNst.Extensions := TBytes.Create($00, $00);
  LGood := THandshakeMessages.EncodeNewSessionTicket(LNst);
  CheckFalse(Rejects(LGood), 'a well-formed NewSessionTicket decodes');

  // empty ticket is opaque ticket<1..2^16-1> -> decode_error (RFC 8446 4.6.1)
  LNst.Ticket := nil;
  CheckTrue(Rejects(THandshakeMessages.EncodeNewSessionTicket(LNst)),
    'an empty NewSessionTicket ticket is a decode_error');

  // trailing bytes after the structure are rejected
  LTrailing := System.Copy(LGood, 0, System.Length(LGood));
  SetLength(LTrailing, System.Length(LTrailing) + 1);
  CheckTrue(Rejects(LTrailing), 'trailing data after a NewSessionTicket is a decode_error');
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestHandshakeMessages);
{$ELSE}
  RegisterTest(TTestHandshakeMessages.Suite);
{$ENDIF FPC}

end.
