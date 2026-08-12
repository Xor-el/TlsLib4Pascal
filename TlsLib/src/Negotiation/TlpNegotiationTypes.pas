{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpNegotiationTypes;

{$I ..\Include\TlsLib.inc}

interface

uses
  SysUtils,
  TlpCryptoAlgorithms;

type
  /// <summary>How a server resolves the cipher suite when more than one is mutually supported:
  /// ServerOrder (the default) imposes the server's own preference order; ClientOrder honors the
  /// client's offered order, selecting the client's most-preferred mutually supported suite.</summary>
  TServerCipherPreference = (ServerOrder, ClientOrder);

  /// <summary>TLS 1.3 cipher-suite wire codepoints (RFC 8446 B.4).</summary>
  TCipherSuites13 = class sealed(TObject)
  public const
    Aes128GcmSha256 = UInt16($1301);
    Aes256GcmSha384 = UInt16($1302);
    ChaCha20Poly1305Sha256 = UInt16($1303);
  end;

  /// <summary>
  /// The hardened TLS 1.2 cipher-suite wire codepoints (RFC 5289 / RFC 7905):
  /// ECDHE key exchange with ECDSA or RSA authentication over AEAD ciphers only.
  /// </summary>
  TCipherSuites12 = class sealed(TObject)
  public const
    EcdheEcdsaAes128GcmSha256 = UInt16($C02B);
    EcdheEcdsaAes256GcmSha384 = UInt16($C02C);
    EcdheRsaAes128GcmSha256 = UInt16($C02F);
    EcdheRsaAes256GcmSha384 = UInt16($C030);
    EcdheEcdsaChaCha20Poly1305Sha256 = UInt16($CCA9);
    EcdheRsaChaCha20Poly1305Sha256 = UInt16($CCA8);
  end;

  /// <summary>Signature-scheme wire codepoints (RFC 8446 4.2.3) and their names.</summary>
  TSignatureSchemes = class sealed(TObject)
  public const
    EcdsaSecp256r1Sha256 = UInt16($0403);
    EcdsaSecp384r1Sha384 = UInt16($0503);
    EcdsaSecp521r1Sha512 = UInt16($0603);
    RsaPssRsaeSha256 = UInt16($0804);
    RsaPssRsaeSha384 = UInt16($0805);
    RsaPssRsaeSha512 = UInt16($0806);
    Ed25519 = UInt16($0807);
    Ed448 = UInt16($0808);
  end;

  /// <summary>Which protocol version a cipher suite belongs to.</summary>
  TSuiteProtocol = (Tls12, Tls13);

  /// <summary>
  /// A suite's key-exchange method. Decoupled means the suite does not tie the
  /// key exchange to the cipher (TLS 1.3, where key_share drives the exchange);
  /// Ecdhe is the ephemeral ECDH exchange named by a TLS 1.2 suite.
  /// </summary>
  TKeyExchangeMethod = (Ecdhe, Decoupled);

  /// <summary>
  /// A suite's server-authentication method. Decoupled means the suite does not
  /// tie authentication to the cipher (TLS 1.3, where signature_algorithms drive
  /// it); Ecdsa/Rsa are the authentication named by a TLS 1.2 suite.
  /// </summary>
  TAuthMethod = (Ecdsa, Rsa, Decoupled);

  /// <summary>
  /// The version-neutral facts a cipher suite resolves to: its wire codepoint,
  /// record-protection hash and AEAD, and AEAD key size. The AEAD usage limit is
  /// derived from Aead by the record layer, so it is not stored here.
  /// </summary>
  TCipherSuiteCommon = record
    Code: UInt16;
    Hash: THashAlgorithm;
    Aead: TAeadAlgorithm;
    KeyLength: Int32;
  end;

  /// <summary>
  /// A cipher suite as a discriminated value: the version-neutral Common facts,
  /// a Protocol tag, and the TLS 1.2 key-exchange/authentication/PRF fields. A
  /// TLS 1.3 suite carries KeyExchange = Auth = Decoupled (a true statement: 1.3
  /// decouples them from the cipher). Selection is branched on Protocol; the 1.2
  /// fields drive ServerKeyExchange signing and the PRF, and are inert for 1.3.
  /// </summary>
  TTlsCipherSuite = record
    Common: TCipherSuiteCommon;
    Protocol: TSuiteProtocol;
    KeyExchange: TKeyExchangeMethod;
    Auth: TAuthMethod;
    Prf: THashAlgorithm;
  end;

  /// <summary>
  /// The named-group wire codepoints (RFC 8446 / RFC 9370) and the mapping between
  /// a code and the provider group name it resolves to.
  /// </summary>
  TNamedGroupCatalog = class sealed(TObject)
  public const
    X25519 = UInt16($001D);
    Secp256r1 = UInt16($0017);
    Secp384r1 = UInt16($0018);
    Secp521r1 = UInt16($0019);
    MlKem768 = UInt16($0201);
    X25519MlKem768 = UInt16($11EC);
  public
    class function TryCode(const AName: string; out ACode: UInt16): Boolean; static;
  end;

const
  // last 8 bytes of ServerHello.random when a 1.3-capable server negotiates lower
  // (RFC 8446 4.1.3): "DOWNGRD" then 0x01 for 1.2, 0x00 for 1.1 and below
  Tls12DowngradeSentinel: array [0 .. 7] of Byte =
    ($44, $4F, $57, $4E, $47, $52, $44, $01);
  Tls11DowngradeSentinel: array [0 .. 7] of Byte =
    ($44, $4F, $57, $4E, $47, $52, $44, $00);
  // RFC 7507 signaling cipher suite: a client lists it when retrying at a lower version
  // after a failed handshake; it is never negotiated as a real suite
  TlsFallbackScsv = UInt16($5600);
  // ServerHello.random of a HelloRetryRequest = SHA-256("HelloRetryRequest")
  // (RFC 8446 4.1.3)
  HelloRetryRequestSentinel: array [0 .. 31] of Byte = (
    $CF, $21, $AD, $74, $E5, $9A, $61, $11, $BE, $1D, $8C, $02, $1E, $65, $B8, $91,
    $C2, $A2, $11, $16, $7A, $BB, $8C, $5E, $07, $9E, $09, $E2, $C8, $A8, $33, $9C);

implementation

{ TNamedGroupCatalog }

class function TNamedGroupCatalog.TryCode(const AName: string;
  out ACode: UInt16): Boolean;
begin
  Result := True;
  if AName = 'X25519' then
    ACode := X25519
  else if AName = 'secp256r1' then
    ACode := Secp256r1
  else if AName = 'secp384r1' then
    ACode := Secp384r1
  else if AName = 'secp521r1' then
    ACode := Secp521r1
  else if AName = 'ML-KEM-768' then
    ACode := MlKem768
  else if AName = 'X25519MLKEM768' then
    ACode := X25519MlKem768
  else
  begin
    ACode := 0;
    Result := False;
  end;
end;

end.
