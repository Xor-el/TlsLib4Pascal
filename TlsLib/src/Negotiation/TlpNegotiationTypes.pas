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
  TlpCryptoDomainTypes;

type
  /// <summary>How a server resolves the cipher suite when more than one is mutually supported:
  /// ServerOrder (the default) imposes the server's own preference order; ClientOrder honors the
  /// client's offered order, selecting the client's most-preferred mutually supported suite.
  /// Governs both TLS 1.3 and TLS 1.2 handshakes identically.</summary>
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

  /// <summary>Signature-scheme wire codepoints (RFC 8446 4.2.3). Wire vocabulary only;
  /// whether a scheme may sign a given version's handshake is decided by
  /// <see cref="TSignatureScheme.IsValidForHandshake" />.</summary>
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
    // the id-RSASSA-PSS (RFC 4055) counterparts: a certificate whose issuer key is a
    // PSS-restricted key is signed with these, not the rsae schemes
    RsaPssPssSha256 = UInt16($0809);
    RsaPssPssSha384 = UInt16($080A);
    RsaPssPssSha512 = UInt16($080B);
    // legacy (RFC 8446 4.2.3): in TLS 1.3 valid only in signature_algorithms_cert,
    // never a CertificateVerify; still a TLS 1.2 handshake signature (RFC 5246 7.4.1.4.1)
    RsaPkcs1Sha256 = UInt16($0401);
    RsaPkcs1Sha384 = UInt16($0501);
    RsaPkcs1Sha512 = UInt16($0601);
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

  /// <summary>Every cipher suite this library implements, and their names: the IANA name and the
  /// OpenSSL name that hosts configure them by.</summary>
  TCipherSuiteCatalog = class sealed(TObject)
  public
    /// <summary>Every implemented suite, in catalog order.</summary>
    class function All: TArray<TTlsCipherSuite>; static;
    /// <summary>The suite for a codepoint; False for one outside the catalog.</summary>
    class function TryGet(ACode: UInt16; out ASuite: TTlsCipherSuite): Boolean; static;
    /// <summary>The IANA registered name of a negotiated cipher-suite codepoint, for display and
    /// logging. Empty for 0 (nothing negotiated yet); the bare hex codepoint for a suite this
    /// library never offers.</summary>
    class function Name(ACode: UInt16): string; static;
    /// <summary>The OpenSSL name of a suite (TLS 1.3 suites share the IANA name); the bare hex
    /// codepoint for one outside the catalog.</summary>
    class function OpenSslName(ACode: UInt16): string; static;
    /// <summary>The codepoint for an IANA or OpenSSL suite name, matched without regard to ASCII
    /// case; False for any name outside the catalog.</summary>
    class function TryCode(const AName: string; out ACode: UInt16): Boolean; static;
  end;

  /// <summary>
  /// The named-group wire codepoints (RFC 8446, the IANA TLS Supported Groups registry,
  /// RFC 10024) and the mapping between a code and the provider group name it resolves to.
  /// </summary>
  TNamedGroupCatalog = class sealed(TObject)
  public const
    X25519 = UInt16($001D);
    Secp256r1 = UInt16($0017);
    Secp384r1 = UInt16($0018);
    Secp521r1 = UInt16($0019);
    MlKem768 = UInt16($0201);
    SecP256r1MlKem768 = UInt16($11EB);
    X25519MlKem768 = UInt16($11EC);
  public
    class function TryCode(const AName: string; out ACode: UInt16): Boolean; static;
    /// <summary>The canonical provider group name for a codepoint (the spelling TryCode maps
    /// back), so a group's name is authoritative here rather than taken from a backend handle
    /// (whose spelling can differ between providers). The bare hex codepoint for an unknown code.</summary>
    class function Name(ACode: UInt16): string; static;
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

type
  TCipherSuiteEntry = record
    Suite: TTlsCipherSuite;
    IanaName: string;
    OpenSslName: string;
  end;

const
  CipherSuiteTable: array [0 .. 8] of TCipherSuiteEntry = (
    (Suite: (Common: (Code: TCipherSuites13.Aes128GcmSha256; Hash: THashAlgorithm.SHA_256;
      Aead: TAeadAlgorithm.AES_128_GCM; KeyLength: 16); Protocol: TSuiteProtocol.Tls13;
      KeyExchange: TKeyExchangeMethod.Decoupled; Auth: TAuthMethod.Decoupled;
      Prf: THashAlgorithm.SHA_256);
      IanaName: 'TLS_AES_128_GCM_SHA256'; OpenSslName: 'TLS_AES_128_GCM_SHA256'),
    (Suite: (Common: (Code: TCipherSuites13.Aes256GcmSha384; Hash: THashAlgorithm.SHA_384;
      Aead: TAeadAlgorithm.AES_256_GCM; KeyLength: 32); Protocol: TSuiteProtocol.Tls13;
      KeyExchange: TKeyExchangeMethod.Decoupled; Auth: TAuthMethod.Decoupled;
      Prf: THashAlgorithm.SHA_384);
      IanaName: 'TLS_AES_256_GCM_SHA384'; OpenSslName: 'TLS_AES_256_GCM_SHA384'),
    (Suite: (Common: (Code: TCipherSuites13.ChaCha20Poly1305Sha256;
      Hash: THashAlgorithm.SHA_256; Aead: TAeadAlgorithm.CHACHA20_POLY1305; KeyLength: 32);
      Protocol: TSuiteProtocol.Tls13; KeyExchange: TKeyExchangeMethod.Decoupled;
      Auth: TAuthMethod.Decoupled; Prf: THashAlgorithm.SHA_256);
      IanaName: 'TLS_CHACHA20_POLY1305_SHA256'; OpenSslName: 'TLS_CHACHA20_POLY1305_SHA256'),
    (Suite: (Common: (Code: TCipherSuites12.EcdheEcdsaAes128GcmSha256;
      Hash: THashAlgorithm.SHA_256; Aead: TAeadAlgorithm.AES_128_GCM; KeyLength: 16);
      Protocol: TSuiteProtocol.Tls12; KeyExchange: TKeyExchangeMethod.Ecdhe;
      Auth: TAuthMethod.Ecdsa; Prf: THashAlgorithm.SHA_256);
      IanaName: 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256';
      OpenSslName: 'ECDHE-ECDSA-AES128-GCM-SHA256'),
    (Suite: (Common: (Code: TCipherSuites12.EcdheEcdsaAes256GcmSha384;
      Hash: THashAlgorithm.SHA_384; Aead: TAeadAlgorithm.AES_256_GCM; KeyLength: 32);
      Protocol: TSuiteProtocol.Tls12; KeyExchange: TKeyExchangeMethod.Ecdhe;
      Auth: TAuthMethod.Ecdsa; Prf: THashAlgorithm.SHA_384);
      IanaName: 'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384';
      OpenSslName: 'ECDHE-ECDSA-AES256-GCM-SHA384'),
    (Suite: (Common: (Code: TCipherSuites12.EcdheEcdsaChaCha20Poly1305Sha256;
      Hash: THashAlgorithm.SHA_256; Aead: TAeadAlgorithm.CHACHA20_POLY1305; KeyLength: 32);
      Protocol: TSuiteProtocol.Tls12; KeyExchange: TKeyExchangeMethod.Ecdhe;
      Auth: TAuthMethod.Ecdsa; Prf: THashAlgorithm.SHA_256);
      IanaName: 'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256';
      OpenSslName: 'ECDHE-ECDSA-CHACHA20-POLY1305'),
    (Suite: (Common: (Code: TCipherSuites12.EcdheRsaAes128GcmSha256;
      Hash: THashAlgorithm.SHA_256; Aead: TAeadAlgorithm.AES_128_GCM; KeyLength: 16);
      Protocol: TSuiteProtocol.Tls12; KeyExchange: TKeyExchangeMethod.Ecdhe;
      Auth: TAuthMethod.Rsa; Prf: THashAlgorithm.SHA_256);
      IanaName: 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256';
      OpenSslName: 'ECDHE-RSA-AES128-GCM-SHA256'),
    (Suite: (Common: (Code: TCipherSuites12.EcdheRsaAes256GcmSha384;
      Hash: THashAlgorithm.SHA_384; Aead: TAeadAlgorithm.AES_256_GCM; KeyLength: 32);
      Protocol: TSuiteProtocol.Tls12; KeyExchange: TKeyExchangeMethod.Ecdhe;
      Auth: TAuthMethod.Rsa; Prf: THashAlgorithm.SHA_384);
      IanaName: 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384';
      OpenSslName: 'ECDHE-RSA-AES256-GCM-SHA384'),
    (Suite: (Common: (Code: TCipherSuites12.EcdheRsaChaCha20Poly1305Sha256;
      Hash: THashAlgorithm.SHA_256; Aead: TAeadAlgorithm.CHACHA20_POLY1305; KeyLength: 32);
      Protocol: TSuiteProtocol.Tls12; KeyExchange: TKeyExchangeMethod.Ecdhe;
      Auth: TAuthMethod.Rsa; Prf: THashAlgorithm.SHA_256);
      IanaName: 'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256';
      OpenSslName: 'ECDHE-RSA-CHACHA20-POLY1305'));

{ TCipherSuiteCatalog }

class function TCipherSuiteCatalog.All: TArray<TTlsCipherSuite>;
var
  LI: Int32;
begin
  SetLength(Result, System.Length(CipherSuiteTable));
  for LI := Low(CipherSuiteTable) to High(CipherSuiteTable) do
    Result[LI] := CipherSuiteTable[LI].Suite;
end;

class function TCipherSuiteCatalog.TryGet(ACode: UInt16;
  out ASuite: TTlsCipherSuite): Boolean;
var
  LI: Int32;
begin
  for LI := Low(CipherSuiteTable) to High(CipherSuiteTable) do
    if CipherSuiteTable[LI].Suite.Common.Code = ACode then
    begin
      ASuite := CipherSuiteTable[LI].Suite;
      Exit(True);
    end;
  ASuite := Default(TTlsCipherSuite);
  Result := False;
end;

class function TCipherSuiteCatalog.Name(ACode: UInt16): string;
var
  LI: Int32;
begin
  if ACode = 0 then
    Exit('');
  for LI := Low(CipherSuiteTable) to High(CipherSuiteTable) do
    if CipherSuiteTable[LI].Suite.Common.Code = ACode then
      Exit(CipherSuiteTable[LI].IanaName);
  Result := Format('0x%.4X', [ACode]);
end;

class function TCipherSuiteCatalog.OpenSslName(ACode: UInt16): string;
var
  LI: Int32;
begin
  for LI := Low(CipherSuiteTable) to High(CipherSuiteTable) do
    if CipherSuiteTable[LI].Suite.Common.Code = ACode then
      Exit(CipherSuiteTable[LI].OpenSslName);
  Result := Format('0x%.4X', [ACode]);
end;

class function TCipherSuiteCatalog.TryCode(const AName: string; out ACode: UInt16): Boolean;
var
  LI: Int32;
begin
  for LI := Low(CipherSuiteTable) to High(CipherSuiteTable) do
    if SameText(AName, CipherSuiteTable[LI].IanaName) or
      SameText(AName, CipherSuiteTable[LI].OpenSslName) then
    begin
      ACode := CipherSuiteTable[LI].Suite.Common.Code;
      Exit(True);
    end;
  ACode := 0;
  Result := False;
end;

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
  else if AName = 'SecP256r1MLKEM768' then
    ACode := SecP256r1MlKem768
  else if AName = 'X25519MLKEM768' then
    ACode := X25519MlKem768
  else
  begin
    ACode := 0;
    Result := False;
  end;
end;

class function TNamedGroupCatalog.Name(ACode: UInt16): string;
begin
  // the canonical spelling for each code (the exact string TryCode maps back)
  case ACode of
    X25519:
      Result := 'X25519';
    Secp256r1:
      Result := 'secp256r1';
    Secp384r1:
      Result := 'secp384r1';
    Secp521r1:
      Result := 'secp521r1';
    MlKem768:
      Result := 'ML-KEM-768';
    SecP256r1MlKem768:
      Result := 'SecP256r1MLKEM768';
    X25519MlKem768:
      Result := 'X25519MLKEM768';
  else
    Result := Format('0x%.4X', [ACode]);
  end;
end;

end.
