{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpCipherSuiteCatalog;

{$I ..\Include\TlsLib.inc}

interface

uses
  SysUtils,
  TlpCryptoDomainTypes,
  TlpNegotiationTypes;

type
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

end.
