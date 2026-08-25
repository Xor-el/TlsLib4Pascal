{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpCipherSuiteRegistry;

{$I ..\Include\TlsLib.inc}

interface

uses
  SysUtils,
  TlpCodeKeyedRegistry,
  TlpCryptoAlgorithms,
  TlpICryptoProvider,
  TlpNegotiationTypes,
  TlpINegotiation;

type
  /// <summary>The default cipher-suite registry: an ordered, prunable suite list.</summary>
  TCipherSuiteRegistry = class sealed(TCodeKeyedRegistry<TTlsCipherSuite>,
    ICipherSuiteRegistry)
  strict private
    class function CodeOf(const ASuite: TTlsCipherSuite): UInt16; static;
    /// <summary>Whether the provider can build both the suite's AEAD and hash, so an
    /// entry is offered only when runnable (or flagged mandatory-to-implement).</summary>
    class function SuiteRunnable(const AProvider: ICryptoProvider;
      AAead: TAeadAlgorithm; AHash: THashAlgorithm): Boolean; static;
  public
    constructor Create;

    /// <summary>
    /// The TLS 1.3 suites the provider can actually run, in preference order.
    /// TLS_AES_128_GCM_SHA256 is mandatory-to-implement and always kept.
    /// </summary>
    class function CreateDefault(const AProvider: ICryptoProvider)
      : ICipherSuiteRegistry; static;

    /// <summary>
    /// The hardened dual-version set: the TLS 1.3 suites followed by the hardened
    /// TLS 1.2 suites (ECDHE-ECDSA/RSA over AES-GCM and ChaCha20-Poly1305). One
    /// registry holds both; selection is branched on the negotiated version.
    /// </summary>
    class function CreateDualVersion(const AProvider: ICryptoProvider)
      : ICipherSuiteRegistry; static;
  end;

implementation

constructor TCipherSuiteRegistry.Create;
begin
  inherited Create(CodeOf);
end;

class function TCipherSuiteRegistry.CodeOf(const ASuite: TTlsCipherSuite): UInt16;
begin
  Result := ASuite.Common.Code;
end;

class function TCipherSuiteRegistry.SuiteRunnable(const AProvider: ICryptoProvider;
  AAead: TAeadAlgorithm; AHash: THashAlgorithm): Boolean;
begin
  Result := True;
  try
    AProvider.Primitives.CreateAead(AAead);
    AProvider.Primitives.CreateHash(AHash);
  except
    on E: Exception do
      Result := False;
  end;
end;

class function TCipherSuiteRegistry.CreateDefault(const AProvider: ICryptoProvider)
  : ICipherSuiteRegistry;
var
  LRegistry: ICipherSuiteRegistry;

  procedure Consider(ACode: UInt16; AAead: TAeadAlgorithm; AHash: THashAlgorithm;
    AKeyLength: Int32; AAlwaysKeep: Boolean);
  var
    LSuite: TTlsCipherSuite;
  begin
    if not (AAlwaysKeep or SuiteRunnable(AProvider, AAead, AHash)) then
      Exit;
    LSuite.Common.Code := ACode;
    LSuite.Common.Aead := AAead;
    LSuite.Common.Hash := AHash;
    LSuite.Common.KeyLength := AKeyLength;
    LSuite.Protocol := TSuiteProtocol.Tls13;
    LSuite.KeyExchange := TKeyExchangeMethod.Decoupled;
    LSuite.Auth := TAuthMethod.Decoupled;
    LSuite.Prf := AHash;
    LRegistry.Add(LSuite);
  end;

begin
  LRegistry := TCipherSuiteRegistry.Create;
  Consider(TCipherSuites13.Aes128GcmSha256, TAeadAlgorithm.AES_128_GCM,
    THashAlgorithm.SHA_256, 16, True);
  Consider(TCipherSuites13.Aes256GcmSha384, TAeadAlgorithm.AES_256_GCM,
    THashAlgorithm.SHA_384, 32, False);
  Consider(TCipherSuites13.ChaCha20Poly1305Sha256, TAeadAlgorithm.CHACHA20_POLY1305,
    THashAlgorithm.SHA_256, 32, False);
  Result := LRegistry;
end;

class function TCipherSuiteRegistry.CreateDualVersion(
  const AProvider: ICryptoProvider): ICipherSuiteRegistry;
var
  LRegistry: ICipherSuiteRegistry;

  procedure Consider12(ACode: UInt16; AKeyExchange: TKeyExchangeMethod;
    AAuth: TAuthMethod; AAead: TAeadAlgorithm; AHash: THashAlgorithm;
    AKeyLength: Int32);
  var
    LSuite: TTlsCipherSuite;
  begin
    if not SuiteRunnable(AProvider, AAead, AHash) then
      Exit;
    LSuite.Common.Code := ACode;
    LSuite.Common.Aead := AAead;
    LSuite.Common.Hash := AHash;
    LSuite.Common.KeyLength := AKeyLength;
    LSuite.Protocol := TSuiteProtocol.Tls12;
    LSuite.KeyExchange := AKeyExchange;
    LSuite.Auth := AAuth;
    LSuite.Prf := AHash;
    LRegistry.Add(LSuite);
  end;

begin
  LRegistry := CreateDefault(AProvider);
  // hardened TLS 1.2 suites: ECDHE key exchange, ECDSA/RSA auth, AEAD only
  Consider12(TCipherSuites12.EcdheEcdsaAes128GcmSha256, TKeyExchangeMethod.Ecdhe,
    TAuthMethod.Ecdsa, TAeadAlgorithm.AES_128_GCM, THashAlgorithm.SHA_256, 16);
  Consider12(TCipherSuites12.EcdheEcdsaAes256GcmSha384, TKeyExchangeMethod.Ecdhe,
    TAuthMethod.Ecdsa, TAeadAlgorithm.AES_256_GCM, THashAlgorithm.SHA_384, 32);
  Consider12(TCipherSuites12.EcdheEcdsaChaCha20Poly1305Sha256,
    TKeyExchangeMethod.Ecdhe, TAuthMethod.Ecdsa, TAeadAlgorithm.CHACHA20_POLY1305,
    THashAlgorithm.SHA_256, 32);
  Consider12(TCipherSuites12.EcdheRsaAes128GcmSha256, TKeyExchangeMethod.Ecdhe,
    TAuthMethod.Rsa, TAeadAlgorithm.AES_128_GCM, THashAlgorithm.SHA_256, 16);
  Consider12(TCipherSuites12.EcdheRsaAes256GcmSha384, TKeyExchangeMethod.Ecdhe,
    TAuthMethod.Rsa, TAeadAlgorithm.AES_256_GCM, THashAlgorithm.SHA_384, 32);
  Consider12(TCipherSuites12.EcdheRsaChaCha20Poly1305Sha256,
    TKeyExchangeMethod.Ecdhe, TAuthMethod.Rsa, TAeadAlgorithm.CHACHA20_POLY1305,
    THashAlgorithm.SHA_256, 32);
  Result := LRegistry;
end;

end.
