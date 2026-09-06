{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpSignatureSchemeRegistry;

{$I ..\Include\TlsLib.inc}

interface

uses
  SysUtils,
  TlpCodeKeyedRegistry,
  TlpCryptoDomainTypes,
  TlpINegotiation;

type
  /// <summary>The default signature-scheme registry: an ordered, prunable list.</summary>
  TSignatureSchemeRegistry = class sealed(TCodeKeyedRegistry<TSignatureScheme>,
    ISignatureSchemeRegistry)
  strict private
    class function CodeOf(const AScheme: TSignatureScheme): UInt16; static;
  public
    constructor Create;

    /// <summary>
    /// The default scheme set in preference order (ECDSA, RSA-PSS, EdDSA). Provider
    /// capability is confirmed when the signers are wired (the signer sub-seam), so
    /// the default set is the full modern list here.
    /// </summary>
    class function CreateDefault: ISignatureSchemeRegistry; static;
  end;

implementation

constructor TSignatureSchemeRegistry.Create;
begin
  inherited Create(CodeOf);
end;

class function TSignatureSchemeRegistry.CodeOf(
  const AScheme: TSignatureScheme): UInt16;
begin
  Result := AScheme.ToCode;
end;

class function TSignatureSchemeRegistry.CreateDefault: ISignatureSchemeRegistry;
var
  LRegistry: ISignatureSchemeRegistry;
begin
  LRegistry := TSignatureSchemeRegistry.Create;
  // preference order: ECDSA, then Ed25519, then RSA-PSS, then legacy RSA-PKCS1. PSS is
  // preferred over PKCS1 (and is the only RSA option a 1.3 handshake signature may use);
  // the pkcs1 schemes are advertised for TLS 1.2 handshake signatures and for pkcs1-signed
  // certificate chains, which RFC 8446 4.2.3 permits ("for backward compatibility with
  // TLS 1.2") even in a 1.3 ClientHello.
  LRegistry.Add(TSignatureScheme.ECDSA_SECP256R1_SHA256);
  LRegistry.Add(TSignatureScheme.ECDSA_SECP384R1_SHA384);
  LRegistry.Add(TSignatureScheme.ECDSA_SECP521R1_SHA512);
  LRegistry.Add(TSignatureScheme.ED25519);
  LRegistry.Add(TSignatureScheme.RSA_PSS_RSAE_SHA256);
  LRegistry.Add(TSignatureScheme.RSA_PSS_RSAE_SHA384);
  LRegistry.Add(TSignatureScheme.RSA_PSS_RSAE_SHA512);
  LRegistry.Add(TSignatureScheme.RSA_PKCS1_SHA256);
  LRegistry.Add(TSignatureScheme.RSA_PKCS1_SHA384);
  LRegistry.Add(TSignatureScheme.RSA_PKCS1_SHA512);
  Result := LRegistry;
end;

end.
