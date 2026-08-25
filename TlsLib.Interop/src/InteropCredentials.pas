{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit InteropCredentials;

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

interface

uses
  SysUtils,
  Classes,
  TlpCryptoAlgorithms,
  TlpICryptoProvider,
  TlpICertificateTrust,
  TlpCertificateVerifier,
  TlpTlsCredential,
  InteropUtils;

type
  /// <summary>
  /// Loads server credentials (leaf chain + signing key) and client trust anchors for
  /// the interop harness, from either the hex field-file vectors under Data/ or the
  /// PEM files handed over by the BoGo runner (-cert-file / -key-file). Every format
  /// is loaded through the library's own credential seam (ImportSigningKey /
  /// LoadCertificateChain): the key reports the schemes it can sign with, so the shim
  /// carries no key parsing of its own.
  /// </summary>
  TInteropCredentials = class sealed(TObject)
  public
    /// <summary>A server credential from an in-memory leaf DER + private key DER.</summary>
    class function ServerCredential(const AProvider: ICryptoProvider;
      const ALeafCertDer, AKeyDer: TBytes): TTlsCredential; static;
    /// <summary>A server credential from a KEY=hex field-file (leaf_cert + leaf_key).</summary>
    class function ServerCredentialFromFieldFile(const AProvider: ICryptoProvider;
      const AFile: string): TTlsCredential; static;
    /// <summary>A stapling server credential from a KEY=hex field-file: the chain carries
    /// leaf_cert then issuer_cert (so a peer can authenticate the stapled OCSP response
    /// against the issuer) and the key is leaf_key.</summary>
    class function ServerStaplingCredentialFromFieldFile(
      const AProvider: ICryptoProvider; const AFile: string): TTlsCredential; static;
    /// <summary>A server credential from a PEM certificate file + PEM key file.</summary>
    class function ServerCredentialFromPem(const AProvider: ICryptoProvider;
      const ACertFile, AKeyFile: string): TTlsCredential; static;
    /// <summary>A trust store over one root DER certificate.</summary>
    class function Trust(const AProvider: ICryptoProvider;
      const ARootDer: TBytes): ITrustAnchorStore; static;
    /// <summary>A trust store from a KEY=hex field-file (root_cert).</summary>
    class function TrustFromFieldFile(const AProvider: ICryptoProvider;
      const AFile: string): ITrustAnchorStore; static;
    /// <summary>A trust store from a PEM CA-certificate file.</summary>
    class function TrustFromPem(const AProvider: ICryptoProvider;
      const ACaFile: string): ITrustAnchorStore; static;
    /// <summary>Maps BoGo -signing-prefs codepoints to the signature schemes we know,
    /// in order; unknown codepoints (e.g. rsa_pkcs1_*, ML-DSA) are dropped.</summary>
    class function SchemesFromCodes(const ACodes: TArray<UInt16>)
      : TArray<TSignatureScheme>; static;
  end;

implementation

{ TInteropCredentials }

class function TInteropCredentials.ServerCredential(const AProvider: ICryptoProvider;
  const ALeafCertDer, AKeyDer: TBytes): TTlsCredential;
begin
  Result.CertificateChain := AProvider.Certificates.LoadChain(ALeafCertDer);
  Result.PrivateKey := AProvider.Signing.ImportSigningKey(AKeyDer);
end;

class function TInteropCredentials.ServerCredentialFromFieldFile(
  const AProvider: ICryptoProvider; const AFile: string): TTlsCredential;
var
  LFields: TStringList;
begin
  LFields := TStringList.Create;
  try
    TInteropUtils.LoadFieldFile(AFile, LFields);
    Result := ServerCredential(AProvider,
      TInteropUtils.DecodeHex(LFields.Values['leaf_cert']),
      TInteropUtils.DecodeHex(LFields.Values['leaf_key']));
  finally
    LFields.Free;
  end;
end;

class function TInteropCredentials.ServerStaplingCredentialFromFieldFile(
  const AProvider: ICryptoProvider; const AFile: string): TTlsCredential;
var
  LFields: TStringList;
begin
  LFields := TStringList.Create;
  try
    TInteropUtils.LoadFieldFile(AFile, LFields);
    Result.CertificateChain := TArray<TBytes>.Create(
      TInteropUtils.DecodeHex(LFields.Values['leaf_cert']),
      TInteropUtils.DecodeHex(LFields.Values['issuer_cert']));
    Result.PrivateKey := AProvider.Signing.ImportSigningKey(
      TInteropUtils.DecodeHex(LFields.Values['leaf_key']));
  finally
    LFields.Free;
  end;
end;

class function TInteropCredentials.ServerCredentialFromPem(
  const AProvider: ICryptoProvider;
  const ACertFile, AKeyFile: string): TTlsCredential;
begin
  // the loaders accept PEM directly; a PEM cert file may carry the whole chain
  Result.CertificateChain := AProvider.Certificates.LoadChain(
    TEncoding.ASCII.GetBytes(TInteropUtils.ReadAllText(ACertFile)));
  Result.PrivateKey := AProvider.Signing.ImportSigningKey(
    TEncoding.ASCII.GetBytes(TInteropUtils.ReadAllText(AKeyFile)));
end;

class function TInteropCredentials.Trust(const AProvider: ICryptoProvider;
  const ARootDer: TBytes): ITrustAnchorStore;
begin
  Result := TTrustAnchorStore.Create(AProvider.Certificates.LoadChain(ARootDer))
    as ITrustAnchorStore;
end;

class function TInteropCredentials.TrustFromFieldFile(
  const AProvider: ICryptoProvider; const AFile: string): ITrustAnchorStore;
var
  LFields: TStringList;
begin
  LFields := TStringList.Create;
  try
    TInteropUtils.LoadFieldFile(AFile, LFields);
    Result := Trust(AProvider, TInteropUtils.DecodeHex(LFields.Values['root_cert']));
  finally
    LFields.Free;
  end;
end;

class function TInteropCredentials.TrustFromPem(const AProvider: ICryptoProvider;
  const ACaFile: string): ITrustAnchorStore;
begin
  Result := Trust(AProvider, TEncoding.ASCII.GetBytes(TInteropUtils.ReadAllText(ACaFile)));
end;

class function TInteropCredentials.SchemesFromCodes(
  const ACodes: TArray<UInt16>): TArray<TSignatureScheme>;
var
  LCode: UInt16;
  LScheme: TSignatureScheme;
  LN: Int32;
begin
  Result := nil;
  for LCode in ACodes do
    if TSignatureScheme.TryFromCode(LCode, LScheme) then
    begin
      LN := System.Length(Result);
      SetLength(Result, LN + 1);
      Result[LN] := LScheme;
    end;
end;

end.
