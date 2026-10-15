{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlsLibTestCertificates;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  SysUtils,
  Classes,
  TlpDataEncoding,
  TlpCryptoDomainTypes,
  TlpICryptoProvider,
  TlpIPkixProvider,
  TlpITrustAnchorStore,
  TlpTrustAnchorStore,
  TlsLibTestResourceLoader;

type
  /// <summary>The certificate vectors the suites share, read from the vector files.</summary>
  TTlsLibTestCertificates = class sealed(TObject)
  public
    /// <summary>The named hex field of a vector file, decoded.</summary>
    class function Field(const AFile, AName: string): TBytes; static;
    /// <summary>A store holding the EcP256Chain self-signed root, for config-only tests that need
    /// a real trust source present but never verify a chain.</summary>
    class function EcP256RootStore: ITrustAnchorStore; static;
    /// <summary>The SHA-256 of ACert's SubjectPublicKeyInfo, as a key pin.</summary>
    class function SpkiSha256(const ACrypto: ICryptoProvider; const APkix: IPkixProvider;
      const ACert: TBytes): TBytes; static;
  end;

implementation

class function TTlsLibTestCertificates.Field(const AFile, AName: string): TBytes;
var
  LFields: TStringList;
begin
  LFields := TStringList.Create;
  try
    LFields.LoadFromFile(TTlsLibTestResourceLoader.ResourcePath(AFile));
    // vector files may space-separate bytes; strip whitespace, then decode strictly
    Result := TDataEncoding.HexDecode(StringReplace(LFields.Values[AName], ' ', '',
      [rfReplaceAll]));
  finally
    LFields.Free;
  end;
end;

class function TTlsLibTestCertificates.EcP256RootStore: ITrustAnchorStore;
begin
  Result := TTrustAnchorStore.Create(TArray<TBytes>.Create(
    Field('Certs/EcP256Chain.txt', 'root_cert'))) as ITrustAnchorStore;
end;

class function TTlsLibTestCertificates.SpkiSha256(const ACrypto: ICryptoProvider;
  const APkix: IPkixProvider; const ACert: TBytes): TBytes;
var
  LHash: IHash;
  LSpki: TBytes;
begin
  LSpki := APkix.Certificates.PublicKeyInfo(ACert);
  LHash := ACrypto.Primitives.CreateHash(THashAlgorithm.SHA_256);
  LHash.Update(LSpki, 0, System.Length(LSpki));
  Result := LHash.DoFinal;
end;

end.
