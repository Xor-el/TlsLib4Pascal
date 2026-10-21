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
    /// <summary>ASpki, a 2048-bit-style rsaEncryption SubjectPublicKeyInfo, with the NULL
    /// parameters of its AlgorithmIdentifier dropped: a different encoding of the same key.</summary>
    class function RsaSpkiWithoutNullParameters(const ASpki: TBytes): TBytes; static;
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

class function TTlsLibTestCertificates.RsaSpkiWithoutNullParameters(const ASpki: TBytes): TBytes;
const
  RsaEncryptionOid: array [0 .. 10] of Byte = ($06, $09, $2A, $86, $48, $86, $F7, $0D, $01,
    $01, $01);
  OidLength = 11;
var
  LOidAt, LLength: Int32;
begin
  // header: SEQUENCE (two-byte length form), then AlgorithmIdentifier SEQUENCE, then the OID
  LOidAt := 6;
  if (System.Length(ASpki) < LOidAt + OidLength + 2) or (ASpki[1] <> $82) or
    not CompareMem(@ASpki[LOidAt], @RsaEncryptionOid[0], OidLength) or
    (ASpki[LOidAt + OidLength] <> $05) or (ASpki[LOidAt + OidLength + 1] <> $00) then
    raise Exception.Create('not an rsaEncryption SubjectPublicKeyInfo with NULL parameters');
  Result := System.Copy(ASpki, 0, System.Length(ASpki) - 2);
  System.Move(ASpki[LOidAt + OidLength + 2], Result[LOidAt + OidLength],
    System.Length(ASpki) - LOidAt - OidLength - 2);
  // the AlgorithmIdentifier and the outer SEQUENCE each shrink by the two dropped bytes
  Result[LOidAt - 1] := Byte(Result[LOidAt - 1] - 2);
  LLength := ((Int32(Result[2]) shl 8) or Int32(Result[3])) - 2;
  Result[2] := Byte(LLength shr 8);
  Result[3] := Byte(LLength);
end;

end.
