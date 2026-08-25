{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpBundleTrust;

{$I ..\..\TlsLib\src\Include\TlsLib.inc}

interface

uses
  SysUtils,
  Classes,
  TlpICryptoProvider,
  TlpICertificateTrust;

type
  /// <summary>
  /// Builds a trust-anchor store from a PEM CA bundle - a single certificate or a
  /// concatenated bundle - parsed through the crypto provider. The result is an
  /// ordinary anchor source, so it composes (unions) with system trust or another
  /// bundle via the builder. Fail-closed: a bundle that yields no certificate
  /// raises through the provider.
  /// </summary>
  TBundleTrust = class sealed(TObject)
  strict private
    class function ReadAllBytes(const AFileName: string): TBytes; static;
  public
    /// <summary>An anchor store over the certificates in the PEM/DER bundle bytes.</summary>
    class function FromPem(const AProvider: ICryptoProvider;
      const AData: TBytes): ITrustAnchorStore; static;
    /// <summary>As FromPem, reading the bundle from a file.</summary>
    class function FromPemFile(const AProvider: ICryptoProvider;
      const AFileName: string): ITrustAnchorStore; static;
  end;

implementation

uses
  TlpCertificateVerifier;

{ TBundleTrust }

class function TBundleTrust.ReadAllBytes(const AFileName: string): TBytes;
var
  LStream: TMemoryStream;
begin
  Result := nil;
  LStream := TMemoryStream.Create;
  try
    LStream.LoadFromFile(AFileName);
    SetLength(Result, LStream.Size);
    if LStream.Size > 0 then
      Move(LStream.Memory^, Result[0], LStream.Size);
  finally
    LStream.Free;
  end;
end;

class function TBundleTrust.FromPem(const AProvider: ICryptoProvider;
  const AData: TBytes): ITrustAnchorStore;
begin
  Result := TTrustAnchorStore.Create(AProvider.Certificates.LoadChain(AData))
    as ITrustAnchorStore;
end;

class function TBundleTrust.FromPemFile(const AProvider: ICryptoProvider;
  const AFileName: string): ITrustAnchorStore;
begin
  Result := FromPem(AProvider, ReadAllBytes(AFileName));
end;

end.
