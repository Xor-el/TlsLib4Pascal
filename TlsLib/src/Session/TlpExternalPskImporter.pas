{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpExternalPskImporter;

{$I ..\Include\TlsLib.inc}

interface

uses
  SysUtils,
  TlpCryptoAlgorithms,
  TlpISecretBuffer,
  TlpICryptoProvider,
  TlpHkdfLabel,
  TlpIWireWriter,
  TlpWireWriter,
  TlpWireVectorMarker,
  TlpISession,
  TlpSession;

type
  /// <summary>
  /// The external-PSK importer (RFC 9258): turns an out-of-band pre-shared key and its
  /// identity/context into the wire pre_shared_key identity and derived key, bound to a
  /// target KDF hash and target protocol. A single external PSK yields one imported PSK
  /// per target hash; the resulting <see cref="IPreSharedKey" /> carries the imported
  /// identity (5.1), the derived key (ipskx, 4.1) and the target hash, and uses the
  /// "imp binder" label. The derivation is keyed on the PSK's provisioned hash while the
  /// target hash sets only the imported KDF id, the output length and the bound hash,
  /// so a single provisioned key imports for every supported KDF.
  /// </summary>
  TExternalPskImporter = class sealed(TObject)
  strict private
    /// <summary>The RFC 8446 / IANA KDF id for a hash: HKDF-SHA256 = 1, HKDF-SHA384 = 2.</summary>
    class function KdfId(AHash: THashAlgorithm): UInt16; static;
  public
    /// <summary>The serialized ImportedIdentity (RFC 9258 5.1): the external identity and
    /// context as uint16-length-prefixed opaques, then the target protocol and KDF id.</summary>
    class function ImportedIdentity(const AExternalIdentity, AContext: TBytes;
      ATargetProtocol, ATargetKdf: UInt16): TBytes; static;
    /// <summary>Imports ASpec for ATargetProtocol and ATargetHash into a wire PSK.</summary>
    class function Import(const AProvider: ICryptoProvider; const ASpec: TExternalPsk;
      ATargetProtocol: UInt16; ATargetHash: THashAlgorithm): IPreSharedKey; static;
  end;

implementation

const
  KdfHkdfSha256 = UInt16($0001);
  KdfHkdfSha384 = UInt16($0002);
  KdfHkdfSha512 = UInt16($0003);
  DerivedPskLabel = 'derived psk';

{ TExternalPskImporter }

class function TExternalPskImporter.KdfId(AHash: THashAlgorithm): UInt16;
begin
  case AHash of
    THashAlgorithm.SHA_384:
      Result := KdfHkdfSha384;
    THashAlgorithm.SHA_512:
      Result := KdfHkdfSha512;
  else
    Result := KdfHkdfSha256;
  end;
end;

class function TExternalPskImporter.ImportedIdentity(const AExternalIdentity,
  AContext: TBytes; ATargetProtocol, ATargetKdf: UInt16): TBytes;
var
  LWriter: IWireWriter;
  LMarker: TWireVectorMarker;
begin
  LWriter := TWireWriter.Create;
  LMarker := LWriter.OpenVector(2); // external_identity<1..2^16-1>
  LWriter.WriteBytes(AExternalIdentity);
  LWriter.CloseVector(LMarker);
  LMarker := LWriter.OpenVector(2); // context<0..2^16-1>
  LWriter.WriteBytes(AContext);
  LWriter.CloseVector(LMarker);
  LWriter.WriteUInt16(ATargetProtocol);
  LWriter.WriteUInt16(ATargetKdf);
  Result := LWriter.ToBytes;
end;

class function TExternalPskImporter.Import(const AProvider: ICryptoProvider;
  const ASpec: TExternalPsk; ATargetProtocol: UInt16;
  ATargetHash: THashAlgorithm): IPreSharedKey;
var
  LIdentity, LIdentityHash: TBytes;
  LHash: IHash;
  LHkdf: IHkdf;
  LEpsk, LIpsk: ISecretBuffer;
  LOutLen: Int32;
begin
  // RFC 9258 5.1: the imported identity binds the external identity, context, target
  // protocol and target KDF, so the same secret under a different context/KDF/protocol
  // yields a distinct wire identity that will not match.
  LIdentity := ImportedIdentity(ASpec.Identity, ASpec.Context, ATargetProtocol,
    KdfId(ATargetHash));

  // the derivation is keyed on the provisioned hash (ASpec.Hash); only the output length
  // follows the target hash (RFC 9258 4.1)
  LHash := AProvider.Primitives.CreateHash(ASpec.Hash);
  LHash.Update(LIdentity, 0, System.Length(LIdentity));
  LIdentityHash := LHash.DoFinal;

  LHkdf := AProvider.Primitives.CreateHkdf(ASpec.Hash);
  // epskx = HKDF-Extract(0, epsk): an empty salt is HashLen zeros
  LEpsk := LHkdf.Extract(nil, ASpec.Secret);
  LOutLen := AProvider.Primitives.CreateHash(ATargetHash).HashSize;
  // ipskx = HKDF-Expand-Label(epskx, "derived psk", Hash(ImportedIdentity), L)
  LIpsk := THkdfLabel.HkdfExpandLabel(LHkdf, LEpsk, DerivedPskLabel, LIdentityHash,
    LOutLen);

  Result := TPreSharedKey.CreateImported(LIdentity, LIpsk, ATargetHash);
end;

end.
