{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpPkcs12Identity;

{$I ..\Include\TlsLib.inc}

interface

uses
  SysUtils,
  TlpISigningKey,
  TlpImportedCredential,
  TlpArrayUtilities,
  TlpTlsLibExceptions;

type
  /// <summary>One certificate of an unwrapped PKCS#12 store: its DER and the raw DER of its
  /// Subject and Issuer names.</summary>
  TPkcs12Certificate = record
    Der: TBytes;
    Subject: TBytes;
    Issuer: TBytes;
  end;

  /// <summary>One private key of an unwrapped PKCS#12 store. Linked is the index of the
  /// certificate the store links to the key (-1: none); Pairs lists the certificates whose public
  /// key pairs the key, as the backend that unwrapped the store compares them.</summary>
  TPkcs12Key = record
    Key: ISigningKey;
    Linked: Int32;
    Pairs: TArray<Int32>;
  end;

  /// <summary>The public view of an unwrapped PKCS#12 store, as a backend extracts it.</summary>
  TPkcs12Contents = record
    Certificates: TArray<TPkcs12Certificate>;
    Keys: TArray<TPkcs12Key>;
  end;

  /// <summary>The one PKCS#12 credential policy, shared by every backend: exactly one private key,
  /// the leaf is the certificate that pairs it, and the chain follows the issuer names.</summary>
  TPkcs12Identity = class sealed(TObject)
  strict private
    class function IndexOfLowestDer(const AContents: TPkcs12Contents;
      const AIndexes: TArray<Int32>): Int32; static;
  public
    /// <summary>The credential AContents holds. Raises EArgumentTlsLibException when the store
    /// has no private key, more than one, or no certificate that pairs its key. The leaf is the
    /// linked certificate when it pairs the key, else the pairing certificate with the lowest DER
    /// byte order. The chain is the leaf followed by the certificate whose Subject equals the
    /// current Issuer byte for byte (the lowest DER on a tie), ending at a self-issued
    /// certificate, when nothing matches, or when a certificate would repeat; certificates off
    /// that walk are dropped.</summary>
    class function Select(const AContents: TPkcs12Contents): TImportedCredential; static;
  end;

implementation

resourcestring
  SPkcs12NoKeyEntry = 'the PKCS#12 blob holds no private-key entry';
  SPkcs12MultipleKeys =
    'the PKCS#12 blob holds more than one private-key entry; it is ambiguous for a ' +
    'single credential — split it or import the intended identity explicitly';
  SPkcs12NoCertForKey =
    'the PKCS#12 blob holds no certificate for its private key';

{ TPkcs12Identity }

class function TPkcs12Identity.IndexOfLowestDer(const AContents: TPkcs12Contents;
  const AIndexes: TArray<Int32>): Int32;
var
  LI: Int32;
begin
  Result := -1;
  for LI := 0 to System.Length(AIndexes) - 1 do
    if (Result < 0) or (TArrayUtilities.CompareLexicographic(
      AContents.Certificates[AIndexes[LI]].Der, AContents.Certificates[Result].Der) < 0) then
      Result := AIndexes[LI];
end;

class function TPkcs12Identity.Select(const AContents: TPkcs12Contents): TImportedCredential;
var
  LKey: TPkcs12Key;
  LLeaf, LNext, LI, LJ: Int32;
  LIssuers, LChain: TArray<Int32>;
  LSeen: Boolean;
begin
  if System.Length(AContents.Keys) = 0 then
    raise EArgumentTlsLibException.CreateRes(@SPkcs12NoKeyEntry);
  if System.Length(AContents.Keys) > 1 then
    raise EArgumentTlsLibException.CreateRes(@SPkcs12MultipleKeys);
  LKey := AContents.Keys[0];
  if System.Length(LKey.Pairs) = 0 then
    raise EArgumentTlsLibException.CreateRes(@SPkcs12NoCertForKey);

  if TArrayUtilities.Contains<Int32>(LKey.Pairs, LKey.Linked) then
    LLeaf := LKey.Linked
  else
    LLeaf := IndexOfLowestDer(AContents, LKey.Pairs);

  LChain := TArray<Int32>.Create(LLeaf);
  LNext := LLeaf;
  repeat
    if TArrayUtilities.AreEqual(AContents.Certificates[LNext].Subject,
      AContents.Certificates[LNext].Issuer) then
      Break;
    LIssuers := nil;
    for LI := 0 to System.Length(AContents.Certificates) - 1 do
      if TArrayUtilities.AreEqual(AContents.Certificates[LI].Subject,
        AContents.Certificates[LNext].Issuer) then
        TArrayUtilities.Append<Int32>(LIssuers, LI);
    if System.Length(LIssuers) = 0 then
      Break;
    LNext := IndexOfLowestDer(AContents, LIssuers);
    LSeen := False;
    for LJ := 0 to System.Length(LChain) - 1 do
      if TArrayUtilities.AreEqual(AContents.Certificates[LChain[LJ]].Der,
        AContents.Certificates[LNext].Der) then
        LSeen := True;
    if LSeen then
      Break;
    TArrayUtilities.Append<Int32>(LChain, LNext);
  until False;

  Result.PrivateKey := LKey.Key;
  SetLength(Result.CertificateChain, System.Length(LChain));
  for LI := 0 to System.Length(LChain) - 1 do
    Result.CertificateChain[LI] := AContents.Certificates[LChain[LI]].Der;
end;

end.
