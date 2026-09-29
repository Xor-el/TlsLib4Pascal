{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpEchConfirmation;

{$I ..\Include\TlsLib.inc}

interface

uses
  SysUtils,
  TlpICryptoProvider,
  TlpISecretBuffer,
  TlpSecretBuffer,
  TlpHkdfLabel,
  TlpEchExtension;

type
  /// <summary>
  /// The ECH accept-confirmation derivations (RFC 9849 sec. 7.2). Class functions because on the
  /// server the key schedule does not yet exist when the ServerHello/HelloRetryRequest is built;
  /// AHkdf carries the negotiated suite's hash.
  /// </summary>
  TEchConfirmation = class sealed(TObject)
  strict private
    class function Compute(const AHkdf: IHkdf; const ALabel: string;
      const AInnerRandom, ATranscriptHash: TBytes): TBytes; static;
  public
    /// <summary>
    /// The ECH ServerHello accept confirmation: the 8 bytes the backend writes over
    /// ServerHello.random[24..32] and the client recomputes. AInnerRandom is
    /// ClientHelloInner.random; ATranscriptEchConf is
    /// Transcript-Hash(ClientHelloInner...ServerHello) with those 8 random bytes zeroed.
    /// </summary>
    class function Accept(const AHkdf: IHkdf;
      const AInnerRandom, ATranscriptEchConf: TBytes): TBytes; static;
    /// <summary>
    /// The ECH HelloRetryRequest accept confirmation (sec. 7.2.1): the 8 bytes written over the
    /// HRR encrypted_client_hello payload. AInnerRandom is ClientHelloInner1.random;
    /// ATranscriptHrrEchConf is Transcript-Hash(message_hash(ClientHelloInner1)...HelloRetryRequest)
    /// with the HRR ech payload zeroed.
    /// </summary>
    class function HrrAccept(const AHkdf: IHkdf;
      const AInnerRandom, ATranscriptHrrEchConf: TBytes): TBytes; static;
  end;

implementation

{ TEchConfirmation }

class function TEchConfirmation.Compute(const AHkdf: IHkdf; const ALabel: string;
  const AInnerRandom, ATranscriptHash: TBytes): TBytes;
var
  LPrk: ISecretBuffer;
begin
  // HKDF-Extract(0, ClientHelloInner.random): a HashLen-zero salt over the inner
  // random as IKM (the random is public; the seam types IKM as a secret)
  LPrk := AHkdf.Extract(nil, TSecretBuffer.From(AInnerRandom));
  Result := THkdfLabel.HkdfExpandLabel(AHkdf, LPrk, ALabel, ATranscriptHash,
    TEchExtension.ConfirmationLength).ToBytes;
end;

class function TEchConfirmation.Accept(const AHkdf: IHkdf;
  const AInnerRandom, ATranscriptEchConf: TBytes): TBytes;
begin
  Result := Compute(AHkdf, 'ech accept confirmation', AInnerRandom, ATranscriptEchConf);
end;

class function TEchConfirmation.HrrAccept(const AHkdf: IHkdf;
  const AInnerRandom, ATranscriptHrrEchConf: TBytes): TBytes;
begin
  Result := Compute(AHkdf, 'hrr ech accept confirmation', AInnerRandom, ATranscriptHrrEchConf);
end;

end.
