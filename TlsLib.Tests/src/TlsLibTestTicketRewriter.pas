{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlsLibTestTicketRewriter;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  SysUtils,
  TlpArrayUtilities,
  TlpCryptoDomainTypes,
  TlpICryptoProvider,
  TlpISecretBuffer,
  TlpAeadUtilities,
  TlpISession;

type
  /// <summary>
  /// Opens and re-seals a stateless ticket under its own key, so a test can rewrite a ticket's
  /// plaintext (an older format, an altered field) and present it as the server's.
  /// </summary>
  TTlsLibTestTicketRewriter = class sealed(TObject)
  public
    /// <summary>The plaintext of ATicket, which AKeys sealed.</summary>
    class function Plaintext(const ACrypto: ICryptoProvider;
      const AKeys: ISessionTicketKeyManager; const ATicket: TBytes): TBytes; static;
    /// <summary>A ticket carrying APlain under the key ATicket names, with a fresh nonce.</summary>
    class function Resealed(const ACrypto: ICryptoProvider;
      const AKeys: ISessionTicketKeyManager; const ATicket, APlain: TBytes): TBytes; static;
  end;

implementation

const
  TicketNonceLength = Int32(12);

{ TTlsLibTestTicketRewriter }

class function TTlsLibTestTicketRewriter.Plaintext(const ACrypto: ICryptoProvider;
  const AKeys: ISessionTicketKeyManager; const ATicket: TBytes): TBytes;
var
  LKeyName, LNonce: TBytes;
  LKey: ISecretBuffer;
  LAead: IAead;
  LNameLen: Int32;
begin
  LNameLen := AKeys.KeyNameLength;
  LKeyName := System.Copy(ATicket, 0, LNameLen);
  LNonce := System.Copy(ATicket, LNameLen, TicketNonceLength);
  if not AKeys.KeyByName(LKeyName, LKey) then
    raise Exception.Create('the ticket key is not held');
  LAead := ACrypto.Primitives.CreateAead(TAeadAlgorithm.AES_256_GCM);
  LAead.Init(LKey);
  Result := TAeadUtilities.Open(LAead, LNonce, LKeyName,
    System.Copy(ATicket, LNameLen + TicketNonceLength,
    System.Length(ATicket) - LNameLen - TicketNonceLength));
end;

class function TTlsLibTestTicketRewriter.Resealed(const ACrypto: ICryptoProvider;
  const AKeys: ISessionTicketKeyManager; const ATicket, APlain: TBytes): TBytes;
var
  LKeyName, LNonce, LCipher: TBytes;
  LKey: ISecretBuffer;
  LAead: IAead;
begin
  LKeyName := System.Copy(ATicket, 0, AKeys.KeyNameLength);
  if not AKeys.KeyByName(LKeyName, LKey) then
    raise Exception.Create('the ticket key is not held');
  LNonce := ACrypto.Primitives.GetRandom.GenerateBytes(TicketNonceLength);
  LAead := ACrypto.Primitives.CreateAead(TAeadAlgorithm.AES_256_GCM);
  LAead.Init(LKey);
  LCipher := TAeadUtilities.Seal(LAead, LNonce, LKeyName, APlain);
  Result := TArrayUtilities.Concat<Byte>(TArrayUtilities.Concat<Byte>(LKeyName, LNonce),
    LCipher);
end;

end.
