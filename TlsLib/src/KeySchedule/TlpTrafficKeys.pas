{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpTrafficKeys;

{$I ..\Include\TlsLib.inc}

interface

uses
  TlpISecretBuffer,
  TlpICryptoProvider,
  TlpIKeySchedule,
  TlpHkdfLabel;

type
  /// <summary>The (key, iv) a schedule derived for one epoch and direction.</summary>
  TTrafficKeys = class sealed(TInterfacedObject, ITrafficKeys)
  strict private
  var
    FKey: ISecretBuffer;
    FIv: ISecretBuffer;
  public
    constructor Create(const AKey, AIv: ISecretBuffer);
    /// <summary>The TLS 1.3 key and iv of a traffic secret (RFC 9846 7.3): the one derivation every
    /// installer and the schedule share.</summary>
    class function FromSecret(const AHkdf: IHkdf; const ASecret: ISecretBuffer;
      AKeyLength: Int32): ITrafficKeys; static;
    function Key: ISecretBuffer;
    function Iv: ISecretBuffer;
  end;

implementation

const
  Tls13IvLength = Int32(12);

{ TTrafficKeys }

class function TTrafficKeys.FromSecret(const AHkdf: IHkdf; const ASecret: ISecretBuffer;
  AKeyLength: Int32): ITrafficKeys;
begin
  Result := TTrafficKeys.Create(
    THkdfLabel.HkdfExpandLabel(AHkdf, ASecret, 'key', nil, AKeyLength),
    THkdfLabel.HkdfExpandLabel(AHkdf, ASecret, 'iv', nil, Tls13IvLength));
end;

constructor TTrafficKeys.Create(const AKey, AIv: ISecretBuffer);
begin
  inherited Create;
  FKey := AKey;
  FIv := AIv;
end;

function TTrafficKeys.Key: ISecretBuffer;
begin
  Result := FKey;
end;

function TTrafficKeys.Iv: ISecretBuffer;
begin
  Result := FIv;
end;

end.
