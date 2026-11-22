{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpTrafficSecret;

{$I ..\Include\TlsLib.inc}

interface

uses
  TlpCryptoDomainTypes,
  TlpISecretBuffer,
  TlpIKeySchedule;

type
  /// <summary>A TLS 1.3 traffic secret with the suite facts needed to key record protection
  /// from it; owns its buffer, which is wiped once the last holder lets go.</summary>
  TTrafficSecret = class sealed(TInterfacedObject, ITrafficSecret)
  strict private
  var
    FSecret: ISecretBuffer;
    FCipherSuite: UInt16;
    FHash: THashAlgorithm;
    FAead: TAeadAlgorithm;
  public
    constructor Create(const ASecret: ISecretBuffer; ACipherSuite: UInt16;
      AHash: THashAlgorithm; AAead: TAeadAlgorithm);
    function Secret: ISecretBuffer;
    function CipherSuite: UInt16;
    function Hash: THashAlgorithm;
    function Aead: TAeadAlgorithm;
  end;

implementation

{ TTrafficSecret }

constructor TTrafficSecret.Create(const ASecret: ISecretBuffer; ACipherSuite: UInt16;
  AHash: THashAlgorithm; AAead: TAeadAlgorithm);
begin
  inherited Create;
  FSecret := ASecret;
  FCipherSuite := ACipherSuite;
  FHash := AHash;
  FAead := AAead;
end;

function TTrafficSecret.Secret: ISecretBuffer;
begin
  Result := FSecret;
end;

function TTrafficSecret.CipherSuite: UInt16;
begin
  Result := FCipherSuite;
end;

function TTrafficSecret.Hash: THashAlgorithm;
begin
  Result := FHash;
end;

function TTrafficSecret.Aead: TAeadAlgorithm;
begin
  Result := FAead;
end;

end.
