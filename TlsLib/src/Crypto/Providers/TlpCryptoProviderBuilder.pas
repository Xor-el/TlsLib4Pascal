{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpCryptoProviderBuilder;

{$I ..\..\Include\TlsLib.inc}

interface

uses
  TlpICryptoProvider,
  TlpDefaultCryptoProvider;

type
  /// <summary>
  /// The fluent <see cref="ICryptoProviderBuilder" />: accumulates facet overrides
  /// and composes through <see cref="TDefaultCryptoProvider.Create" />.
  /// </summary>
  TCryptoProviderBuilder = class(TInterfacedObject, ICryptoProviderBuilder)
  strict private
  var
    FRandom: IRandom;
    FPrimitives: ICryptoPrimitives;
    FSigning: ISigningCrypto;
    FHpke: IHpkeCrypto;
  public
    function WithRandom(const ARandom: IRandom): ICryptoProviderBuilder;
    function WithPrimitives(const APrimitives: ICryptoPrimitives): ICryptoProviderBuilder;
    function WithSigning(const ASigning: ISigningCrypto): ICryptoProviderBuilder;
    function WithHpke(const AHpke: IHpkeCrypto): ICryptoProviderBuilder;
    function Build: ICryptoProvider;
  end;

implementation

{ TCryptoProviderBuilder }

function TCryptoProviderBuilder.WithRandom(
  const ARandom: IRandom): ICryptoProviderBuilder;
begin
  FRandom := ARandom;
  Result := Self;
end;

function TCryptoProviderBuilder.WithPrimitives(
  const APrimitives: ICryptoPrimitives): ICryptoProviderBuilder;
begin
  FPrimitives := APrimitives;
  Result := Self;
end;

function TCryptoProviderBuilder.WithSigning(
  const ASigning: ISigningCrypto): ICryptoProviderBuilder;
begin
  FSigning := ASigning;
  Result := Self;
end;

function TCryptoProviderBuilder.WithHpke(
  const AHpke: IHpkeCrypto): ICryptoProviderBuilder;
begin
  FHpke := AHpke;
  Result := Self;
end;

function TCryptoProviderBuilder.Build: ICryptoProvider;
begin
  Result := TDefaultCryptoProvider.Create(FRandom, FPrimitives, FSigning, FHpke) as ICryptoProvider;
end;

end.
