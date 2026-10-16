{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpPkixProviderBuilder;

{$I ..\..\Include\TlsLib.inc}

interface

uses
  TlpIPkixProvider,
  TlpDefaultPkixProvider;

type
  /// <summary>
  /// The fluent <see cref="IPkixProviderBuilder" />: accumulates facet overrides
  /// and composes through <see cref="TDefaultPkixProvider.Create" />.
  /// </summary>
  TPkixProviderBuilder = class(TInterfacedObject, IPkixProviderBuilder)
  strict private
  var
    FInspector: ICertificateInspector;
    FPathValidation: ICertificatePathValidator;
    FRevocation: IRevocationChecker;
  public
    function WithInspector(const AInspector: ICertificateInspector): IPkixProviderBuilder;
    function WithPathValidation(
      const APathValidation: ICertificatePathValidator): IPkixProviderBuilder;
    function WithRevocation(const ARevocation: IRevocationChecker): IPkixProviderBuilder;
    function Build: IPkixProvider;
  end;

implementation

{ TPkixProviderBuilder }

function TPkixProviderBuilder.WithInspector(
  const AInspector: ICertificateInspector): IPkixProviderBuilder;
begin
  FInspector := AInspector;
  Result := Self;
end;

function TPkixProviderBuilder.WithPathValidation(
  const APathValidation: ICertificatePathValidator): IPkixProviderBuilder;
begin
  FPathValidation := APathValidation;
  Result := Self;
end;

function TPkixProviderBuilder.WithRevocation(
  const ARevocation: IRevocationChecker): IPkixProviderBuilder;
begin
  FRevocation := ARevocation;
  Result := Self;
end;

function TPkixProviderBuilder.Build: IPkixProvider;
begin
  Result := TDefaultPkixProvider.Create(FInspector, FPathValidation, FRevocation) as IPkixProvider;
end;

end.
