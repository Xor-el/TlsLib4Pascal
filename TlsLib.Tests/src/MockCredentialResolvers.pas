{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit MockCredentialResolvers;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  SysUtils,
  TlpTlsLibExceptions,
  TlpTlsCredential,
  TlpITlsCredentialResolver,
  TlpITlsServerCredentialSet;

type
  /// <summary>A resolver that answers one fixed credential, or refuses, and does not list it, as a
  /// host-owned one. It keeps the ClientHello facts of the last lookup. Never for production
  /// use.</summary>
  TFixedCredentialResolver = class sealed(TInterfacedObject, ITlsServerCredentialResolver)
  strict private
  var
    FCredential: TTlsCredential;
    FResolves: Boolean;
    FHello: TTlsClientHelloInfo;
  public
    constructor Create(const ACredential: TTlsCredential; AResolves: Boolean);
    function TryResolve(const AClientHello: TTlsClientHelloInfo;
      out ACredential: TTlsCredential): Boolean;
    property Hello: TTlsClientHelloInfo read FHello;
  end;

  /// <summary>A host-written resolver that lists the credentials it may select and hands out the
  /// first. Never for production use.</summary>
  TListedCredentialResolver = class sealed(TInterfacedObject, ITlsServerCredentialResolver,
    ITlsServerCredentialSet)
  strict private
  var
    FCredentials: TArray<TTlsCredential>;
  public
    constructor Create(const ACredentials: TArray<TTlsCredential>);
    function TryResolve(const AClientHello: TTlsClientHelloInfo;
      out ACredential: TTlsCredential): Boolean;
    function Credentials: TArray<TTlsCredential>;
  end;

  /// <summary>A resolver whose lookup fails, as a host resolver backed by a store that is down.
  /// Never for production use.</summary>
  TFailingCredentialResolver = class sealed(TInterfacedObject, ITlsServerCredentialResolver)
  public
    function TryResolve(const AClientHello: TTlsClientHelloInfo;
      out ACredential: TTlsCredential): Boolean;
  end;

implementation

resourcestring
  SResolverStoreDown = 'the credential store is down';

{ TFixedCredentialResolver }

constructor TFixedCredentialResolver.Create(const ACredential: TTlsCredential;
  AResolves: Boolean);
begin
  inherited Create;
  FCredential := ACredential;
  FResolves := AResolves;
end;

function TFixedCredentialResolver.TryResolve(const AClientHello: TTlsClientHelloInfo;
  out ACredential: TTlsCredential): Boolean;
begin
  FHello := AClientHello;
  ACredential := FCredential;
  Result := FResolves;
end;

{ TListedCredentialResolver }

constructor TListedCredentialResolver.Create(const ACredentials: TArray<TTlsCredential>);
begin
  inherited Create;
  FCredentials := ACredentials;
end;

function TListedCredentialResolver.TryResolve(const AClientHello: TTlsClientHelloInfo;
  out ACredential: TTlsCredential): Boolean;
begin
  ACredential := FCredentials[0];
  Result := True;
end;

function TListedCredentialResolver.Credentials: TArray<TTlsCredential>;
begin
  Result := FCredentials;
end;

{ TFailingCredentialResolver }

function TFailingCredentialResolver.TryResolve(const AClientHello: TTlsClientHelloInfo;
  out ACredential: TTlsCredential): Boolean;
begin
  ACredential := Default(TTlsCredential);
  raise EInvalidOperationTlsLibException.CreateRes(@SResolverStoreDown);
end;

end.
