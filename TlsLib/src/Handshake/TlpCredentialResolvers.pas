{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpCredentialResolvers;

{$I ..\Include\TlsLib.inc}

interface

uses
  SysUtils,
  TlpArrayUtilities,
  TlpTlsCredential,
  TlpITlsCredentialResolver,
  TlpITlsServerCredentialSet,
  TlpEndpointIdentity,
  TlpServerName;

type
  /// <summary>One host-pattern to credential mapping for the built-in SNI resolver. AHost is a
  /// DNS host_name, either exact (host.example.com) or a single left-most-label wildcard
  /// (*.example.com); matching follows RFC 9525 via TEndpointIdentity.</summary>
  TSniCredentialEntry = record
    Host: string;
    Credential: TTlsCredential;
  end;

  /// <summary>
  /// The built-in <see cref="ITlsServerCredentialResolver" />: selects a server credential
  /// by the client's SNI host_name (RFC 6066) - lowercased exact match first, then a
  /// single-label wildcard entry, reusing the same TEndpointIdentity rules client-side name
  /// verification uses so the two can never disagree. A no-SNI / no-match handshake falls back
  /// to the default credential when one was supplied, else TryResolve returns False (the state
  /// machine then aborts). Immutable after construction, so concurrent use across the peers of
  /// one frozen configuration needs no lock.
  /// </summary>
  TSniCredentialResolver = class sealed(TInterfacedObject, ITlsServerCredentialResolver,
    ITlsServerCredentialSet)
  strict private
    FEntries: TArray<TSniCredentialEntry>;
    FDefault: TTlsCredential;
    FHasDefault: Boolean;
  public
    constructor Create(const AEntries: TArray<TSniCredentialEntry>); overload;
    /// <summary>ADefault is returned when a client's SNI matches no entry (the WithCredential
    /// single credential); the no-default overload refuses such a client.</summary>
    constructor Create(const AEntries: TArray<TSniCredentialEntry>;
      const ADefault: TTlsCredential); overload;
    /// <summary>A resolver that returns ACredential for every handshake, ignoring the SNI - the
    /// single-certificate server, and the one-line adapter for a direct sans-IO caller that holds
    /// a credential rather than a resolver.</summary>
    class function ForCredential(
      const ACredential: TTlsCredential): ITlsServerCredentialResolver; static;
    /// <summary>A resolver over host-keyed entries with no default: a client whose SNI matches no
    /// entry is refused.</summary>
    class function ForEntries(
      const AEntries: TArray<TSniCredentialEntry>): ITlsServerCredentialResolver; static;
    function TryResolve(const AClientHello: TTlsClientHelloInfo;
      out ACredential: TTlsCredential): Boolean;
    /// <summary>The default (when one was supplied) then each entry in order, in a new array, with
    /// no deduplication. The chains and staples are copies the caller may change; the keys and
    /// the OcspStapleCallback are shared with the resolver.</summary>
    function Credentials: TArray<TTlsCredential>;
  end;

implementation

{ TSniCredentialResolver }

class function TSniCredentialResolver.ForCredential(
  const ACredential: TTlsCredential): ITlsServerCredentialResolver;
begin
  Result := TSniCredentialResolver.Create(nil, ACredential)
    as ITlsServerCredentialResolver;
end;

class function TSniCredentialResolver.ForEntries(
  const AEntries: TArray<TSniCredentialEntry>): ITlsServerCredentialResolver;
begin
  Result := TSniCredentialResolver.Create(AEntries)
    as ITlsServerCredentialResolver;
end;

constructor TSniCredentialResolver.Create(const AEntries: TArray<TSniCredentialEntry>);
var
  LI: Integer;
begin
  inherited Create;
  FEntries := System.Copy(AEntries, 0, System.Length(AEntries));
  // host_names are case-insensitive (RFC 6066 / DNS); normalise once so lookup can compare raw
  for LI := 0 to System.High(FEntries) do
    FEntries[LI].Host := LowerCase(FEntries[LI].Host);
end;

constructor TSniCredentialResolver.Create(const AEntries: TArray<TSniCredentialEntry>;
  const ADefault: TTlsCredential);
begin
  Create(AEntries);
  FHasDefault := True;
  FDefault := ADefault;
end;

function TSniCredentialResolver.TryResolve(const AClientHello: TTlsClientHelloInfo;
  out ACredential: TTlsCredential): Boolean;
var
  LSni: string;
  LI: Integer;
begin
  ACredential := Default(TTlsCredential);
  LSni := LowerCase(AClientHello.ServerName);
  if LSni <> '' then
  begin
    // an exact host always beats a wildcard covering the same name, so match exact entries first
    for LI := 0 to System.High(FEntries) do
      if (Pos('*', FEntries[LI].Host) = 0) and (FEntries[LI].Host = LSni) then
      begin
        ACredential := FEntries[LI].Credential;
        Exit(True);
      end;
    for LI := 0 to System.High(FEntries) do
      if (Pos('*', FEntries[LI].Host) > 0) and
        TEndpointIdentity.Matches(TServerName.DnsName(LSni),
        TArray<string>.Create(FEntries[LI].Host), nil) then
      begin
        ACredential := FEntries[LI].Credential;
        Exit(True);
      end;
  end;
  // no SNI, or no configured host matched: the default credential is the fallback
  if FHasDefault then
  begin
    ACredential := FDefault;
    Exit(True);
  end;
  Result := False;
end;

function TSniCredentialResolver.Credentials: TArray<TTlsCredential>;
var
  LI: Integer;
begin
  Result := nil;
  if FHasDefault then
    TArrayUtilities.Append<TTlsCredential>(Result, FDefault.Clone);
  for LI := 0 to System.High(FEntries) do
    TArrayUtilities.Append<TTlsCredential>(Result, FEntries[LI].Credential.Clone);
end;

end.
