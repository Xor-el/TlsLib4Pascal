{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpSession;

{$I ..\Include\TlsLib.inc}

interface

uses
  SysUtils,
  TlpTlsVersion,
  TlpCryptoAlgorithms,
  TlpIKeySchedule,
  TlpISecretBuffer,
  TlpISession;

type
  /// <summary>
  /// An out-of-band external pre-shared key as provisioned to the endpoint, before it
  /// is imported for the wire (RFC 9258): the shared secret, the external identity and
  /// an optional context that scopes the key, plus the KDF hash the PSK is provisioned
  /// for. The importer turns this into one or more wire <see cref="IPreSharedKey" />
  /// (one per target hash) bound to a specific KDF and target protocol.
  /// </summary>
  TExternalPsk = record
    /// <summary>The external identity (RFC 9258 external_identity), pre-import.</summary>
    Identity: TBytes;
    /// <summary>The out-of-band pre-shared secret.</summary>
    Secret: ISecretBuffer;
    /// <summary>The RFC 9258 context that scopes this PSK (may be empty).</summary>
    Context: TBytes;
    /// <summary>The KDF hash the PSK was provisioned for (the importer hash).</summary>
    Hash: THashAlgorithm;
  end;

  /// <summary>The default <see cref="IPreSharedKey" />: an immutable value holder.</summary>
  TPreSharedKey = class sealed(TInterfacedObject, IPreSharedKey)
  strict private
  var
    FIdentity: TBytes;
    FKey: ISecretBuffer;
    FHash: THashAlgorithm;
    FCipherSuite: UInt16;
    FMaxEarlyData: UInt32;
    FAlpn: string;
    FBinderKind: TPskBinderKind;
    FTicketLifetime: UInt32;
    FTicketAgeAdd: UInt32;
    FIssuedAtMillis: UInt64;
  public
    constructor Create(const AIdentity: TBytes; const AKey: ISecretBuffer;
      AHash: THashAlgorithm; ACipherSuite: UInt16; AMaxEarlyData: UInt32;
      const AAlpn: string; ABinderKind: TPskBinderKind;
      ATicketLifetime, ATicketAgeAdd: UInt32; AIssuedAtMillis: UInt64);

    function Identity: TBytes;
    function Key: ISecretBuffer;
    function Hash: THashAlgorithm;
    function CipherSuite: UInt16;
    function MaxEarlyData: UInt32;
    function Alpn: string;
    function BinderKind: TPskBinderKind;
    function TicketLifetime: UInt32;
    function TicketAgeAdd: UInt32;
    function IssuedAtMillis: UInt64;

    /// <summary>An RFC 9258 imported external PSK bound only to a hash (any same-hash
    /// suite is acceptable): the identity is the imported identity and the key the
    /// derived ipskx.</summary>
    class function CreateImported(const AIdentity: TBytes; const AKey: ISecretBuffer;
      AHash: THashAlgorithm): IPreSharedKey; static;
  end;

  /// <summary>The default <see cref="IResumableSession" />: an immutable value holder.</summary>
  TResumableSession = class sealed(TInterfacedObject, IResumableSession)
  strict private
  var
    FVersion: TTlsVersion;
    FCipherSuite: UInt16;
    FHash: THashAlgorithm;
    FResumptionSecret: ISecretBuffer;
    FNamedGroup: UInt16;
    FAlpn: string;
    FServerName: string;
    FTicketIdentity: TBytes;
    FTicketLifetime: UInt32;
    FTicketAgeAdd: UInt32;
    FIssuedAtMillis: UInt64;
    FMaxEarlyData: UInt32;
    FMasterSecret: ISecretBuffer;
    FSessionId: TBytes;
    FSessionTicket: TBytes;
    FExtendedMasterSecret: Boolean;
  public
    function Version: TTlsVersion;
    function CipherSuite: UInt16;
    function Hash: THashAlgorithm;
    function ResumptionSecret: ISecretBuffer;
    function NamedGroup: UInt16;
    function Alpn: string;
    function ServerName: string;
    function TicketIdentity: TBytes;
    function TicketLifetime: UInt32;
    function TicketAgeAdd: UInt32;
    function IssuedAtMillis: UInt64;
    function MaxEarlyData: UInt32;
    function MasterSecret: ISecretBuffer;
    function SessionId: TBytes;
    function SessionTicket: TBytes;
    function ExtendedMasterSecret: Boolean;
    function AsPreSharedKey: IPreSharedKey;

    /// <summary>A TLS 1.3 resumable session (a resumption PSK + its selected parameters).</summary>
    class function CreateTls13(ACipherSuite: UInt16; AHash: THashAlgorithm;
      const AResumptionSecret: ISecretBuffer; ANamedGroup: UInt16;
      const AAlpn, AServerName: string; const ATicketIdentity: TBytes;
      ATicketLifetime, ATicketAgeAdd: UInt32; AIssuedAtMillis: UInt64;
      AMaxEarlyData: UInt32): IResumableSession; static;
    /// <summary>A TLS 1.2 resumable session (a master secret keyed by session id and/or ticket).</summary>
    class function CreateTls12(ACipherSuite: UInt16; AHash: THashAlgorithm;
      const AMasterSecret: ISecretBuffer; const ASessionId, ASessionTicket: TBytes;
      AExtendedMasterSecret: Boolean; const AAlpn, AServerName: string;
      ATicketLifetime, ATicketAgeAdd: UInt32;
      AIssuedAtMillis: UInt64): IResumableSession; static;
  end;

implementation

{ TPreSharedKey }

constructor TPreSharedKey.Create(const AIdentity: TBytes; const AKey: ISecretBuffer;
  AHash: THashAlgorithm; ACipherSuite: UInt16; AMaxEarlyData: UInt32;
  const AAlpn: string; ABinderKind: TPskBinderKind;
  ATicketLifetime, ATicketAgeAdd: UInt32; AIssuedAtMillis: UInt64);
begin
  inherited Create;
  FIdentity := System.Copy(AIdentity, 0, System.Length(AIdentity));
  FKey := AKey;
  FHash := AHash;
  FCipherSuite := ACipherSuite;
  FMaxEarlyData := AMaxEarlyData;
  FAlpn := AAlpn;
  FBinderKind := ABinderKind;
  FTicketLifetime := ATicketLifetime;
  FTicketAgeAdd := ATicketAgeAdd;
  FIssuedAtMillis := AIssuedAtMillis;
end;

class function TPreSharedKey.CreateImported(const AIdentity: TBytes;
  const AKey: ISecretBuffer; AHash: THashAlgorithm): IPreSharedKey;
begin
  // bound to a hash, not a suite (CipherSuite 0): the server may pick any same-hash
  // suite the client offered. No ticket lifetime/age or ALPN - an external PSK has none.
  Result := TPreSharedKey.Create(AIdentity, AKey, AHash, 0, 0,
    '', TPskBinderKind.Imported, 0, 0, 0);
end;

function TPreSharedKey.Identity: TBytes;
begin
  Result := nil;
  Result := System.Copy(FIdentity, 0, System.Length(FIdentity));
end;

function TPreSharedKey.Key: ISecretBuffer;
begin
  Result := FKey;
end;

function TPreSharedKey.Hash: THashAlgorithm;
begin
  Result := FHash;
end;

function TPreSharedKey.CipherSuite: UInt16;
begin
  Result := FCipherSuite;
end;

function TPreSharedKey.MaxEarlyData: UInt32;
begin
  Result := FMaxEarlyData;
end;

function TPreSharedKey.Alpn: string;
begin
  Result := FAlpn;
end;

function TPreSharedKey.BinderKind: TPskBinderKind;
begin
  Result := FBinderKind;
end;

function TPreSharedKey.TicketLifetime: UInt32;
begin
  Result := FTicketLifetime;
end;

function TPreSharedKey.TicketAgeAdd: UInt32;
begin
  Result := FTicketAgeAdd;
end;

function TPreSharedKey.IssuedAtMillis: UInt64;
begin
  Result := FIssuedAtMillis;
end;

{ TResumableSession }

class function TResumableSession.CreateTls13(ACipherSuite: UInt16;
  AHash: THashAlgorithm; const AResumptionSecret: ISecretBuffer;
  ANamedGroup: UInt16; const AAlpn, AServerName: string; const ATicketIdentity: TBytes;
  ATicketLifetime, ATicketAgeAdd: UInt32; AIssuedAtMillis: UInt64;
  AMaxEarlyData: UInt32): IResumableSession;
var
  LSession: TResumableSession;
begin
  LSession := TResumableSession.Create;
  LSession.FVersion := TTlsVersion.Tls13;
  LSession.FCipherSuite := ACipherSuite;
  LSession.FHash := AHash;
  LSession.FResumptionSecret := AResumptionSecret;
  LSession.FNamedGroup := ANamedGroup;
  LSession.FAlpn := AAlpn;
  LSession.FServerName := AServerName;
  LSession.FTicketIdentity := System.Copy(ATicketIdentity, 0,
    System.Length(ATicketIdentity));
  LSession.FTicketLifetime := ATicketLifetime;
  LSession.FTicketAgeAdd := ATicketAgeAdd;
  LSession.FIssuedAtMillis := AIssuedAtMillis;
  LSession.FMaxEarlyData := AMaxEarlyData;
  Result := LSession;
end;

class function TResumableSession.CreateTls12(ACipherSuite: UInt16;
  AHash: THashAlgorithm; const AMasterSecret: ISecretBuffer;
  const ASessionId, ASessionTicket: TBytes; AExtendedMasterSecret: Boolean;
  const AAlpn, AServerName: string; ATicketLifetime, ATicketAgeAdd: UInt32;
  AIssuedAtMillis: UInt64): IResumableSession;
var
  LSession: TResumableSession;
begin
  LSession := TResumableSession.Create;
  LSession.FVersion := TTlsVersion.Tls12;
  LSession.FCipherSuite := ACipherSuite;
  LSession.FHash := AHash;
  LSession.FMasterSecret := AMasterSecret;
  LSession.FSessionId := System.Copy(ASessionId, 0, System.Length(ASessionId));
  LSession.FSessionTicket := System.Copy(ASessionTicket, 0,
    System.Length(ASessionTicket));
  LSession.FExtendedMasterSecret := AExtendedMasterSecret;
  LSession.FAlpn := AAlpn;
  LSession.FServerName := AServerName;
  LSession.FTicketLifetime := ATicketLifetime;
  LSession.FTicketAgeAdd := ATicketAgeAdd;
  LSession.FIssuedAtMillis := AIssuedAtMillis;
  Result := LSession;
end;

function TResumableSession.Version: TTlsVersion;
begin
  Result := FVersion;
end;

function TResumableSession.CipherSuite: UInt16;
begin
  Result := FCipherSuite;
end;

function TResumableSession.Hash: THashAlgorithm;
begin
  Result := FHash;
end;

function TResumableSession.ResumptionSecret: ISecretBuffer;
begin
  Result := FResumptionSecret;
end;

function TResumableSession.NamedGroup: UInt16;
begin
  Result := FNamedGroup;
end;

function TResumableSession.Alpn: string;
begin
  Result := FAlpn;
end;

function TResumableSession.ServerName: string;
begin
  Result := FServerName;
end;

function TResumableSession.TicketIdentity: TBytes;
begin
  Result := nil;
  Result := System.Copy(FTicketIdentity, 0, System.Length(FTicketIdentity));
end;

function TResumableSession.TicketLifetime: UInt32;
begin
  Result := FTicketLifetime;
end;

function TResumableSession.TicketAgeAdd: UInt32;
begin
  Result := FTicketAgeAdd;
end;

function TResumableSession.IssuedAtMillis: UInt64;
begin
  Result := FIssuedAtMillis;
end;

function TResumableSession.MaxEarlyData: UInt32;
begin
  Result := FMaxEarlyData;
end;

function TResumableSession.MasterSecret: ISecretBuffer;
begin
  Result := FMasterSecret;
end;

function TResumableSession.SessionId: TBytes;
begin
  Result := nil;
  Result := System.Copy(FSessionId, 0, System.Length(FSessionId));
end;

function TResumableSession.SessionTicket: TBytes;
begin
  Result := nil;
  Result := System.Copy(FSessionTicket, 0, System.Length(FSessionTicket));
end;

function TResumableSession.ExtendedMasterSecret: Boolean;
begin
  Result := FExtendedMasterSecret;
end;

function TResumableSession.AsPreSharedKey: IPreSharedKey;
begin
  // only a TLS 1.3 session carries a resumption secret; a 1.2 session has none, so it is
  // never a valid 1.3 PSK offer - callers treat nil as "no 1.3 resumption offer"
  Result := nil;
  if not FVersion.Equals(TTlsVersion.Tls13) then
    Exit;
  Result := TPreSharedKey.Create(FTicketIdentity, FResumptionSecret, FHash,
    FCipherSuite, FMaxEarlyData, FAlpn, TPskBinderKind.Resumption, FTicketLifetime,
    FTicketAgeAdd, FIssuedAtMillis);
end;

end.
