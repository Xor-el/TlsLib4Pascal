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
  TlpArrayUtilities,
  TlpTlsVersion,
  TlpCryptoDomainTypes,
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
    FAlpn: TBytes;
    FBinderKind: TPskBinderKind;
    FTicketLifetime: UInt32;
    FTicketAgeAdd: UInt32;
    FIssuedAtMillis: UInt64;
  public
    constructor Create(const AIdentity: TBytes; const AKey: ISecretBuffer;
      AHash: THashAlgorithm; ACipherSuite: UInt16; AMaxEarlyData: UInt32;
      const AAlpn: TBytes; ABinderKind: TPskBinderKind;
      ATicketLifetime, ATicketAgeAdd: UInt32; AIssuedAtMillis: UInt64);

    function Identity: TBytes;
    function Key: ISecretBuffer;
    function Hash: THashAlgorithm;
    function CipherSuite: UInt16;
    function MaxEarlyData: UInt32;
    function Alpn: TBytes;
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

  /// <summary>The version-agnostic base of the default resumable-session holders: the
  /// fields common to both protocol versions.</summary>
  TResumableSessionBase = class abstract(TInterfacedObject, IResumableSession)
  strict protected
  var
    FVersion: TTlsVersion;
    FCipherSuite: UInt16;
    FHash: THashAlgorithm;
    FAlpn: TBytes;
    FServerName: string;
    FTicketLifetime: UInt32;
    FIssuedAtMillis: UInt64;
    FPeerCertificates: TArray<TBytes>;
    FResumptionScope: TBytes;
  public
    function Version: TTlsVersion;
    function CipherSuite: UInt16;
    function Hash: THashAlgorithm;
    function Alpn: TBytes;
    function ServerName: string;
    function TicketLifetime: UInt32;
    function IssuedAtMillis: UInt64;
    function PeerCertificates: TArray<TBytes>;
    function ResumptionScope: TBytes;
  end;

  /// <summary>The default <see cref="ITls13ResumableSession" />: an immutable value holder that
  /// also projects itself as the <see cref="IPreSharedKey" /> a client offers on resumption
  /// (identity = ticket identity, key = resumption secret, Resumption binder).</summary>
  TTls13ResumableSession = class sealed(TResumableSessionBase,
    ITls13ResumableSession, IPreSharedKey)
  strict private
  var
    FResumptionSecret: ISecretBuffer;
    FTicketIdentity: TBytes;
    FTicketAgeAdd: UInt32;
    FMaxEarlyData: UInt32;
  public
    /// <summary>APeerCertificates is the peer chain verified at establishment (empty when none).
    /// AResumptionScope is the opaque server scope sealed into the ticket (empty when none).</summary>
    constructor Create(ACipherSuite: UInt16; AHash: THashAlgorithm;
      const AResumptionSecret: ISecretBuffer; const AAlpn: TBytes; const AServerName: string;
      const ATicketIdentity: TBytes; ATicketLifetime, ATicketAgeAdd: UInt32;
      AIssuedAtMillis: UInt64; AMaxEarlyData: UInt32;
      const APeerCertificates: TArray<TBytes>; const AResumptionScope: TBytes);

    function ResumptionSecret: ISecretBuffer;
    function TicketIdentity: TBytes;
    function TicketAgeAdd: UInt32;
    function MaxEarlyData: UInt32;
    // IPreSharedKey (Hash/CipherSuite/Alpn/TicketLifetime/IssuedAtMillis are the base's; MaxEarlyData
    // and TicketAgeAdd are shared with ITls13ResumableSession) - only the PSK-specific projection here
    function Identity: TBytes;
    function Key: ISecretBuffer;
    function BinderKind: TPskBinderKind;
  end;

  /// <summary>The default <see cref="ITls12ResumableSession" />: an immutable value holder.</summary>
  TTls12ResumableSession = class sealed(TResumableSessionBase, ITls12ResumableSession)
  strict private
  var
    FMasterSecret: ISecretBuffer;
    FSessionId: TBytes;
    FSessionTicket: TBytes;
    FExtendedMasterSecret: Boolean;
  public
    /// <summary>APeerCertificates is the peer chain verified at establishment (empty when none).
    /// AResumptionScope is the opaque server scope sealed into the ticket (empty when none).</summary>
    constructor Create(ACipherSuite: UInt16; AHash: THashAlgorithm;
      const AMasterSecret: ISecretBuffer; const ASessionId, ASessionTicket: TBytes;
      AExtendedMasterSecret: Boolean; const AAlpn: TBytes; const AServerName: string;
      ATicketLifetime: UInt32; AIssuedAtMillis: UInt64;
      const APeerCertificates: TArray<TBytes>; const AResumptionScope: TBytes);

    function MasterSecret: ISecretBuffer;
    function SessionId: TBytes;
    function SessionTicket: TBytes;
    function ExtendedMasterSecret: Boolean;
  end;

implementation

{ TPreSharedKey }

constructor TPreSharedKey.Create(const AIdentity: TBytes; const AKey: ISecretBuffer;
  AHash: THashAlgorithm; ACipherSuite: UInt16; AMaxEarlyData: UInt32;
  const AAlpn: TBytes; ABinderKind: TPskBinderKind;
  ATicketLifetime, ATicketAgeAdd: UInt32; AIssuedAtMillis: UInt64);
begin
  inherited Create;
  FIdentity := System.Copy(AIdentity, 0, System.Length(AIdentity));
  FKey := AKey;
  FHash := AHash;
  FCipherSuite := ACipherSuite;
  FMaxEarlyData := AMaxEarlyData;
  FAlpn := System.Copy(AAlpn);
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
    nil, TPskBinderKind.Imported, 0, 0, 0);
end;

function TPreSharedKey.Identity: TBytes;
begin
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

function TPreSharedKey.Alpn: TBytes;
begin
  Result := System.Copy(FAlpn);
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

{ TResumableSessionBase }

function TResumableSessionBase.Version: TTlsVersion;
begin
  Result := FVersion;
end;

function TResumableSessionBase.CipherSuite: UInt16;
begin
  Result := FCipherSuite;
end;

function TResumableSessionBase.Hash: THashAlgorithm;
begin
  Result := FHash;
end;

function TResumableSessionBase.Alpn: TBytes;
begin
  Result := System.Copy(FAlpn);
end;

function TResumableSessionBase.ServerName: string;
begin
  Result := FServerName;
end;

function TResumableSessionBase.TicketLifetime: UInt32;
begin
  Result := FTicketLifetime;
end;

function TResumableSessionBase.IssuedAtMillis: UInt64;
begin
  Result := FIssuedAtMillis;
end;

function TResumableSessionBase.PeerCertificates: TArray<TBytes>;
begin
  Result := TArrayUtilities.DeepCopy<Byte>(FPeerCertificates);
end;

function TResumableSessionBase.ResumptionScope: TBytes;
begin
  Result := System.Copy(FResumptionScope);
end;

{ TTls13ResumableSession }

constructor TTls13ResumableSession.Create(ACipherSuite: UInt16;
  AHash: THashAlgorithm; const AResumptionSecret: ISecretBuffer;
  const AAlpn: TBytes; const AServerName: string; const ATicketIdentity: TBytes;
  ATicketLifetime, ATicketAgeAdd: UInt32; AIssuedAtMillis: UInt64;
  AMaxEarlyData: UInt32; const APeerCertificates: TArray<TBytes>;
  const AResumptionScope: TBytes);
begin
  inherited Create;
  FVersion := TTlsVersion.Tls13;
  FCipherSuite := ACipherSuite;
  FHash := AHash;
  FResumptionSecret := AResumptionSecret;
  FAlpn := System.Copy(AAlpn);
  FServerName := AServerName;
  FTicketIdentity := System.Copy(ATicketIdentity, 0, System.Length(ATicketIdentity));
  FTicketLifetime := ATicketLifetime;
  FTicketAgeAdd := ATicketAgeAdd;
  FIssuedAtMillis := AIssuedAtMillis;
  FMaxEarlyData := AMaxEarlyData;
  FPeerCertificates := TArrayUtilities.DeepCopy<Byte>(APeerCertificates);
  FResumptionScope := System.Copy(AResumptionScope);
end;

function TTls13ResumableSession.ResumptionSecret: ISecretBuffer;
begin
  Result := FResumptionSecret;
end;

function TTls13ResumableSession.TicketIdentity: TBytes;
begin
  Result := System.Copy(FTicketIdentity, 0, System.Length(FTicketIdentity));
end;

function TTls13ResumableSession.TicketAgeAdd: UInt32;
begin
  Result := FTicketAgeAdd;
end;

function TTls13ResumableSession.MaxEarlyData: UInt32;
begin
  Result := FMaxEarlyData;
end;

function TTls13ResumableSession.Identity: TBytes;
begin
  Result := System.Copy(FTicketIdentity, 0, System.Length(FTicketIdentity));
end;

function TTls13ResumableSession.Key: ISecretBuffer;
begin
  Result := FResumptionSecret;
end;

function TTls13ResumableSession.BinderKind: TPskBinderKind;
begin
  Result := TPskBinderKind.Resumption;
end;

{ TTls12ResumableSession }

constructor TTls12ResumableSession.Create(ACipherSuite: UInt16;
  AHash: THashAlgorithm; const AMasterSecret: ISecretBuffer;
  const ASessionId, ASessionTicket: TBytes; AExtendedMasterSecret: Boolean;
  const AAlpn: TBytes; const AServerName: string; ATicketLifetime: UInt32;
  AIssuedAtMillis: UInt64; const APeerCertificates: TArray<TBytes>;
  const AResumptionScope: TBytes);
begin
  inherited Create;
  FVersion := TTlsVersion.Tls12;
  FCipherSuite := ACipherSuite;
  FHash := AHash;
  FMasterSecret := AMasterSecret;
  FSessionId := System.Copy(ASessionId, 0, System.Length(ASessionId));
  FSessionTicket := System.Copy(ASessionTicket, 0, System.Length(ASessionTicket));
  FExtendedMasterSecret := AExtendedMasterSecret;
  FAlpn := System.Copy(AAlpn);
  FServerName := AServerName;
  FTicketLifetime := ATicketLifetime;
  FIssuedAtMillis := AIssuedAtMillis;
  FPeerCertificates := TArrayUtilities.DeepCopy<Byte>(APeerCertificates);
  FResumptionScope := System.Copy(AResumptionScope);
end;

function TTls12ResumableSession.MasterSecret: ISecretBuffer;
begin
  Result := FMasterSecret;
end;

function TTls12ResumableSession.SessionId: TBytes;
begin
  Result := System.Copy(FSessionId, 0, System.Length(FSessionId));
end;

function TTls12ResumableSession.SessionTicket: TBytes;
begin
  Result := System.Copy(FSessionTicket, 0, System.Length(FSessionTicket));
end;

function TTls12ResumableSession.ExtendedMasterSecret: Boolean;
begin
  Result := FExtendedMasterSecret;
end;

end.
