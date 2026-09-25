{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpVersionDispatchMachine;

{$I ..\Include\TlsLib.inc}

interface

uses
  SysUtils,
  TlpArrayUtilities,
  TlpTlsVersion,
  TlpTlsAlert,
  TlpTlsLibExceptions,
  TlpWireReader,
  TlpExtensionVector,
  TlpCoreExtensions,
  TlpNegotiationTypes,
  TlpNegotiationPolicy,
  TlpHandshakeMessage,
  TlpHandshakeMessages,
  TlpHandshakeEffect,
  TlpHandshakeStage,
  TlpIHandshakeMachine,
  TlpTls13ClientStateMachine,
  TlpTls13ServerStateMachine,
  TlpTls12ClientStateMachine,
  TlpTls12ServerStateMachine;

type
  /// <summary>
  /// A handshake machine that resolves the protocol version from the first message and
  /// then delegates every message to the version-specific sub-machine. Both roles share
  /// the forwarding: once Dispatch has picked a sub-machine, ProcessMessage just relays.
  /// </summary>
  TVersionDispatchMachineBase = class abstract(TInterfacedObject, IHandshakeMachine)
  strict protected
    FInner: IHandshakeMachine;
    /// <summary>Picks the sub-machine for AMessage, assigns FInner, and returns the
    /// sub-machine's effects for that message.</summary>
    function Dispatch(const AMessage: TTlsHandshakeMessage)
      : TArray<THandshakeEffect>; reintroduce; virtual; abstract;
    /// <summary>The one structural parse of a ClientHello's extension block: Empty for an absent
    /// field (a legacy 1.2-only shape), otherwise the fully-validated vector. Both readers below
    /// take this vector, so the outer block is walked once per dispatch.</summary>
    class function ParseExtensions(const AExtensions: TBytes): TExtensionVector; static;
    /// <summary>Reads the versions listed in a ClientHello's supported_versions
    /// extension (empty when the extension is absent - a legacy 1.2-only client).</summary>
    class function ClientHelloVersions(const AVector: TExtensionVector): TArray<UInt16>; static;
    /// <summary>Whether the ClientHello carries an encrypted_client_hello extension (RFC
    /// 9849): such a client is doing ECH and is TLS 1.3, even when a minimal ClientHelloOuter
    /// omits supported_versions.</summary>
    class function HasEncryptedClientHello(const AVector: TExtensionVector): Boolean; static;
  public
    /// <summary>A responder (server dispatcher) by default; the client dispatcher overrides.</summary>
    function Initiates: Boolean; virtual;
    /// <summary>Forwards the coarse stage from the resolved sub-machine (Handshaking until one
    /// is chosen).</summary>
    function Stage: THandshakeStage;
    function Start: TArray<THandshakeEffect>; virtual; abstract;
    function ProcessMessage(const AMessage: TTlsHandshakeMessage)
      : TArray<THandshakeEffect>;
    /// <summary>Forwards a post-handshake KeyUpdate request to the resolved sub-machine.</summary>
    function RequestKeyUpdate(ARequest: TKeyUpdateRequest): TArray<THandshakeEffect>;
    function TakePendingKeyUpdate: TArray<THandshakeEffect>;
    /// <summary>Forwards a resume-after-verdict continuation to the resolved sub-machine.</summary>
    function ResumeAfterVerdict: TArray<THandshakeEffect>;
    /// <summary>Forwards an exporter request to the resolved sub-machine.</summary>
    function ExportKeyingMaterial(const ALabel: string;
      ALength: Int32): TBytes; overload;
    function ExportKeyingMaterial(const ALabel: string; const AContext: TBytes;
      ALength: Int32): TBytes; overload;
    function CanExportKeyingMaterial: Boolean;
  end;

  /// <summary>
  /// The server-side version dispatcher: it starts on the ClientHello, chooses TLS 1.3
  /// when both peers support it and TLS 1.2 otherwise, and builds the matching server
  /// sub-machine. When a 1.3-capable server negotiates 1.2 it tells the 1.2 machine to
  /// stamp the downgrade sentinel (RFC 8446 4.1.3).
  /// </summary>
  TServerVersionDispatchMachine = class sealed(TVersionDispatchMachineBase)
  strict private
    FServerSupportsTls13: Boolean;
    FServerSupportsTls12: Boolean;
    FServerHighestVersion: UInt16;
    FParams13: TServerHandshakeParams;
    FParams12: TServer12HandshakeParams;
    /// <summary>The numerically greatest known TLS wire version (0x0301..0x0304) in the set,
    /// or 0 when none is present; GREASE and unknown codepoints are not versions.</summary>
    class function HighestKnownVersion(const AVersions: TArray<UInt16>): UInt16; static;
  strict protected
    function Dispatch(const AMessage: TTlsHandshakeMessage)
      : TArray<THandshakeEffect>; override;
  public
    constructor Create(const AParams13: TServerHandshakeParams;
      const AParams12: TServer12HandshakeParams;
      const ASupportedVersions: TArray<UInt16>);
    function Start: TArray<THandshakeEffect>; override;
  end;

  /// <summary>
  /// The client-side version dispatcher: Start builds and sends one unified ClientHello
  /// (via a 1.3 client machine that also offers 1.2), then on the ServerHello it keeps
  /// that 1.3 machine if 1.3 was selected, or hands off to a 1.2 client machine seeded
  /// with the already-sent ClientHello if 1.2 was selected.
  /// </summary>
  TClientVersionDispatchMachine = class sealed(TVersionDispatchMachineBase)
  strict private
    FPrimary13: IHandshakeMachine;
    // the same object as FPrimary13, held typed so a 1.2 hand-off can read the cached 1.2
    // session it took; FPrimary13 owns the reference (this stays valid while that does)
    FPrimary13Typed: TTls13ClientStateMachine;
    FParams12: TClient12HandshakeParams;
    FClientHello: TBytes;
    /// <summary>Whether the client requires one of its offered external PSKs: a server that
    /// negotiates TLS 1.2 (which cannot carry a TLS 1.3 external PSK) is then rejected.</summary>
    FRequirePsk: Boolean;
  strict protected
    function Dispatch(const AMessage: TTlsHandshakeMessage)
      : TArray<THandshakeEffect>; override;
  public
    constructor Create(const AParams13: TClientHandshakeParams;
      const AParams12: TClient12HandshakeParams);
    function Initiates: Boolean; override;
    function Start: TArray<THandshakeEffect>; override;
  end;

implementation

resourcestring
  SEchRequiresTls13 = 'Encrypted Client Hello requires TLS 1.3; it cannot be offered by a ' +
    'version-dispatching client that also offers TLS 1.2';

{ TVersionDispatchMachineBase }

function TVersionDispatchMachineBase.Initiates: Boolean;
begin
  Result := False;
end;

function TVersionDispatchMachineBase.ProcessMessage(
  const AMessage: TTlsHandshakeMessage): TArray<THandshakeEffect>;
begin
  // the inner machine already maps its own in-band failures to Fail effects; only the
  // first-message dispatch (a malformed ClientHello/ServerHello) needs the same mapping
  if FInner <> nil then
    Result := FInner.ProcessMessage(AMessage)
  else
    try
      Result := Dispatch(AMessage);
    except
      on E: EPeerInputTlsLibException do
        Result := TArray<THandshakeEffect>.Create(
          THandshakeEffects.Fail(TTlsAlertDescription.IllegalParameter));
      on E: EFatalAlertTlsLibException do
        Result := TArray<THandshakeEffect>.Create(
          THandshakeEffects.Fail(E.AlertDescription));
    end;
end;

function TVersionDispatchMachineBase.Stage: THandshakeStage;
begin
  // Handshaking until a sub-machine is resolved; then whatever it reports
  if FInner <> nil then
    Result := FInner.Stage
  else
    Result := THandshakeStage.Handshaking;
end;

function TVersionDispatchMachineBase.RequestKeyUpdate(
  ARequest: TKeyUpdateRequest): TArray<THandshakeEffect>;
begin
  // only meaningful once a version was resolved (post-handshake)
  if FInner <> nil then
    Result := FInner.RequestKeyUpdate(ARequest)
  else
    Result := nil;
end;

function TVersionDispatchMachineBase.TakePendingKeyUpdate: TArray<THandshakeEffect>;
begin
  if FInner <> nil then
    Result := FInner.TakePendingKeyUpdate
  else
    Result := nil;
end;

function TVersionDispatchMachineBase.ResumeAfterVerdict: TArray<THandshakeEffect>;
begin
  if FInner <> nil then
    Result := FInner.ResumeAfterVerdict
  else
    Result := nil;
end;

function TVersionDispatchMachineBase.ExportKeyingMaterial(const ALabel: string;
  ALength: Int32): TBytes;
begin
  // only meaningful once a version was resolved and its secrets derived
  if FInner <> nil then
    Result := FInner.ExportKeyingMaterial(ALabel, ALength)
  else
    Result := nil;
end;

function TVersionDispatchMachineBase.ExportKeyingMaterial(const ALabel: string;
  const AContext: TBytes; ALength: Int32): TBytes;
begin
  if FInner <> nil then
    Result := FInner.ExportKeyingMaterial(ALabel, AContext, ALength)
  else
    Result := nil;
end;

function TVersionDispatchMachineBase.CanExportKeyingMaterial: Boolean;
begin
  Result := (FInner <> nil) and FInner.CanExportKeyingMaterial;
end;

class function TVersionDispatchMachineBase.ParseExtensions(
  const AExtensions: TBytes): TExtensionVector;
begin
  // an absent extensions field is a legacy ClientHello shape: the empty vector, never parsed
  // (TExtensionVector.Parse treats an empty field as decode_error). A present field is parsed in
  // full here - a duplicate type, an over-cap count or trailing bytes are rejected with their
  // structural alert before the version is chosen, rather than slipping through a tolerant
  // pre-scan to fail later during the message's own extension pass
  if System.Length(AExtensions) = 0 then
    Result := TExtensionVector.Empty
  else
    Result := TExtensionVector.Parse(AExtensions);
end;

class function TVersionDispatchMachineBase.ClientHelloVersions(
  const AVector: TExtensionVector): TArray<UInt16>;
var
  LEntry: TExtensionEntry;
  LReader, LVers: TWireReader;
begin
  Result := nil;
  if AVector.TryFind(TExtensionTypes.SupportedVersions, LEntry) then
  begin
    // ClientHello supported_versions: a 1-byte-length list of uint16 versions
    LReader := TWireReader.Create(LEntry.Data);
    LVers := LReader.OpenVector(1);
    while not LVers.EndReached do
      TArrayUtilities.Append<UInt16>(Result, LVers.ReadUInt16);
  end;
end;

class function TVersionDispatchMachineBase.HasEncryptedClientHello(
  const AVector: TExtensionVector): Boolean;
begin
  Result := AVector.Contains(TExtensionTypes.EncryptedClientHello);
end;

{ TServerVersionDispatchMachine }

class function TServerVersionDispatchMachine.HighestKnownVersion(
  const AVersions: TArray<UInt16>): UInt16;
var
  LVersion: UInt16;
begin
  // a GREASE or otherwise unknown supported_versions entry is ignored (RFC 8701 3.1 /
  // RFC 8446 4.2.1); counting it as an offer would mask a spurious fallback (RFC 7507)
  Result := 0;
  for LVersion in AVersions do
    if (LVersion >= TlsWireVersionTls10) and (LVersion <= TlsWireVersionTls13) and
      (LVersion > Result) then
      Result := LVersion;
end;

constructor TServerVersionDispatchMachine.Create(
  const AParams13: TServerHandshakeParams;
  const AParams12: TServer12HandshakeParams;
  const ASupportedVersions: TArray<UInt16>);
begin
  inherited Create;
  FParams13 := AParams13;
  FParams12 := AParams12;
  FServerSupportsTls13 := TArrayUtilities.Contains<UInt16>(ASupportedVersions,
    TlsWireVersionTls13);
  FServerSupportsTls12 := TArrayUtilities.Contains<UInt16>(ASupportedVersions,
    TlsWireVersionTls12);
  FServerHighestVersion := HighestKnownVersion(ASupportedVersions);
end;

function TServerVersionDispatchMachine.Start: TArray<THandshakeEffect>;
begin
  // a server does not initiate; it starts on the ClientHello
  Result := nil;
end;

function TServerVersionDispatchMachine.Dispatch(
  const AMessage: TTlsHandshakeMessage): TArray<THandshakeEffect>;
var
  LHello: TTlsClientHello;
  LExtensions: TExtensionVector;
  LClientVersions: TArray<UInt16>;
  LClientSupportsTls13: Boolean;
  LClientOffers12: Boolean;
  LClientHighest: UInt16;
begin
  LHello := THandshakeMessages.DecodeClientHello(AMessage.Body);
  // parse the outer extension block once; both the supported_versions read and the ech-presence
  // check below take this vector rather than re-walking the unauthenticated block
  LExtensions := ParseExtensions(LHello.Extensions);
  LClientVersions := ClientHelloVersions(LExtensions);
  // an Encrypted Client Hello whose minimal ClientHelloOuter omits supported_versions is still
  // a TLS 1.3 client (RFC 9849 sec. 7: the version comes from the decrypted inner) - route it
  // to the 1.3 machine. An ech alongside an explicit version list does NOT override that list,
  // so a legacy client GREASE-ing ech while offering only 1.2 still negotiates 1.2.
  LClientSupportsTls13 := (TArrayUtilities.Contains<UInt16>(LClientVersions,
    TlsWireVersionTls13)) or ((System.Length(LClientVersions) = 0) and
    HasEncryptedClientHello(LExtensions));

  // RFC 7507 TLS_FALLBACK_SCSV: a client that retried at a lower version signals it in
  // cipher_suites. The client's highest version is its supported_versions (a 1.3 client
  // sets legacy_version 0x0303 but lists 1.3 there); a legacy client without the
  // extension tops out at 1.2. If the server could have done better, the fallback was
  // spurious and is refused (RFC 7507 3). This is checked before the version floor so a
  // spurious fallback reports inappropriate_fallback rather than protocol_version.
  if TArrayUtilities.Contains<UInt16>(LHello.CipherSuites, TlsFallbackScsv) then
  begin
    if System.Length(LClientVersions) = 0 then
      LClientHighest := TlsWireVersionTls12
    else
      LClientHighest := HighestKnownVersion(LClientVersions);
    // a list with no known version is not a fallback signal; let the version floor report it as
    // protocol_version rather than inappropriate_fallback
    if (LClientHighest <> 0) and (FServerHighestVersion > LClientHighest) then
      Exit(TArray<THandshakeEffect>.Create(
        THandshakeEffects.Fail(TTlsAlertDescription.InappropriateFallback)));
  end;

  // a client whose highest offered version is below our floor (TLS 1.2) - a pre-1.2 client,
  // whose version is the legacy_version when supported_versions is absent - selected nothing
  // this server supports: protocol_version, rather than a 1.2 handshake it cannot complete
  if System.Length(LClientVersions) = 0 then
    LClientHighest := LHello.LegacyVersion
  else
    LClientHighest := HighestKnownVersion(LClientVersions);
  if LClientHighest < TlsWireVersionTls12 then
    Exit(TArray<THandshakeEffect>.Create(
      THandshakeEffects.Fail(TTlsAlertDescription.ProtocolVersion)));

  // a client with no supported_versions offers 1.2 through its legacy_version (already floored
  // at 1.2 above); a 1.3 client that lists supported_versions must name 1.2 there to negotiate it
  LClientOffers12 := (System.Length(LClientVersions) = 0) or
    (TArrayUtilities.Contains<UInt16>(LClientVersions, TlsWireVersionTls12));

  if FServerSupportsTls13 and LClientSupportsTls13 then
  begin
    // a TLS 1.3 ClientHello's legacy_compression_methods is exactly the single null byte;
    // any additional methods are an illegal_parameter (RFC 8446 4.1.2). A lower version
    // still accepts a longer list, so this is enforced only now that 1.3 is selected - the
    // decode already rejected a list that offers no null method at all.
    if not THandshakeMessages.IsNullOnlyCompression(LHello.CompressionMethods) then
      Exit(TArray<THandshakeEffect>.Create(
        THandshakeEffects.Fail(TTlsAlertDescription.IllegalParameter)));
    FInner := TTls13ServerStateMachine.Create(FParams13) as IHandshakeMachine;
  end
  else if FServerSupportsTls12 and LClientOffers12 then
  begin
    // a 1.3-capable server that negotiates 1.2 stamps the downgrade sentinel so a
    // 1.3-capable client detects a stripped 1.3 offer (RFC 8446 4.1.3)
    FParams12.EmitDowngradeSentinel := FServerSupportsTls13;
    FInner := TTls12ServerStateMachine.Create(FParams12) as IHandshakeMachine;
  end
  else
    // the client and server share no supported protocol version (RFC 8446 4.2.1)
    Exit(TArray<THandshakeEffect>.Create(
      THandshakeEffects.Fail(TTlsAlertDescription.ProtocolVersion)));
  Result := FInner.ProcessMessage(AMessage);
end;

{ TClientVersionDispatchMachine }

constructor TClientVersionDispatchMachine.Create(
  const AParams13: TClientHandshakeParams;
  const AParams12: TClient12HandshakeParams);
var
  L13: TClientHandshakeParams;
begin
  inherited Create;
  // a config carrying ECH keys cannot go through the dual-version client: the dispatcher offers
  // TLS 1.2 in the outer ClientHello, and ECH is defined only for TLS 1.3 (RFC 9849 sec. 6.1).
  // GREASE-only ECH (an empty config list) stays allowed
  if (AParams13.EchPolicy <> nil) and (System.Length(AParams13.EchPolicy.Configs) > 0) then
    raise EArgumentTlsLibException.CreateRes(@SEchRequiresTls13);
  L13 := AParams13;
  L13.AlsoOfferTls12 := True;
  FPrimary13Typed := TTls13ClientStateMachine.Create(L13);
  FPrimary13 := FPrimary13Typed as IHandshakeMachine;
  FParams12 := AParams12;
  FRequirePsk := AParams13.RequirePsk;
end;

function TClientVersionDispatchMachine.Initiates: Boolean;
begin
  Result := True;
end;

function TClientVersionDispatchMachine.Start: TArray<THandshakeEffect>;
var
  LEffect: THandshakeEffect;
begin
  // the 1.3 machine builds and "sends" the unified ClientHello (offering both versions);
  // capture its bytes so a 1.2 hand-off can seed its transcript from the same message.
  // The 1.3 machine defers its middlebox change_cipher_spec until the version is known,
  // so there is nothing here a 1.2 server would reject
  Result := FPrimary13.Start;
  for LEffect in Result do
    if LEffect.Kind = THandshakeEffectKind.SendHandshake then
      FClientHello := LEffect.Bytes;
end;

function TClientVersionDispatchMachine.Dispatch(
  const AMessage: TTlsHandshakeMessage): TArray<THandshakeEffect>;
var
  LHello: TTlsServerHello;
  LSelectedVersion: UInt16;
begin
  LHello := THandshakeMessages.DecodeServerHello(AMessage.Body);
  // a HelloRetryRequest is a 1.3 construct; otherwise the negotiated version is the
  // supported_versions selection, or the legacy_version when the extension is absent
  if THelloRetryRequest.IsSentinel(LHello.Random) then
    LSelectedVersion := TlsWireVersionTls13
  else
  begin
    LSelectedVersion := THandshakeMessages.ServerHelloSelectedVersion(LHello.Extensions);
    if LSelectedVersion = 0 then
      LSelectedVersion := LHello.LegacyVersion
    // supported_versions in a ServerHello is a TLS 1.3 construct: a server that
    // negotiates 1.2 or below MUST NOT send it (RFC 8446 4.2.1). Present but
    // selecting a pre-1.3 version is an unpermitted extension, not a 1.2 handshake.
    else if LSelectedVersion < TlsWireVersionTls13 then
      Exit(TArray<THandshakeEffect>.Create(
        THandshakeEffects.Fail(TTlsAlertDescription.UnsupportedExtension)));
    // a server that selected a version below our floor (TLS 1.2) chose one this client
    // does not support: protocol_version, not a downstream handshake failure (RFC 8446 4.2.1)
    if LSelectedVersion < TlsWireVersionTls12 then
      Exit(TArray<THandshakeEffect>.Create(
        THandshakeEffects.Fail(TTlsAlertDescription.ProtocolVersion)));
  end;

  if LSelectedVersion = TlsWireVersionTls13 then
    FInner := FPrimary13
  else
  begin
    // a PSK-only client cannot satisfy its required external PSK over TLS 1.2 (an external
    // PSK is a TLS 1.3 construct), so a 1.2 selection is protocol_version (RFC 8446 4.2.1)
    if FRequirePsk then
      Exit(TArray<THandshakeEffect>.Create(
        THandshakeEffects.Fail(TTlsAlertDescription.ProtocolVersion)));
    // 0-RTT was offered but the server chose 1.2, where early data cannot exist: the response
    // is inconsistent with the offer (RFC 8446 D.3)
    if FPrimary13Typed.EarlyDataOffered then
      Exit(TArray<THandshakeEffect>.Create(
        THandshakeEffects.Fail(TTlsAlertDescription.IllegalParameter)));
    FParams12.PresentClientHello := FClientHello;
    // carry any cached 1.2 session the unified ClientHello offered into the 1.2 machine, so
    // it resumes when the server echoes the offered session id (read before releasing the
    // 1.3 machine that holds it)
    FParams12.PresentResumptionSession := FPrimary13Typed.Tls12ResumptionSession;
    // the actually-sent legacy_session_id (a cached 1.2 id, or the compatibility-mode id when
    // resuming nothing), so the 1.2 machine can catch a server that falsely echoes it
    FParams12.PresentOfferedSessionId := FPrimary13Typed.SentLegacySessionId;
    FInner := TTls12ClientStateMachine.Create(FParams12) as IHandshakeMachine;
    FInner.Start; // seeds the transcript from the already-sent ClientHello
    FPrimary13 := nil;
    FPrimary13Typed := nil;
  end;
  Result := FInner.ProcessMessage(AMessage);
end;

end.
