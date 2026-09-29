{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpISession;

{$I ..\..\Include\TlsLib.inc}

interface

uses
  SysUtils,
  TlpTlsVersion,
  TlpCryptoDomainTypes,
  TlpIKeySchedule,
  TlpISecretBuffer;

type
  /// <summary>
  /// A pre-shared key the client offers in a ClientHello (RFC 8446 4.2.11). An
  /// external PSK carries only its identity, secret and bound hash; a resumption PSK
  /// adds the bound suite, the ticket lifetime, the ticket_age_add obfuscator and its
  /// issue time so the client can compute obfuscated_ticket_age, plus the
  /// max_early_data the ticket authorized for 0-RTT. BinderKind selects the binder
  /// label the key was provisioned under.
  /// </summary>
  IPreSharedKey = interface(IInterface)
    ['{0D3F6A21-4C58-4E9B-9A17-2B7E0C5D8F31}']
    /// <summary>The PSK identity: an opaque ticket for resumption, or the imported
    /// identity (RFC 9258 5.1) of an external PSK.</summary>
    function Identity: TBytes;
    /// <summary>The PSK secret keying material.</summary>
    function Key: ISecretBuffer;
    /// <summary>The hash the PSK is bound to (the transcript/binder hash).</summary>
    function Hash: THashAlgorithm;
    /// <summary>The cipher suite the PSK is bound to, or 0 when the PSK is bound only to
    /// a hash and any same-hash suite is acceptable (external PSKs).</summary>
    function CipherSuite: UInt16;
    /// <summary>The 0-RTT byte budget the ticket authorized (0 = no early data).</summary>
    function MaxEarlyData: UInt32;
    /// <summary>The ALPN protocol negotiated on the session this PSK resumes (empty when none),
    /// so an accepted 0-RTT offer can enforce that the server keeps the same protocol (RFC 8446
    /// 4.2.11); external PSKs carry no ALPN.</summary>
    function Alpn: string;
    /// <summary>Which binder label the PSK uses: Resumption for a ticket, Imported for an
    /// RFC 9258 external PSK. Also selects whether an obfuscated_ticket_age is offered.</summary>
    function BinderKind: TPskBinderKind;
    /// <summary>The ticket lifetime hint in seconds (resumption only).</summary>
    function TicketLifetime: UInt32;
    /// <summary>The ticket_age_add obfuscator (resumption only).</summary>
    function TicketAgeAdd: UInt32;
    /// <summary>Wall-clock issue time in milliseconds (resumption only; 0 for external).</summary>
    function IssuedAtMillis: UInt64;
  end;

  /// <summary>
  /// The version-agnostic core of a session a client caches or a server stores for
  /// later resumption. The version-specific keying material and ticket fields live on
  /// the <see cref="ITls13ResumableSession" /> / <see cref="ITls12ResumableSession" />
  /// sub-interfaces; a consumer narrows to the one matching <see cref="Version" />.
  /// </summary>
  IResumableSession = interface(IInterface)
    ['{F972F274-932F-4220-95C4-FC2B0D122254}']
    /// <summary>The protocol version this session was established under.</summary>
    function Version: TTlsVersion;
    /// <summary>The negotiated cipher suite.</summary>
    function CipherSuite: UInt16;
    /// <summary>The hash bound to the suite.</summary>
    function Hash: THashAlgorithm;
    /// <summary>The negotiated ALPN protocol, or the empty string.</summary>
    function Alpn: string;
    /// <summary>The SNI host_name the session was established under (empty when none). A server
    /// binds it into the ticket and refuses a resumption whose ClientHello names a different host,
    /// so a ticket issued for one virtual host cannot resume as another.</summary>
    function ServerName: string;
    /// <summary>The ticket lifetime hint in seconds.</summary>
    function TicketLifetime: UInt32;
    /// <summary>Wall-clock issue time in milliseconds.</summary>
    function IssuedAtMillis: UInt64;
    /// <summary>The peer certificate chain verified when this session was established (leaf-first,
    /// as the peer sent it), empty when the peer presented none. A resumed handshake carries no
    /// Certificate, so the endpoint surfaces this stored chain instead; it is NOT re-verified on
    /// resumption.</summary>
    function PeerCertificates: TArray<TBytes>;
    /// <summary>The opaque scope the issuing server configuration sealed into the ticket to
    /// partition resumption across configurations that share a ticket key or store; empty when
    /// none. A server resumes a ticket only when this equals its own configured scope, so a
    /// configuration never resumes a session another established under a different scope. Compared
    /// byte-for-byte, never interpreted.</summary>
    function ResumptionScope: TBytes;
  end;

  /// <summary>
  /// A TLS 1.3 resumable session: the resumption-PSK secret and the ticket fields a
  /// client needs to offer it as a pre_shared_key. Project it to an
  /// <see cref="IPreSharedKey" /> with a plain <c>as</c> cast.
  /// </summary>
  ITls13ResumableSession = interface(IResumableSession)
    ['{9B3DC2B4-29C8-428B-9003-E96F4E1E370A}']
    /// <summary>The resumption PSK secret.</summary>
    function ResumptionSecret: ISecretBuffer;
    /// <summary>The opaque ticket that identifies this session on resumption.</summary>
    function TicketIdentity: TBytes;
    /// <summary>The ticket_age_add obfuscator.</summary>
    function TicketAgeAdd: UInt32;
    /// <summary>The 0-RTT byte budget the ticket authorized (0 = no early data).</summary>
    function MaxEarlyData: UInt32;
  end;

  /// <summary>
  /// A TLS 1.2 resumable session: the master secret, the session id and/or RFC 5077
  /// ticket, and whether Extended Master Secret bound it.
  /// </summary>
  ITls12ResumableSession = interface(IResumableSession)
    ['{5F074730-ECB9-42CB-B889-D1901191A873}']
    /// <summary>The master secret.</summary>
    function MasterSecret: ISecretBuffer;
    /// <summary>The session id (empty when only a ticket is held).</summary>
    function SessionId: TBytes;
    /// <summary>The RFC 5077 session ticket (empty when only a session id is held).</summary>
    function SessionTicket: TBytes;
    /// <summary>Whether Extended Master Secret (RFC 7627) bound the session.</summary>
    function ExtendedMasterSecret: Boolean;
  end;

  /// <summary>
  /// A client-side, bounded cache of resumable sessions keyed by server identity
  /// and SNI. Retrieval is single-use (a ticket is consumed on use), so a client
  /// stores several tickets per server and pops one per resumption. Retrieval
  /// prefers a TLS 1.3 session over a TLS 1.2 one for the same server, so a
  /// dual-version client never downgrades on resumption when a 1.3 ticket is held.
  /// The cache also remembers, per server, the (EC)DHE group the server last
  /// selected (a key-exchange hint) so the next initial ClientHello can lead with
  /// that group and avoid a HelloRetryRequest. The server-identity string a client
  /// passes may carry the client configuration's opaque scope; an implementer must
  /// treat the whole identity as opaque so a cache shared by two configurations
  /// keeps their sessions apart.
  /// </summary>
  ISessionCache = interface(IInterface)
    ['{2E5B9F30-7C41-4A68-9D12-6B0E3F8C4A57}']
    /// <summary>Caches a session under (server identity, SNI), evicting to stay bounded.</summary>
    procedure Store(const AServerIdentity, AServerName: string;
      const ASession: IResumableSession);
    /// <summary>Pops one cached session for (server identity, SNI), preferring a TLS 1.3
    /// session over a TLS 1.2 one; False if none.</summary>
    function Take(const AServerIdentity, AServerName: string;
      out ASession: IResumableSession): Boolean;
    /// <summary>Remembers the (EC)DHE group the server selected for this server, so the
    /// next initial ClientHello can key_share it up front and skip a HelloRetryRequest.</summary>
    procedure SetKxHint(const AServerIdentity, AServerName: string; AGroup: UInt16);
    /// <summary>The remembered (EC)DHE group for this server, or 0 when none is known.</summary>
    function KxHint(const AServerIdentity, AServerName: string): UInt16;
    /// <summary>Drops every cached session.</summary>
    procedure Clear;
    /// <summary>The number of sessions currently cached.</summary>
    function Count: Int32;
  end;

  /// <summary>
  /// A server-side, bounded, stateful store of resumable sessions. A stored
  /// session is addressed by an opaque handle (the ticket blob or a TLS 1.2
  /// session id); retrieval is single-use, which is what enforces true one-time
  /// tickets and backs 0-RTT anti-replay.
  /// </summary>
  ISessionStore = interface(IInterface)
    ['{9C4A7E18-3D60-4B95-8A27-5E1B0F6C2D49}']
    /// <summary>Stores a session under a fresh opaque handle and returns it.</summary>
    function Put(const ASession: IResumableSession): TBytes;
    /// <summary>Stores a session under a caller-chosen id (e.g. a TLS 1.2 session id).</summary>
    procedure PutWithId(const AId: TBytes; const ASession: IResumableSession);
    /// <summary>Removes and returns the session for AId; False if absent (single-use).</summary>
    function Take(const AId: TBytes; out ASession: IResumableSession): Boolean;
    /// <summary>Removes the session for AId if present.</summary>
    procedure Remove(const AId: TBytes);
    /// <summary>Drops every stored session.</summary>
    procedure Clear;
    /// <summary>The number of sessions currently stored.</summary>
    function Count: Int32;
  end;

  /// <summary>
  /// The server's session-ticket encryption keys (STEK): one current key used to
  /// seal new tickets and a bounded window of recent keys still accepted for
  /// opening tickets. Each key is tagged by a fixed-length name carried in the
  /// clear at the front of a ticket so the opener can select it. Rotation
  /// promotes a fresh current key and retires the oldest beyond the window.
  /// </summary>
  ISessionTicketKeyManager = interface(IInterface)
    ['{5F1C8A24-6B39-4D70-9E58-0A2D7C4B6F13}']
    /// <summary>The key name and key to seal a new ticket with; False if none configured.</summary>
    function CurrentKey(out AKeyName: TBytes; out AKey: ISecretBuffer): Boolean;
    /// <summary>The decrypt key for AKeyName within the accepted window; False if unknown/retired.</summary>
    function KeyByName(const AKeyName: TBytes; out AKey: ISecretBuffer): Boolean;
    /// <summary>Promotes a fresh current key and retires the oldest beyond the window.</summary>
    procedure Rotate;
    /// <summary>The fixed length in bytes of a key name.</summary>
    function KeyNameLength: Int32;
  end;

  /// <summary>
  /// The server's ticket strategy: turns a resumable session into the opaque ticket a
  /// client re-presents, and recovers it. The stateless STEK strategy AEAD-seals the
  /// session under a rotating key (no server storage); the stateful store strategy keeps
  /// opaque handles into an <see cref="ISessionStore" /> (true single-use). Open returns
  /// False on any parse/verify/lookup failure, so the server falls through to a full
  /// handshake rather than failing.
  /// </summary>
  ISessionTicketStrategy = interface(IInterface)
    ['{8B2F4D07-6A19-4C53-9E84-3D5A0C7B62F1}']
    /// <summary>Produces the opaque ticket that identifies ASession on resumption.</summary>
    function Seal(const ASession: IResumableSession): TBytes;
    /// <summary>Recovers the session ATicket identifies; False on any failure.</summary>
    function Open(const ATicket: TBytes; out ASession: IResumableSession): Boolean;
  end;

  /// <summary>
  /// A bounded anti-replay register for 0-RTT early data (RFC 8446 8). It records
  /// a per-attempt unique value (accepting it once) and rejects any later attempt
  /// carrying the same value within its freshness window. Bounded by a
  /// configurable cap; entries past their expiry are pruned.
  /// </summary>
  IAntiReplayStrategy = interface(IInterface)
    ['{3B7D0F52-8C46-4A19-9027-6E5A1C4B8D30}']
    /// <summary>
    /// Records AUniqueValue and returns True if it was not seen before (accept the
    /// early data); returns False on a replay or when the register cannot admit it.
    /// ANowMillis prunes expired entries; AExpiryMillis is when this entry lapses.
    /// </summary>
    function CheckAndRecord(const AUniqueValue: TBytes;
      ANowMillis, AExpiryMillis: UInt64): Boolean;
    /// <summary>Drops every recorded value.</summary>
    procedure Clear;
    /// <summary>The number of live entries.</summary>
    function Count: Int32;
  end;

implementation

end.
