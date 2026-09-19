{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpIKeySchedule;

{$I ..\..\Include\TlsLib.inc}

interface

uses
  SysUtils,
  TlpISecretBuffer;

type
  /// <summary>A protection epoch, in the order keys become available.</summary>
  TTlsEpoch = (EarlyData, Handshake, Application);

  /// <summary>
  /// Which binder label a pre_shared_key derives its binder key under (RFC 8446 7.1,
  /// RFC 9258 6): a resumption ticket uses "res binder", a raw out-of-band external PSK
  /// uses "ext binder", and an RFC 9258 imported external PSK uses "imp binder". The
  /// three labels domain-separate the binder so a key provisioned for one role cannot be
  /// replayed in another.
  /// </summary>
  TPskBinderKind = (Resumption, External, Imported);

  /// <summary>Which peer's write keys a derivation refers to.</summary>
  TTlsDirection = (ClientWrite, ServerWrite);

  /// <summary>
  /// The (key, iv) a schedule derived for one epoch and direction, ready to build
  /// an IRecordProtection. Both are held as secret buffers.
  /// </summary>
  ITrafficKeys = interface(IInterface)
    ['{A6F4B0C2-3E71-4D95-8B26-0C7A1E5F93D4}']
    function Key: ISecretBuffer;
    function Iv: ISecretBuffer;
  end;

  /// <summary>
  /// The version-agnostic surface a schedule exposes once its secrets exist: the
  /// per-direction traffic keys, the Finished verify_data, and exported keying
  /// material. A record-layer installer or a Finished handler uses this without
  /// knowing the negotiated version; the inputs and derivation are version-specific.
  /// </summary>
  IKeySchedule = interface(IInterface)
    ['{2F8D5A16-9C43-4E70-B1A8-6D0E2C7F84B5}']
    /// <summary>
    /// The (key, iv) for an already-derived epoch and direction. Every version has
    /// an Application epoch; a schedule rejects an epoch it never derives.
    /// </summary>
    function TrafficKeys(AEpoch: TTlsEpoch; ADirection: TTlsDirection): ITrafficKeys;
    /// <summary>The Finished verify_data over the transcript hash, for a direction.</summary>
    function ComputeVerifyData(ADirection: TTlsDirection;
      const ATranscriptHash: TBytes): TBytes;
    /// <summary>Constant-time check of a peer's verify_data against the expected.</summary>
    function VerifyFinished(ADirection: TTlsDirection;
      const ATranscriptHash, APeerVerifyData: TBytes): Boolean;
    /// <summary>Exported keying material (RFC 8446 7.5 / RFC 5705). AUseContext
    /// distinguishes a supplied (possibly empty) context from no context at all: in TLS 1.2
    /// an empty-but-present context contributes a zero-length block to the seed while no
    /// context contributes nothing, which produce different output (RFC 5705 4).</summary>
    function ExportKeyingMaterial(const ALabel: string; const AContext: TBytes;
      AUseContext: Boolean; ALength: Int32): TBytes;
  end;

  /// <summary>
  /// The TLS 1.3 key schedule (RFC 8446 7.1): the HKDF Early -> Handshake -> Master
  /// tree, epoch traffic secrets derived from a transcript hash, the per-direction
  /// Finished key, KeyUpdate, and the resumption master secret. The schedule
  /// derives; a driver installs the results into the record layer.
  /// </summary>
  ITls13KeySchedule = interface(IKeySchedule)
    ['{7C3A9E12-4F85-4B60-A1D9-2E6C0B5F84A7}']
    /// <summary>Sets the pre-shared key (omit for a 0-PSK handshake).</summary>
    procedure SetPsk(const APsk: ISecretBuffer);
    /// <summary>Sets the (EC)DHE shared secret.</summary>
    procedure SetSharedSecret(const ASharedSecret: ISecretBuffer);
    /// <summary>
    /// Derives and caches an epoch's traffic secrets from the transcript hash at
    /// that point (up to ServerHello for Handshake, up to the server Finished for
    /// Application).
    /// </summary>
    procedure DeriveEpochSecrets(AEpoch: TTlsEpoch; const ATranscriptHash: TBytes);
    /// <summary>The Finished key for the handshake traffic secret of a direction.</summary>
    function FinishedKey(ADirection: TTlsDirection): ISecretBuffer;
    /// <summary>Advances the application traffic secret one generation (KeyUpdate).</summary>
    procedure AdvanceKeyUpdate(ADirection: TTlsDirection);
    /// <summary>Whether the exporter_master_secret has been derived (RFC 8446 7.5): true once
    /// the Application epoch secrets are derived - for a server that is half-RTT (after it has
    /// sent its Finished), before the peer's Finished.</summary>
    function HasExporterSecret: Boolean;
    /// <summary>The resumption master secret from the ClientHello..client Finished hash.</summary>
    function ResumptionMasterSecret(const ATranscriptHash: TBytes): ISecretBuffer;
    /// <summary>
    /// The per-ticket resumption PSK (RFC 8446 4.6.1):
    /// HKDF-Expand-Label(resumption_master_secret, "resumption", ticket_nonce).
    /// </summary>
    function ResumptionPsk(const ATranscriptHash, ATicketNonce: TBytes): ISecretBuffer;
    /// <summary>
    /// The PSK binder key (RFC 8446 7.1): Derive-Secret(early_secret, AKind's label, "").
    /// AKind selects the binder label ("res binder" / "ext binder" / "imp binder").
    /// Requires the PSK to have been set.
    /// </summary>
    function BinderKey(AKind: TPskBinderKind): ISecretBuffer;
    /// <summary>
    /// The PSK binder verify_data: HMAC(finished_key, ATruncatedTranscriptHash),
    /// where finished_key derives from the binder key and the hash is taken over
    /// the ClientHello up to (excluding) the binders list (RFC 8446 4.2.11.2).
    /// </summary>
    function ComputeBinder(AKind: TPskBinderKind;
      const ATruncatedTranscriptHash: TBytes): TBytes;
    /// <summary>Constant-time check of a peer's binder against the expected value.</summary>
    function VerifyBinder(AKind: TPskBinderKind;
      const ATruncatedTranscriptHash, APeerBinder: TBytes): Boolean;
  end;

  /// <summary>
  /// The TLS 1.2 key schedule (RFC 5246 6.3 / RFC 7627): the PRF-derived master
  /// secret (plain or Extended Master Secret) and the key_block split into the
  /// AEAD write keys and salts. verify_data and the traffic keys are read back
  /// through the base IKeySchedule surface.
  /// </summary>
  ITls12KeySchedule = interface(IKeySchedule)
    ['{3D8B1F60-5A24-4C93-8E17-9B0A6D2F45C8}']
    /// <summary>Sets the pre-master secret (the (EC)DHE shared secret for ECDHE suites).</summary>
    procedure SetPreMasterSecret(const APreMasterSecret: ISecretBuffer);
    /// <summary>Installs a stored master secret directly, for an abbreviated (resumption)
    /// handshake that reuses it: the caller sets the new randoms and calls DeriveKeyBlock,
    /// skipping the pre-master secret and master-secret derivation entirely.</summary>
    procedure SetMasterSecret(const AMasterSecret: ISecretBuffer);
    /// <summary>Sets the client and server randoms used as PRF seeds.</summary>
    procedure SetRandoms(const AClientRandom, AServerRandom: TBytes);
    /// <summary>master_secret = PRF(pms, "master secret", client_random+server_random).</summary>
    procedure DeriveMasterSecret;
    /// <summary>master_secret = PRF(pms, "extended master secret", session_hash) (RFC 7627).</summary>
    procedure DeriveExtendedMasterSecret(const ASessionHash: TBytes);
    /// <summary>key_block = PRF(master, "key expansion", server_random+client_random), split.</summary>
    procedure DeriveKeyBlock;
    /// <summary>The derived (or installed) master secret, for a session an endpoint
    /// persists to resume later; nil before it exists.</summary>
    function MasterSecret: ISecretBuffer;
  end;

implementation

end.
