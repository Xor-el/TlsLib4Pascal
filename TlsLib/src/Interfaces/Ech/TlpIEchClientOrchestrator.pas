{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpIEchClientOrchestrator;

{$I ..\..\Include\TlsLib.inc}

interface

uses
  SysUtils,
  TlpCryptoDomainTypes,
  TlpITranscriptHash,
  TlpISession,
  TlpHandshakeMessage,
  TlpHandshakeMessages,
  TlpEchConfig;

type
  /// <summary>
  /// The client side of Encrypted Client Hello (RFC 9849), as driven by the 1.3 client state
  /// machine. It resolves a usable config (or GREASE) once at construction and owns the
  /// per-connection ECH state (the sealer, inner random and transcript, the sent inner and
  /// outer-ech bytes, the GREASE-PSK decoys, and the accept/reject verdict).
  ///
  /// It is a "data in, verdict out" collaborator: the machine passes the data it needs (the built
  /// inner hello, the outer random, the offered PSKs) and applies the consequences itself (adopting
  /// the inner transcript and random on accept, or the public_name on reject).
  /// </summary>
  IEchClientOrchestrator = interface(IInterface)
    ['{6D9A2F14-8C53-4E71-A0B6-2F7C1D5E3A48}']
    /// <summary>Creates the inner transcript before the inner ClientHello is built (a single
    /// offered PSK pre-activates it so its binder MACs the inner history).</summary>
    procedure PrepareInnerTranscript(APreActivated: Boolean; AHash: THashAlgorithm);
    /// <summary>Builds the ClientHelloOuter for AMode from the already-built, binder-patched inner
    /// hello AInnerFramed (also recorded as SentInnerRaw), the outer random and session id, and the
    /// offered PSKs (whose count/lengths the GREASE decoy mirrors).</summary>
    function BuildClientHelloOuter(AMode: TEchChMode; const AInnerFramed, AOuterRandom,
      ALegacySessionId: TBytes; const APskOffers: TArray<IPreSharedKey>): TBytes;
    /// <summary>Decides ECH accept vs reject from the ServerHello accept confirmation (RFC 9849
    /// sec. 7.2): activates/rebuilds only the inner transcript under AHash, checks the confirmation
    /// on a clone, cross-checks any HelloRetryRequest verdict, sets Status, returns True on accept.
    /// It does NOT append the ServerHello to any transcript - the machine adopts the inner
    /// transcript and random on accept, or the public_name on reject, and appends it itself.</summary>
    function DecideServerHello(const AServerHelloRaw, AServerRandom: TBytes;
      AHash: THashAlgorithm; ARebuildInnerUnderHash: Boolean): Boolean;
    /// <summary>On a HelloRetryRequest under ECH: decides accept/reject from the HRR ech accept
    /// confirmation and rebases the inner transcript to message_hash(Hash(innerCH1)), HRR.</summary>
    procedure DecideHelloRetryRequest(const AHello: TTlsServerHello;
      const AMessage: TTlsHandshakeMessage; AHash: THashAlgorithm);
    /// <summary>Under GREASE, validate the HelloRetryRequest ech syntactically without acting on
    /// it: a present-but-not-8-byte ech is a decode_error (RFC 9849 sec. 6.2.1).</summary>
    procedure NoteHelloRetryRequestGrease(const ARaw: TBytes);
    /// <summary>Applies the EncryptedExtensions ech rule: unsolicited on accept
    /// (unsupported_extension), retry_configs captured on reject (unless this was a retry),
    /// validated-and-ignored under GREASE.</summary>
    procedure NoteEncryptedExtensions(const AEeBody: TBytes);
    /// <summary>Prunes the GREASE-PSK decoys to the surviving offer indices, keeping them
    /// index-aligned with the machine's pruned pre_shared_key offers across a HelloRetryRequest.</summary>
    procedure KeepPskDecoys(const AKeptIndices: TArray<Int32>);
    function Active: Boolean;
    function Grease: Boolean;
    function Status: TEchStatus;
    function RetryConfigs: TBytes;
    function HrrAccepted: Boolean;
    function HrrDecided: Boolean;
    function InnerRandom: TBytes;
    function InnerTranscript: ITranscriptHash;
    function SentInnerRaw: TBytes;
    function GreaseEchExt: TBytes;
    /// <summary>The inner-type ech marker for the inner ClientHello (symmetric with GreaseEchExt).</summary>
    function InnerEchExt: TBytes;
    /// <summary>The selected config's public_name (the ClientHelloOuter SNI / reject identity).</summary>
    function PublicName: string;
  end;

implementation

end.
