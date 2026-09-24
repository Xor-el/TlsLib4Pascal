{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpITranscriptHash;

{$I ..\..\Include\TlsLib.inc}

interface

uses
  SysUtils,
  TlpICryptoProvider;

type
  /// <summary>
  /// The running hash of the handshake transcript (RFC 8446 4.4.1). Messages are
  /// fed in the exact wire bytes as they are sent or received; CurrentHash is the
  /// digest of everything fed so far. The boundary invariant: a signature or MAC
  /// is taken over the transcript EXCLUDING the message being produced, while key
  /// derivations include it - callers snapshot with CurrentHash at the right
  /// boundary and Clone to branch (e.g. a truncated prefix for the PSK binder).
  ///
  /// Because the hash algorithm is not known until the cipher suite is selected in
  /// ServerHello, the transcript can start deferred - buffering the early messages
  /// (ClientHello, an optional HelloRetryRequest) until Activate replays them into
  /// the chosen hash.
  /// </summary>
  ITranscriptHash = interface(IInterface)
    ['{6B2E9F14-7A50-4C38-9D61-4E8A0C7B25F3}']
    /// <summary>Feeds a whole message's wire bytes into the transcript.</summary>
    procedure Update(const AData: TBytes); overload;
    /// <summary>Feeds ALength bytes of AData starting at AOffset.</summary>
    procedure Update(const AData: TBytes; AOffset, ALength: Int32); overload;

    /// <summary>Picks the hash and replays any buffered messages into it.</summary>
    procedure Activate(const AHash: IHash);
    /// <summary>Whether a hash has been selected (False while still deferred).</summary>
    function IsActive: Boolean;

    /// <summary>
    /// Restarts the transcript from AFreshHash, seeded with the synthetic
    /// Handshake(message_hash, ACh1Hash) that replaces ClientHello1 after a
    /// HelloRetryRequest (RFC 8446 4.4.1). Discards any prior state or deferred buffer.
    /// </summary>
    procedure SeedWithMessageHash(const AFreshHash: IHash; const ACh1Hash: TBytes);

    /// <summary>A snapshot digest of the transcript so far (leaves the running state intact).</summary>
    function CurrentHash: TBytes;
    /// <summary>
    /// The digest of the transcript so far followed by APartialClientHello, without
    /// disturbing the running state - the PSK binder MAC covers the ClientHello up
    /// to (excluding) the binders list (RFC 8446 4.2.11.2).
    /// </summary>
    function HashPrefixExcludingBinders(const APartialClientHello: TBytes): TBytes;
    /// <summary>The digest size in bytes (0 while deferred).</summary>
    function HashSize: Int32;
    /// <summary>An independent branch at the current state.</summary>
    function Clone: ITranscriptHash;
  end;

implementation

end.
