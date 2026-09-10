{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpIEch;

{$I ..\..\Include\TlsLib.inc}

interface

uses
  SysUtils,
  TlpISecretBuffer,
  TlpEchOuterExtensions,
  TlpEchConfig;

type
  /// <summary>
  /// The client's frozen Encrypted Client Hello policy (RFC 9849): the parsed
  /// ECHConfigList to offer, whether GREASE ECH is enabled, and whether this handshake
  /// is a retry after an earlier reject (the one-retry cap of sec. 6.1.6). Immutable and
  /// shared lock-free.
  /// </summary>
  IEchClientPolicy = interface(IInterface)
    ['{9E1B7A34-5C82-46D0-A1F7-3B6E8C2D4059}']
    /// <summary>The parsed ECHConfigList (in decreasing order of preference); empty when
    /// only GREASE is configured.</summary>
    function Configs: TArray<TEchConfig>;
    /// <summary>Whether to send a GREASE ECH when no config is usable (RFC 9849 sec. 6.2).</summary>
    function GreaseEnabled: Boolean;
    /// <summary>Whether this handshake already follows an earlier ECH reject; a further
    /// reject then does not chain another retry.</summary>
    function IsRetryAttempt: Boolean;
  end;

  /// <summary>
  /// The server's Encrypted Client Hello key store (RFC 9849 sec. 4.5 / RFC 9934):
  /// app-driven, immutable once frozen, holding the currently valid config/private-key
  /// entries and the retry_configs to advertise on reject. The operator manages validity
  /// out of band. Shared lock-free; the operator swaps the whole store to rotate keys.
  /// </summary>
  IEchServerKeyStore = interface(IInterface)
    ['{5D2F8B10-7A64-4E39-9C81-2B6E0D5A3F47}']
    /// <summary>The valid entries (config + private key), in preference order. The server
    /// trial-decrypts against those whose config_id matches, or against all when trial
    /// decryption is enabled.</summary>
    function Entries: TArray<TEchKeyEntry>;
    /// <summary>The retry_configs advertised on an ECH reject: an ECHConfigList of the
    /// entries flagged is_retry, in preference order. A server that holds any ECH keys MUST
    /// advertise retry_configs on a reject (RFC 9849 sec. 7.1), so an implementation whose
    /// Entries is non-empty must return a non-empty list here; TInMemoryEchKeyStore enforces
    /// this at construction.</summary>
    function RetryConfigs: TBytes;
  end;

  /// <summary>
  /// The client side of one connection's Encrypted Client Hello (RFC 9849): seals the
  /// ClientHelloInner under the selected config and assembles the EncodedClientHelloInner
  /// with its compressed outer_extensions. One instance per connection; carries the HPKE
  /// sender context (reused with an empty enc across a HelloRetryRequest).
  /// </summary>
  IEchClientHandshake = interface(IInterface)
    ['{7C3E9A15-4D82-4F60-9B18-2E6C0D5A3F84}']
    /// <summary>The EncodedClientHelloInner for AInnerBody: the inner extensions replaced by an
    /// ech_outer_extensions block referencing the outer, padded per RFC 9849 sec. 6.1.3.</summary>
    function BuildEncodedInner(const AInnerBody: TBytes;
      const AOuterEntries: TArray<TEchExtEntry>): TBytes;
    /// <summary>Sets up the HPKE sender against the selected config and returns the enc.</summary>
    function SetupSeal: TBytes;
    /// <summary>Seals APlaintext under the ClientHelloOuterAAD AAad at the current sequence.</summary>
    function Seal(const AAad, APlaintext: TBytes): TBytes;
  end;

  /// <summary>
  /// The server side of one connection's Encrypted Client Hello (RFC 9849): trial-decrypts the
  /// ClientHelloOuter, reconstructs the ClientHelloInner, and carries the HPKE recipient context
  /// (reused across a HelloRetryRequest). One instance per connection.
  /// </summary>
  IEchServerHandshake = interface(IInterface)
    ['{2B8D4F60-6A13-4E59-9C82-5D6E0B3A1F47}']
    /// <summary>Trial-decrypts the ClientHelloOuter AOuterFramed: Accepted (inner reconstructed),
    /// Rejected (serve the public_name), or NotOffered / Backend.</summary>
    function ProcessOuter(const AOuterFramed: TBytes): TEchStatus;
    /// <summary>Decrypts the retry ClientHelloOuter (seq 1, empty enc) after an accepted CH1.</summary>
    function ProcessRetryOuter(const AOuterFramed: TBytes): TEchStatus;
    /// <summary>The reconstructed inner ClientHello, framed as a handshake message.</summary>
    function InnerFramed: TBytes;
    /// <summary>The inner ClientHello's random, cross-checked against CH2 under HRR.</summary>
    function InnerRandom: TBytes;
  end;

implementation

end.
