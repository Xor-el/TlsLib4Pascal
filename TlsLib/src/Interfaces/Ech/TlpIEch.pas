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
  TlpICryptoProvider,
  TlpExtensionVector,
  TlpHandshakeMessages,
  TlpEchConfig;

type
  /// <summary>
  /// The client's frozen Encrypted Client Hello policy (RFC 9849): the parsed
  /// ECHConfigList to offer, whether GREASE ECH is enabled, and whether this handshake
  /// is a retry after an earlier reject (the one-retry cap of sec. 6.1.6). Immutable and
  /// shared lock-free.
  /// </summary>
  IEchClientPolicy = interface(IInterface)
    ['{5E379F43-A271-47AA-A1DB-01BC7B86900A}']
    /// <summary>Whether to send a GREASE ECH when no config is usable (RFC 9849 sec. 6.2).</summary>
    function GreaseEnabled: Boolean;
    /// <summary>Whether this handshake already follows an earlier ECH reject; a further
    /// reject then does not chain another retry.</summary>
    function IsRetryAttempt: Boolean;
    /// <summary>Whether a usable (config, HPKE suite) was resolved once at Build; when False the
    /// client offers GREASE (if enabled) or the config fails at Build.</summary>
    function Usable: Boolean;
    /// <summary>The config resolved at Build (valid only when Usable).</summary>
    function SelectedConfig: TEchConfig;
    /// <summary>The HPKE suite resolved at Build (valid only when Usable).</summary>
    function SelectedSuite: IHpkeSuite;
  end;

  /// <summary>
  /// The server's Encrypted Client Hello key store (RFC 9849 sec. 4.1 / RFC 9934):
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
  /// The server side of one connection's Encrypted Client Hello (RFC 9849): trial-decrypts the
  /// ClientHelloOuter, reconstructs the ClientHelloInner, and carries the HPKE recipient context
  /// (reused across a HelloRetryRequest). One instance per connection.
  /// </summary>
  IEchServerHandshake = interface(IInterface)
    ['{5EE8D115-D01C-40CE-A12D-D4D7955C3442}']
    /// <summary>Trial-decrypts the ClientHelloOuter AOuterFramed, reusing the outer the caller
    /// already decoded (AOuter) and vector-parsed (AOuterEntries): Accepted (inner reconstructed),
    /// Rejected (serve the public_name), or NotOffered / Backend.</summary>
    function ProcessOuter(const AOuterFramed: TBytes; const AOuter: TTlsClientHello;
      const AOuterEntries: TExtensionVector): TEchStatus;
    /// <summary>Decrypts the retry ClientHelloOuter (seq 1, empty enc) after an accepted CH1.
    /// Precondition: the first ClientHelloOuter was accepted (ProcessOuter returned Accepted);
    /// calling it otherwise is a programming error and raises.</summary>
    function ProcessRetryOuter(const AOuterFramed: TBytes): TEchStatus;
    /// <summary>The reconstructed inner ClientHello, framed as a handshake message; a copy, since
    /// the handshake wipes its own buffer on release.</summary>
    function InnerFramed: TBytes;
    /// <summary>The inner ClientHello's random (a copy), cross-checked against CH2 under HRR.</summary>
    function InnerRandom: TBytes;
  end;

implementation

end.
