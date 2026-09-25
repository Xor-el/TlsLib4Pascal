{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpINegotiation;

{$I ..\..\Include\TlsLib.inc}

interface

uses
  TlpCryptoDomainTypes,
  TlpNegotiationTypes;

type
  /// <summary>
  /// The enabled TLS 1.3 cipher suites, in server-preference order. Injectable:
  /// prune an entry to harden a profile, add one for a new suite. Every entry is
  /// validated against provider capability when the default set is built.
  /// </summary>
  ICipherSuiteRegistry = interface(IInterface)
    ['{6E2A9C14-5F73-4B80-A1D6-3C7E0B4F82A9}']
    function Items: TArray<TTlsCipherSuite>;
    function Contains(ACode: UInt16): Boolean;
    function TryGet(ACode: UInt16; out ASuite: TTlsCipherSuite): Boolean;
    procedure Add(const ASuite: TTlsCipherSuite);
    procedure Prune(ACode: UInt16);
  end;

  /// <summary>The enabled signature schemes, in server-preference order (injectable).</summary>
  ISignatureSchemeRegistry = interface(IInterface)
    ['{9A4C1E28-7D50-4F63-8B17-2E6A0C5F94D8}']
    function Items: TArray<TSignatureScheme>;
    function Contains(ACode: UInt16): Boolean;
    function TryGet(ACode: UInt16; out AScheme: TSignatureScheme): Boolean;
    procedure Add(const AScheme: TSignatureScheme);
    procedure Prune(ACode: UInt16);
  end;

  /// <summary>
  /// The server's pure negotiation authority: given the client's offered lists,
  /// choose the version, cipher suite, and group, or raise the correct fatal alert.
  /// Every server-side suite pick (certificate and PSK paths alike) goes through
  /// this policy, so the configured cipher preference applies uniformly. The
  /// signature scheme is not chosen here: a server signs with the first of its
  /// credential's capable schemes the client offered. No state, no side effects.
  /// </summary>
  INegotiationPolicy = interface(IInterface)
    ['{A3F1C7D8-5E24-4B69-8D07-2C9E6F4B1A35}']
    function SelectVersion(const AClientVersions: TArray<UInt16>): UInt16;
    /// <summary>The mutually supported suites registered for ANegotiatedVersion, in the
    /// configured preference order (the server's order, or the client's order filtered
    /// to what the server supports). Empty when nothing is shared. A dual-version
    /// registry never yields a 1.2 suite for a 1.3 handshake.</summary>
    function CandidateSuites(const AClientSuites: TArray<UInt16>;
      ANegotiatedVersion: UInt16): TArray<UInt16>;
    /// <summary>The first candidate suite, or handshake_failure when none is shared.</summary>
    function SelectCipherSuite(const AClientSuites: TArray<UInt16>;
      ANegotiatedVersion: UInt16): UInt16;
    /// <summary>The first candidate suite whose hash is AHash (a PSK binds the suite hash,
    /// RFC 8446 4.2.11); False when none qualifies so the caller can fall through to
    /// another PSK or to certificate authentication.</summary>
    function TrySelectCipherSuiteWithHash(const AClientSuites: TArray<UInt16>;
      ANegotiatedVersion: UInt16; AHash: THashAlgorithm; out ASuite: UInt16): Boolean;
    /// <summary>Chooses a named group; for TLS 1.2 only classical ECDHE groups are
    /// eligible (KEM and hybrid groups are 1.3-only).</summary>
    function SelectGroup(const AClientGroups: TArray<UInt16>;
      ANegotiatedVersion: UInt16): UInt16;
  end;

implementation

end.
