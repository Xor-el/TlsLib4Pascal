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
  ICipherSuiteRegistryBuilder = interface;
  ISignatureSchemeRegistryBuilder = interface;

  /// <summary>
  /// The enabled TLS 1.3 cipher suites, in server-preference order. Immutable: a frozen config
  /// holds it as is. To prune an entry to harden a profile or add one for a new suite, start from
  /// ToBuilder and build a new registry. Every entry is validated against provider capability when
  /// the default set is built.
  /// </summary>
  ICipherSuiteRegistry = interface(IInterface)
    ['{6E2A9C14-5F73-4B80-A1D6-3C7E0B4F82A9}']
    function Items: TArray<TTlsCipherSuite>;
    function Contains(ACode: UInt16): Boolean;
    function TryGet(ACode: UInt16; out ASuite: TTlsCipherSuite): Boolean;
    /// <summary>A builder holding this registry's entries, for deriving a changed registry.</summary>
    function ToBuilder: ICipherSuiteRegistryBuilder;
  end;

  /// <summary>Assembles a cipher-suite registry; Build snapshots the entries and refuses a record
  /// that differs from the catalog entry for its code.</summary>
  ICipherSuiteRegistryBuilder = interface(IInterface)
    ['{367573DA-4CFD-4342-8605-47EBA95E6069}']
    /// <summary>Appends ASuite unless its code is already present.</summary>
    procedure Add(const ASuite: TTlsCipherSuite);
    /// <summary>Removes the suite with ACode, if any.</summary>
    procedure Prune(ACode: UInt16);
    function Build: ICipherSuiteRegistry;
  end;

  /// <summary>The enabled signature schemes, in server-preference order (immutable).</summary>
  ISignatureSchemeRegistry = interface(IInterface)
    ['{9A4C1E28-7D50-4F63-8B17-2E6A0C5F94D8}']
    function Items: TArray<TSignatureScheme>;
    function Contains(ACode: UInt16): Boolean;
    function TryGet(ACode: UInt16; out AScheme: TSignatureScheme): Boolean;
    /// <summary>A builder holding this registry's entries, for deriving a changed registry.</summary>
    function ToBuilder: ISignatureSchemeRegistryBuilder;
  end;

  /// <summary>Assembles a signature-scheme registry; Build snapshots the entries.</summary>
  ISignatureSchemeRegistryBuilder = interface(IInterface)
    ['{143A1E4C-42AB-4F72-8342-AE929D990D6E}']
    /// <summary>Appends AScheme unless its code is already present.</summary>
    procedure Add(const AScheme: TSignatureScheme);
    /// <summary>Removes the scheme with ACode, if any.</summary>
    procedure Prune(ACode: UInt16);
    function Build: ISignatureSchemeRegistry;
  end;

  /// <summary>
  /// The server's pure negotiation authority: given the client's offered lists, choose the
  /// version, cipher suite and (EC)DHE group (or raise the correct fatal alert). Both the TLS 1.3
  /// and TLS 1.2 servers route version, suite and group selection through this policy, so the
  /// configured cipher preference governs both versions; a resumption ticket instead pins its own
  /// suite, and a low-level sans-IO caller may pin a single group. The signature scheme is not
  /// chosen here: a server signs with the first of its credential's capable schemes the client
  /// offered. No state, no side effects.
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
    /// RFC 9846 4.3.11); False when none qualifies so the caller can fall through to
    /// another PSK or to certificate authentication.</summary>
    function TrySelectCipherSuiteWithHash(const AClientSuites: TArray<UInt16>;
      ANegotiatedVersion: UInt16; AHash: THashAlgorithm; out ASuite: UInt16): Boolean;
    /// <summary>Chooses a named group by server preference order among the client's
    /// supported_groups; handshake_failure when none is shared. The client's key shares never steer
    /// the choice (server-preference policy; RFC 9846 4.2.1) - the caller retries with a HelloRetryRequest when the chosen
    /// group has no share (4.2.1). For TLS 1.2 only classical ECDHE groups are eligible (KEM and
    /// hybrid groups are 1.3-only).</summary>
    function SelectGroup(const AClientGroups: TArray<UInt16>;
      ANegotiatedVersion: UInt16): UInt16;
  end;

implementation

end.
