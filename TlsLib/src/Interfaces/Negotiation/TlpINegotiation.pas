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
  TlpCryptoAlgorithms,
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
  /// Pure negotiation: given the client's offered lists, choose the version, cipher
  /// suite, group, and signature scheme, or raise the correct fatal alert. The
  /// server selects; the client uses the same policy to confirm the server chose
  /// only from what was offered. No state, no side effects.
  /// </summary>
  INegotiationPolicy = interface(IInterface)
    ['{2D8F5A16-4C93-4E70-B1A8-6D0E2C7F85B4}']
    function SelectVersion(const AClientVersions: TArray<UInt16>): UInt16;
    /// <summary>Chooses a cipher suite among those registered for ANegotiatedVersion,
    /// so a dual-version registry never offers a 1.2 suite on a 1.3 handshake.</summary>
    function SelectCipherSuite(const AClientSuites: TArray<UInt16>;
      ANegotiatedVersion: UInt16): UInt16;
    /// <summary>Chooses a named group; for TLS 1.2 only classical ECDHE groups are
    /// eligible (KEM and hybrid groups are 1.3-only).</summary>
    function SelectGroup(const AClientGroups: TArray<UInt16>;
      ANegotiatedVersion: UInt16): UInt16;
    function SelectSignatureScheme(const AClientSchemes: TArray<UInt16>): UInt16;
  end;

implementation

end.
