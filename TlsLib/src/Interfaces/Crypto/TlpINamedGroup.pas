{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpINamedGroup;

{$I ..\..\Include\TlsLib.inc}

interface

uses
  SysUtils,
  TlpCryptoDomainTypes,
  TlpISecretBuffer;

type
  /// <summary>
  /// A key-exchange group in a uniform KEM shape over classical, post-quantum,
  /// and hybrid constructions. Classical ECDHE is wrapped as a KEM (the
  /// ciphertext is the responder's ephemeral share); ML-KEM is a KEM directly;
  /// a hybrid is a combinator over two. Incoming peer shares are validated
  /// before use.
  /// </summary>
  INamedGroup = interface(IInterface)
    ['{2EBC7B08-44E0-4664-A3A2-B43C2A9B7492}']
    /// <summary>The group's wire codepoint (RFC 8446 4.2.7 NamedGroup).</summary>
    function Code: UInt16;
    /// <summary>The group's registered name (e.g. "X25519").</summary>
    function Name: string;
    /// <summary>
    /// The group's key-exchange kind. Negotiation uses it to exclude Kem and
    /// Hybrid groups from a TLS 1.2 handshake (1.2 allows only classical ECDHE).
    /// </summary>
    function Kind: TNamedGroupKind;

    /// <summary>
    /// Produces a fresh key pair: the private key and the public share to send.
    /// </summary>
    procedure GenerateKeyPair(out APriv: ISecretBuffer; out APubShare: TBytes);

    /// <summary>
    /// Against a peer's public share, produces the ciphertext to send back and
    /// the agreed shared secret.
    /// </summary>
    procedure Encapsulate(const APeerPub: TBytes; out ACiphertext: TBytes;
      out ASharedSecret: ISecretBuffer);

    /// <summary>
    /// From the private key and the peer's ciphertext, recovers the shared
    /// secret.
    /// </summary>
    procedure Decapsulate(const APriv: ISecretBuffer; const ACiphertext: TBytes;
      out ASharedSecret: ISecretBuffer);

    /// <summary>Whether a peer's public share is well-formed and safe to use.</summary>
    function ValidatePeerShare(const AShare: TBytes): Boolean;
  end;

  /// <summary>
  /// An injectable registry of named groups, keyed by wire codepoint; entries can
  /// be pruned to harden a profile or added for a new group without touching the
  /// core.
  /// </summary>
  INamedGroupRegistry = interface(IInterface)
    ['{BF4ACB64-108E-488F-BF30-C49DCF140421}']
    /// <summary>All registered groups, in insertion order.</summary>
    function Items: TArray<INamedGroup>;
    /// <summary>Whether a group with ACode is registered.</summary>
    function Contains(ACode: UInt16): Boolean;
    /// <summary>The group registered for ACode; False (AGroup nil) when none.</summary>
    function TryGet(ACode: UInt16; out AGroup: INamedGroup): Boolean;
    /// <summary>Registers AGroup unless its code is already present.</summary>
    procedure Add(const AGroup: INamedGroup);
    /// <summary>Removes the group registered for ACode, if any.</summary>
    procedure Prune(ACode: UInt16);
  end;

implementation

end.
