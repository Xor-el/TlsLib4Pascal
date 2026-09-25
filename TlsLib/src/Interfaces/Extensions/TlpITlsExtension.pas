{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpITlsExtension;

{$I ..\..\Include\TlsLib.inc}

interface

uses
  SysUtils,
  TlpExtensionContext,
  TlpExtensionVector;

type
  /// <summary>
  /// One self-contained extension codec. ExtensionType is its 2-byte code;
  /// ValidContexts the messages it may appear in; Produce serializes its body from
  /// the shared context (returning False to omit it for this message) and Consume
  /// parses its body into the shared context. Adding an extension is one registry
  /// entry with no change to the codec.
  /// </summary>
  ITlsExtension = interface(IInterface)
    ['{1F7A4C82-3E56-4D90-B1A7-6C0E2D5F84B9}']
    function ExtensionType: UInt16;
    function ValidContexts: TTlsExtensionContexts;
    function Produce(const AContext: TExtensionContext; out ABody: TBytes): Boolean;
    procedure Consume(const AContext: TExtensionContext; const AExtensionData: TBytes);
  end;

  /// <summary>
  /// The injectable set of extensions the codec drives. Keyed by extension type;
  /// pruning an entry removes that extension from both production and recognition
  /// (unknown-skip then applies).
  /// </summary>
  IExtensionRegistry = interface(IInterface)
    ['{7C2E5A18-9D43-4F60-8B71-3A6C0E4F92D5}']
    /// <summary>All registered extensions, in registration order (production order).</summary>
    function Items: TArray<ITlsExtension>;
    /// <summary>Whether an extension with AExtensionType is registered.</summary>
    function Contains(AExtensionType: UInt16): Boolean;
    /// <summary>The extension registered for AExtensionType; False when none.</summary>
    function TryGet(AExtensionType: UInt16; out AExtension: ITlsExtension): Boolean;
    /// <summary>Registers AExtension unless its type is already present.</summary>
    procedure Add(const AExtension: ITlsExtension);
    /// <summary>Removes the extension registered for AExtensionType, if any.</summary>
    procedure Prune(AExtensionType: UInt16);
  end;

  /// <summary>
  /// Serializes and parses a message's extensions vector, driving the injectable
  /// registry and enforcing the RFC 8446 4.2 rules (duplicate/wrong-context/unknown).
  /// </summary>
  IExtensionBlockCodec = interface(IInterface)
    ['{5F1B8C46-2A70-4E39-9C82-7D5A3E1F6B04}']
    /// <summary>Serializes the extensions vector for AKind from the shared context.</summary>
    function ProduceBlock(const AContext: TExtensionContext;
      AKind: TTlsExtensionContextKind): TBytes;
    /// <summary>Parses an extensions vector for AKind, applying the 4.2 rules.</summary>
    procedure ConsumeBlock(const AContext: TExtensionContext;
      AKind: TTlsExtensionContextKind; const ABlock: TBytes); overload;
    /// <summary>Applies the 4.2 rules to an already-parsed vector, so a caller that has
    /// parsed the block for another purpose need not walk it again.</summary>
    procedure ConsumeBlock(const AContext: TExtensionContext;
      AKind: TTlsExtensionContextKind; const AVector: TExtensionVector); overload;
  end;

implementation

end.
