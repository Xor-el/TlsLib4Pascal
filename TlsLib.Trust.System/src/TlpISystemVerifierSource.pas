{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpISystemVerifierSource;

{$I ..\..\TlsLib\src\Include\TlsLib.inc}

interface

uses
  SysUtils;

type
  /// <summary>The roots facet of the OS verifier source: the server-role roots and distrust set,
  /// so the live re-check builds against the same ones as the inline pass. The source class
  /// lists it, but any class can, so a config check judges the class, not this interface. A
  /// stapled revocation response may be decided by the configured PKIX provider instead of the OS.
  /// All three are empty for a client-only source.</summary>
  ISystemVerifierSource = interface(IInterface)
    ['{0DE1F07C-D1E4-41A9-BF68-5F115CDA14C9}']
    /// <summary>The exclusive server trust root (empty = the OS roots apply).</summary>
    function Anchors: TArray<TBytes>;
    /// <summary>Host roots trusted with the OS roots.</summary>
    function ExtraAnchors: TArray<TBytes>;
    /// <summary>The distrust set the source was built with (the host's, plus the OS list where the
    /// platform exposes one and the factory read it), refused on any accepted path.</summary>
    function Distrusted: TArray<TBytes>;
  end;

implementation

end.
