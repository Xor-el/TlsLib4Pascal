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
  /// <summary>The role-neutral marker of a certificate verifier source that validates chains
  /// through the OS delegate rather than the portable verifier; the source class lists it. Any
  /// class can list it, so a config check judges the class, not the marker. It also carries the
  /// server-role roots, so the live re-check builds against the same ones as the inline pass. A
  /// stapled revocation response may be decided by the configured PKIX provider instead of the OS.
  /// All three are empty for a client-only source.</summary>
  ISystemVerifierSource = interface(IInterface)
    ['{0DE1F07C-D1E4-41A9-BF68-5F115CDA14C9}']
    /// <summary>The exclusive server trust root (empty = the OS roots apply).</summary>
    function Anchors: TArray<TBytes>;
    /// <summary>Host roots trusted with the OS roots.</summary>
    function ExtraAnchors: TArray<TBytes>;
    /// <summary>The distrust set the source was built with (the host's plus the OS list from the
    /// factory), refused on any accepted path.</summary>
    function Distrusted: TArray<TBytes>;
  end;

implementation

end.
