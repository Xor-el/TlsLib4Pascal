{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpILayeredTrustAnchorStore;

{$I ..\..\Include\TlsLib.inc}

interface

uses
  SysUtils,
  TlpITrustAnchorStore;

type
  /// <summary>
  /// The parts of a trust store built as a few extra roots over an existing store. A consumer that
  /// caches work per store identity serves the base from that cache and handles only the extras, so
  /// the base is never copied or re-derived per store. The base is itself never layered.
  /// </summary>
  ILayeredTrustAnchorStore = interface(IInterface)
    ['{6351D925-5FE6-4F9F-8B89-1008E5BE45AA}']
    /// <summary>The store the extras sit on, as given: its identity is stable.</summary>
    function BaseStore: ITrustAnchorStore;
    /// <summary>The roots added over the base, DER-encoded, as a fresh copy. None is in the base
    /// and none is distrusted by it.</summary>
    function ExtraRoots: TArray<TBytes>;
  end;

implementation

end.
