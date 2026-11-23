{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpIHostExtensionReplies;

{$I ..\..\Include\TlsLib.inc}

interface

uses
  SysUtils,
  TlpExtensionContext;

type
  /// <summary>
  /// The reply bodies of a server's host extensions, chosen after the client's ClientHello was
  /// read. It is the engine's private seam to the registry entries: a host reaches it only through
  /// the engine's continue call.
  /// </summary>
  IHostExtensionReplies = interface(IInterface)
    ['{A392B4EA-3A28-4DBA-A7F3-880EA136177D}']
    /// <summary>Whether AExtensionType is a registered host extension the client's ClientHello
    /// carried.</summary>
    function IsOffered(AExtensionType: UInt16): Boolean;
    /// <summary>Sends the reply body of each extension named in AReplies wherever that extension
    /// rides, and sends no other offered one. The registry validates first: it raises
    /// EArgumentTlsLibException and changes nothing when a reply names an extension the client did
    /// not offer, one extension twice, or a body over 65535 bytes; an entry only applies the
    /// replies it is given.</summary>
    procedure Install(const AReplies: TArray<TTlsHostExtensionReply>);
  end;

implementation

end.
