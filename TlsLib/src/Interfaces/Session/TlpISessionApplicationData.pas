{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpISessionApplicationData;

{$I ..\..\Include\TlsLib.inc}

interface

uses
  SysUtils;

type
  /// <summary>
  /// Opaque bytes a client host keeps with the resumable sessions it caches, such as the settings
  /// the server announced on this connection. Reach it with Supports on an engine. A server engine
  /// has no session to attach them to: SetSessionApplicationData raises there and
  /// OfferedSessionApplicationData is empty.
  /// </summary>
  ITlsSessionApplicationData = interface(IInterface)
    ['{A0680FD5-B341-48C4-8C43-B6A4FEE40AC0}']
    /// <summary>Attaches AData to every ticket this connection receives from now on, and the
    /// cached session carries it; a later call replaces the value for tickets received after it.</summary>
    procedure SetSessionApplicationData(const AData: TBytes);
    /// <summary>The bytes stored with the ticket this connection offered, available right after
    /// StartHandshake; empty when no resumption is offered or none were set.</summary>
    function OfferedSessionApplicationData: TBytes;
  end;

  /// <summary>
  /// The engine-internal side of <see cref="ITlsSessionApplicationData" />: what a client machine
  /// reads when it caches a ticket and where it publishes the offered session's bytes.
  /// </summary>
  ISessionApplicationDataChannel = interface(IInterface)
    ['{2D0B2D5D-12C8-4EC9-A239-67E39EE75460}']
    /// <summary>The bytes the host set for tickets received on this connection.</summary>
    function Current: TBytes;
    /// <summary>Records the bytes stored with the session the ClientHello offers.</summary>
    procedure PublishOffered(const AData: TBytes);
  end;

implementation

end.
