{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpINetSocket;

{$I ..\TlsLib\src\Include\TlsLib.inc}

interface

uses
  SysUtils,
  TlpITlsTransport;

type
  /// <summary>Opens client TCP connections. The stream it returns is an ITlsTimedTransport, so a
  /// TTlsConnection runs over it directly and a raw caller uses Read and Write.</summary>
  ITcpConnector = interface(IInterface)
    ['{5146B53F-BD5F-4ABC-99E3-320F6FF63380}']
    /// <summary>A connected stream, closed when its last reference is released. Raises
    /// ENetConnectError when AHost does not resolve, the peer refuses, or the connect timeout
    /// elapses.</summary>
    function Connect(const AHost: string; APort: Word): ITlsTimedTransport;
  end;

  /// <summary>A bound, listening TCP endpoint. Use it from one thread at a time: a server stops by
  /// ending its TryAccept loop, never by closing the listener while another thread waits in it.</summary>
  ITcpListener = interface(IInterface)
    ['{55103122-4223-4A73-BA0B-BC727D605AA6}']
    /// <summary>The bound port, which is the ephemeral one when the listener was created with
    /// port 0.</summary>
    function Port: Word;
    /// <summary>Waits at most ATimeoutMs ms for a connection: True with ATransport set, or False on
    /// timeout. Raises ENetSocketError when the listener fails.</summary>
    function TryAccept(ATimeoutMs: Int32; out ATransport: ITlsTimedTransport): Boolean;
  end;

implementation

end.
