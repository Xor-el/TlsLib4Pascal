{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpITlsHostExtension;

{$I ..\..\Include\TlsLib.inc}

interface

uses
  SysUtils,
  TlpExtensionContext;

type
  /// <summary>
  /// A TLS 1.3 extension the host supplies as data: its type, the messages it is sent in, its
  /// body and the messages the peer must carry it in. A client sends in the ClientHello only and
  /// requires in HelloRetryRequest, EncryptedExtensions, CertificateRequest or NewSessionTicket;
  /// a server does the reverse, and the factory refuses anything else. A message other than the
  /// ClientHello is answered only when the peer's ClientHello carried the type, and a copy in
  /// any message the host did not declare (a ClientHello a server answers excepted) is
  /// illegal_parameter. A peer that omits it from a RequiredIn message fails with
  /// missing_extension. No host code runs inside the handshake. It is carried by TLS 1.3
  /// handshakes only: a dual-version ClientHello still offers it, but a handshake that
  /// negotiates TLS 1.2 neither answers it nor enforces RequiredIn, and a TLS 1.2 server that
  /// echoes it fails the handshake.
  /// </summary>
  ITlsHostExtension = interface(IInterface)
    ['{144E4A90-124D-4A85-8EF5-579B48B634B8}']
    function ExtensionType: UInt16;
    function SendIn: TTlsExtensionContexts;
    function Body: TBytes;
    function RequiredIn: TTlsExtensionContexts;
  end;

  /// <summary>
  /// Reads back the host extensions the peer sent. The bodies are unauthenticated until the
  /// handshake completes: act on them only after that, or treat them as untrusted input.
  /// </summary>
  ITlsHostExtensionResults = interface(IInterface)
    ['{BD89F690-1ACA-4E9C-8C36-991362EFFFB9}']
    /// <summary>The body the peer sent for AType, readable as soon as the message carrying it has
    /// been processed. It is the copy of the earliest message that carried it: a later message
    /// never replaces it. False when the peer sent none or AType is not a configured host
    /// extension.</summary>
    function TryGetPeerExtension(AType: UInt16; out ABody: TBytes): Boolean;
  end;

implementation

end.
