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
  /// body and the messages the peer must carry it in. SendIn and RequiredIn may name
  /// ClientHello, HelloRetryRequest, EncryptedExtensions, CertificateRequest and
  /// NewSessionTicket. A message other than the ClientHello is answered only when the peer's
  /// ClientHello carried the type, so a type sent in the ClientHello may come back in any of
  /// the others and a type sent in any of the others is accepted in the ClientHello; a copy
  /// anywhere else is illegal_parameter. A peer that omits it from a RequiredIn message fails
  /// with missing_extension. No host code runs inside the handshake. It is carried by TLS 1.3
  /// handshakes only: a handshake that negotiates TLS 1.2 carries none, and RequiredIn is not
  /// enforced there.
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
    /// been processed (the one from the latest message that carried it); False when the peer sent
    /// none or AType is not a configured host extension.</summary>
    function TryGetPeerExtension(AType: UInt16; out ABody: TBytes): Boolean;
  end;

implementation

end.
