{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpITlsCredentialResolver;

{$I ..\..\Include\TlsLib.inc}

interface

uses
  TlpTlsCredential;

type
  /// <summary>
  /// Selects which server certificate credential answers a handshake, from a read-only
  /// view of the client's ClientHello - primarily its SNI host_name, so one server can
  /// present a different certificate per virtual host (RFC 6066 3). The full offer
  /// (signature schemes, ALPN, cipher suites, groups) is exposed so a resolver may also
  /// select by client capability (e.g. an ECDSA leaf for capable clients, RSA otherwise),
  /// though the built-in map keys on the host_name alone.
  ///
  /// TryResolve is called once per ClientHello processed, on the certificate path only (a
  /// resumed or PSK handshake sends no Certificate); a HelloRetryRequest re-resolves from the
  /// second ClientHello, so a resolver with side effects may see two calls. It is called
  /// concurrently across connections that
  /// share one frozen configuration, so an implementation must be read-only / thread-safe
  /// and must not perform network I/O. Returning False aborts the handshake: the state
  /// machine sends unrecognized_name when the client named a host, or handshake_failure
  /// when it sent none.
  /// </summary>
  ITlsServerCredentialResolver = interface(IInterface)
    ['{6B2F1E7A-9C84-4D3B-A1E5-2F8C0D74B3A9}']
    function TryResolve(const AClientHello: TTlsClientHelloInfo;
      out ACredential: TTlsCredential): Boolean;
  end;

implementation

end.
