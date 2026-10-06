{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpIHttpFetcher;

{$I ..\..\Include\TlsLib.inc}

interface

uses
  SysUtils;

type
  /// <summary>
  /// The injected, blocking HTTP byte conduit used only at the driver edge for live
  /// revocation retrieval (OCSP over HTTP, RFC 6960 A.1; CRL fetch, RFC 5280). The sans-IO
  /// engine core NEVER references an implementation of this: the core stays network-free,
  /// and a host supplies a concrete fetcher (built on its own sockets/HTTP stack) that the
  /// deferred-verdict resolver calls out-of-band.
  ///
  /// Both methods are synchronous and MUST NOT raise: a transport error, a non-2xx status,
  /// a timeout, or an empty body is reported as a False result with AResponse empty. The
  /// caller treats a False (or an ambiguous body) per the revocation posture it was built with,
  /// so a failed fetch is never taken as Good. ATimeoutMs
  /// bounds the whole exchange; 0 leaves the timeout to the implementation.
  ///
  /// The URLs come from the peer's own certificate and are passed as written, so the scheme
  /// may be upper case (RFC 3986 3.1). The fetcher is the place for a host's egress policy - an
  /// allowlist, a proxy, or rewriting to a mirror - and it must not run TlsLib live revocation
  /// for its own https fetches, which would recurse.
  /// </summary>
  IHttpFetcher = interface(IInterface)
    ['{4C1A9F7E-6D30-4B58-8E24-7F5B0A2C9E13}']
    /// <summary>Performs a blocking HTTP GET (used for CRL distribution points). Returns True
    /// with the response body in AResponse on a 2xx with a body; False (AResponse empty) on
    /// any failure. AMaxBytes bounds the body: a response that would exceed it is a failure and
    /// the fetcher must stop reading at the bound rather than buffer past it. Never raises.</summary>
    function Get(const AUrl: string; ATimeoutMs: Cardinal; AMaxBytes: Int32;
      out AResponse: TBytes): Boolean;
    /// <summary>Performs a blocking HTTP POST (used for OCSP requests: AContentType
    /// application/ocsp-request, ABody the DER request). Returns True with the response body
    /// on a 2xx with a body; False (AResponse empty) on any failure. AMaxBytes bounds the body
    /// as in Get. Never raises.</summary>
    function Post(const AUrl, AContentType: string; const ABody: TBytes;
      ATimeoutMs: Cardinal; AMaxBytes: Int32; out AResponse: TBytes): Boolean;
  end;

implementation

end.
