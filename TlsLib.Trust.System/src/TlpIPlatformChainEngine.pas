{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpIPlatformChainEngine;

{$I ..\..\TlsLib\src\Include\TlsLib.inc}

interface

uses
  TlpTlsAlert,
  TlpSystemTrustBase;

type
  /// <summary>
  /// The platform chain engine behind an OS trust delegate: it builds and trusts a certificate path
  /// with the OS (crypt32, Security.framework, the Android TrustManager) and reports a revocation
  /// outcome, and nothing else - posture, strength policy, staple and identity post-checks are applied
  /// by the delegate that owns it. Both methods return True when the platform built and trusted a path
  /// (AResult filled; the revocation question is answered by AResult.Outcome), and False with AAlert on
  /// a definitive non-revocation failure (untrusted root, expiry, wrong usage, name mismatch, a
  /// platform runtime that is not ready - internal_error). Fail-closed: an engine never accepts what
  /// the platform rejected. Instances are stateless and reusable across connections and threads.
  /// </summary>
  IPlatformChainEngine = interface(IInterface)
    ['{49E77682-9311-473C-A38D-72747D05A868}']
    function Capabilities: TPlatformChainCapabilities;
    /// <summary>The server-authentication evaluation (server-auth EKU, the OS roots, the DNS host
    /// where the platform matches it).</summary>
    function EvaluateServer(const ARequest: TPlatformChainRequest;
      out AResult: TPlatformChainResult; out AAlert: TTlsAlertDescription): Boolean;
    /// <summary>The client-authentication evaluation (client-auth EKU) against ARequest.Anchors as the
    /// exclusive trust root - never the OS/public roots. Zero anchors reject (unknown_ca).</summary>
    function EvaluateClient(const ARequest: TPlatformChainRequest;
      out AResult: TPlatformChainResult; out AAlert: TTlsAlertDescription): Boolean;
  end;

implementation

end.
