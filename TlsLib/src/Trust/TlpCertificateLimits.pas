{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpCertificateLimits;

{$I ..\Include\TlsLib.inc}

interface

uses
  SysUtils;

type
  /// <summary>
  /// The certificate-chain resource caps (anti-DoS), bundled so a caller tunes them
  /// as one frozen config value rather than several loose knobs. Bounds the chain by
  /// bytes, not by entry count; loosening them only relaxes the caller's own resource
  /// budget - the chain still faces full PKIX validation - so this is a tuning input,
  /// not a trust bypass. The defaults are a conservative web-PKI profile; a large
  /// post-quantum chain is the usual reason to raise them.
  /// </summary>
  TCertificateChainLimits = record
    /// <summary>The largest single certificate (cert_data), in bytes: a sub-bound within
    /// the message.</summary>
    MaxCertificateLength: Int32;
    /// <summary>The largest Certificate message body, in bytes - the whole certificate_list
    /// with its per-entry length framing and extensions. This one value is the handshake
    /// reassembly ceiling and the compressed-Certificate decompression ceiling, so the
    /// configured budget bounds the message identically on the uncompressed and compressed
    /// paths (and, once decoded, the chain handed to every verifier).</summary>
    MaxTotalChainLength: Int32;
    /// <summary>The conservative web-PKI defaults (sub-64 KiB certs and message).</summary>
    class function Defaults: TCertificateChainLimits; static;
  end;

implementation

{ TCertificateChainLimits }

class function TCertificateChainLimits.Defaults: TCertificateChainLimits;
begin
  Result.MaxCertificateLength := 1 shl 16;
  Result.MaxTotalChainLength := 1 shl 16;
end;

end.
