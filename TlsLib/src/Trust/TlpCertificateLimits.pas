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
  /// bytes and by entry count; loosening them only relaxes the caller's own resource
  /// budget - the chain still faces full PKIX validation - so this is a tuning input,
  /// not a trust bypass. The defaults are a conservative web-PKI profile; a large
  /// post-quantum chain is the usual reason to raise them. Start a custom value from Defaults:
  /// a cap left at 0 admits no chain. The caps apply in the built-in and OS verifiers; a custom
  /// verifier owns its own limits.
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
    /// <summary>The most certificates a peer may present in one chain. The peer controls the
    /// chain before it proves it holds the leaf key, and path building explores the presented
    /// certificates, so the count is bounded independently of the byte caps.</summary>
    MaxChainCertificates: Int32;
    /// <summary>The conservative web-PKI defaults (sub-64 KiB certs and message, 16 certificates).</summary>
    class function Defaults: TCertificateChainLimits; static;
    /// <summary>True when AChain is within every cap: the entry count, each certificate's length
    /// and the total length. An over-cap chain is refused before any PKIX work.</summary>
    function AdmitsChain(const AChain: TArray<TBytes>): Boolean;
  end;

implementation

{ TCertificateChainLimits }

class function TCertificateChainLimits.Defaults: TCertificateChainLimits;
begin
  Result.MaxCertificateLength := 1 shl 16;
  Result.MaxTotalChainLength := 1 shl 16;
  Result.MaxChainCertificates := 16;
end;

function TCertificateChainLimits.AdmitsChain(const AChain: TArray<TBytes>): Boolean;
var
  LI, LTotal: Int32;
begin
  Result := False;
  if System.Length(AChain) > MaxChainCertificates then
    Exit;
  LTotal := 0;
  for LI := 0 to System.High(AChain) do
  begin
    if System.Length(AChain[LI]) > MaxCertificateLength then
      Exit;
    Inc(LTotal, System.Length(AChain[LI]));
    if LTotal > MaxTotalChainLength then
      Exit;
  end;
  Result := True;
end;

end.
