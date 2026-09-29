{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpExporterArgs;

{$I ..\Include\TlsLib.inc}

interface

uses
  SysUtils,
  TlpTlsLibExceptions;

type
  /// <summary>Shared argument guard for the RFC 5705 / RFC 8446 keying-material exporters, used by
  /// both the TLS 1.2 and TLS 1.3 key schedules.</summary>
  TExporterArgs = class sealed(TObject)
  public
    class procedure Guard(const ALabel: string; ALength: Int32); static;
  end;

implementation

resourcestring
  SExportLengthNotPositive = 'the exported keying material length must be positive';
  SExportLabelNotAscii = 'the exporter label must be ASCII';
  SExportLabelReserved = 'the exporter label collides with a reserved TLS PRF label';

const
  // RFC 5705 4: an exporter label MUST NOT be one the TLS PRF already uses, or the derived value
  // could coincide with a handshake secret (RFC 5246 + RFC 7627 extended_master_secret)
  ReservedPrfLabels: array [0 .. 4] of string = ('client finished', 'server finished',
    'master secret', 'key expansion', 'extended master secret');

{ TExporterArgs }

class procedure TExporterArgs.Guard(const ALabel: string; ALength: Int32);
var
  LI: Int32;
begin
  // RFC 5705 exporters need a positive length; a zero-length export is caller misuse. An empty
  // label is legal, but a non-ASCII one would be silently mangled by the ASCII encoding, so reject it
  if ALength <= 0 then
    raise EArgumentTlsLibException.CreateRes(@SExportLengthNotPositive);
  for LI := 1 to System.Length(ALabel) do
    if Ord(ALabel[LI]) > 127 then
      raise EArgumentTlsLibException.CreateRes(@SExportLabelNotAscii);
  for LI := System.Low(ReservedPrfLabels) to System.High(ReservedPrfLabels) do
    if ALabel = ReservedPrfLabels[LI] then
      raise EArgumentTlsLibException.CreateRes(@SExportLabelReserved);
end;

end.
