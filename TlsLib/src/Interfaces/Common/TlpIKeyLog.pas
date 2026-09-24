{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpIKeyLog;

{$I ..\..\Include\TlsLib.inc}

interface

uses
  SysUtils;

type
  /// <summary>
  /// DANGEROUS. Receives each connection secret as the key schedule derives it, so a packet
  /// capture can be decrypted out of band (the SSLKEYLOGFILE format, RFC 9850). ALabel names the
  /// secret: CLIENT_RANDOM carries the TLS 1.2 master secret; CLIENT_EARLY_TRAFFIC_SECRET,
  /// CLIENT_HANDSHAKE_TRAFFIC_SECRET, SERVER_HANDSHAKE_TRAFFIC_SECRET, CLIENT_TRAFFIC_SECRET_0,
  /// SERVER_TRAFFIC_SECRET_0 and EXPORTER_SECRET carry the TLS 1.3 secrets. AClientRandom is the
  /// 32-byte ClientHello.random the line is keyed by - the inner ClientHello's when Encrypted
  /// Client Hello was accepted, the outer's otherwise. ASecret is a transient copy wiped when the
  /// call returns; a sink that keeps it holds live key material. Never installed unless a caller
  /// opts in through the dangerous builder surface.
  /// </summary>
  IKeyLog = interface(IInterface)
    ['{0D74C940-A545-479A-8FB8-41E38DD16095}']
    procedure Log(const ALabel: string; const AClientRandom, ASecret: TBytes);
  end;

implementation

end.
