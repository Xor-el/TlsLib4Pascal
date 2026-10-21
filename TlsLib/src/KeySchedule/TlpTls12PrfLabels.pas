{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpTls12PrfLabels;

{$I ..\Include\TlsLib.inc}

interface

const
  /// <summary>The TLS 1.2 PRF label of the master secret (RFC 5246 8.1).</summary>
  Tls12PrfLabelMasterSecret = 'master secret';
  /// <summary>The TLS 1.2 PRF label of the extended master secret (RFC 7627 4).</summary>
  Tls12PrfLabelExtendedMasterSecret = 'extended master secret';
  /// <summary>The TLS 1.2 PRF label of the key block (RFC 5246 6.3).</summary>
  Tls12PrfLabelKeyExpansion = 'key expansion';
  /// <summary>The TLS 1.2 PRF label of the client Finished verify_data (RFC 5246 7.4.9).</summary>
  Tls12PrfLabelClientFinished = 'client finished';
  /// <summary>The TLS 1.2 PRF label of the server Finished verify_data (RFC 5246 7.4.9).</summary>
  Tls12PrfLabelServerFinished = 'server finished';

type
  /// <summary>The labels the TLS 1.2 key schedule feeds its PRF; any other label is a keying
  /// material exporter's (RFC 5705 4).</summary>
  TTls12PrfLabels = class sealed(TObject)
  public
    /// <summary>Whether ALabel is one of the five key-schedule PRF labels.</summary>
    class function IsKeyScheduleLabel(const ALabel: string): Boolean; static;
  end;

implementation

class function TTls12PrfLabels.IsKeyScheduleLabel(const ALabel: string): Boolean;
begin
  Result := (ALabel = Tls12PrfLabelMasterSecret) or
    (ALabel = Tls12PrfLabelExtendedMasterSecret) or (ALabel = Tls12PrfLabelKeyExpansion) or
    (ALabel = Tls12PrfLabelClientFinished) or (ALabel = Tls12PrfLabelServerFinished);
end;

end.
