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

type
  /// <summary>The labels the TLS 1.2 key schedule feeds its PRF; any other label is a keying
  /// material exporter's (RFC 5705 4).</summary>
  TTls12PrfLabels = class sealed(TObject)
  public const
    /// <summary>The TLS 1.2 PRF label of the master secret (RFC 5246 8.1).</summary>
    MasterSecret = 'master secret';
    /// <summary>The TLS 1.2 PRF label of the extended master secret (RFC 7627 4).</summary>
    ExtendedMasterSecret = 'extended master secret';
    /// <summary>The TLS 1.2 PRF label of the key block (RFC 5246 6.3).</summary>
    KeyExpansion = 'key expansion';
    /// <summary>The TLS 1.2 PRF label of the client Finished verify_data (RFC 5246 7.4.9).</summary>
    ClientFinished = 'client finished';
    /// <summary>The TLS 1.2 PRF label of the server Finished verify_data (RFC 5246 7.4.9).</summary>
    ServerFinished = 'server finished';
    /// <summary>Whether ALabel is one of the five key-schedule PRF labels.</summary>
    class function IsKeyScheduleLabel(const ALabel: string): Boolean; static;
  end;

implementation

class function TTls12PrfLabels.IsKeyScheduleLabel(const ALabel: string): Boolean;
begin
  Result := (ALabel = MasterSecret) or (ALabel = ExtendedMasterSecret) or
    (ALabel = KeyExpansion) or (ALabel = ClientFinished) or (ALabel = ServerFinished);
end;

end.
