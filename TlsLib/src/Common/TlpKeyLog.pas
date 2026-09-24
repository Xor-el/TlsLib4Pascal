{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpKeyLog;

{$I ..\Include\TlsLib.inc}

interface

uses
  SysUtils,
  TlpDataEncoding,
  TlpTlsLibExceptions,
  TlpIKeyLog;

const
  // NSS Key Log labels (RFC 9850)
  KeyLogLabelClientRandom = 'CLIENT_RANDOM';
  KeyLogLabelClientEarlyTraffic = 'CLIENT_EARLY_TRAFFIC_SECRET';
  KeyLogLabelClientHandshakeTraffic = 'CLIENT_HANDSHAKE_TRAFFIC_SECRET';
  KeyLogLabelServerHandshakeTraffic = 'SERVER_HANDSHAKE_TRAFFIC_SECRET';
  KeyLogLabelClientTraffic0 = 'CLIENT_TRAFFIC_SECRET_0';
  KeyLogLabelServerTraffic0 = 'SERVER_TRAFFIC_SECRET_0';
  KeyLogLabelExporter = 'EXPORTER_SECRET';

type
  /// <summary>A method the host supplies to receive each key-log secret (see IKeyLog).</summary>
  TKeyLogCallback = procedure(const ALabel: string;
    const AClientRandom, ASecret: TBytes) of object;

  /// <summary>Adapts a method pointer to IKeyLog, so a host can log without writing a class.</summary>
  TCallbackKeyLog = class sealed(TInterfacedObject, IKeyLog)
  strict private
  var
    FCallback: TKeyLogCallback;
    procedure Log(const ALabel: string; const AClientRandom, ASecret: TBytes);
  public
    constructor Create(const ACallback: TKeyLogCallback);
  end;

  /// <summary>Formats one SSLKEYLOGFILE line (no trailing newline; the host appends one).</summary>
  TNssKeyLogFormat = class sealed(TObject)
  public
    class function Line(const ALabel: string;
      const AClientRandom, ASecret: TBytes): string; static;
  end;

implementation

resourcestring
  SNilKeyLogCallback = 'the key-log callback must be assigned';

{ TCallbackKeyLog }

constructor TCallbackKeyLog.Create(const ACallback: TKeyLogCallback);
begin
  inherited Create;
  if not Assigned(ACallback) then
    raise EArgumentTlsLibException.CreateRes(@SNilKeyLogCallback);
  FCallback := ACallback;
end;

procedure TCallbackKeyLog.Log(const ALabel: string;
  const AClientRandom, ASecret: TBytes);
begin
  FCallback(ALabel, AClientRandom, ASecret);
end;

{ TNssKeyLogFormat }

class function TNssKeyLogFormat.Line(const ALabel: string;
  const AClientRandom, ASecret: TBytes): string;
begin
  Result := ALabel + ' ' + TDataEncoding.HexEncode(AClientRandom) + ' ' +
    TDataEncoding.HexEncode(ASecret);
end;

end.
