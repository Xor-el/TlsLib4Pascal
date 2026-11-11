{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpITlsEngineOutbound;

{$I ..\..\Include\TlsLib.inc}

interface

uses
  SysUtils,
  TlpTlsAlert,
  TlpTlsError,
  TlpHandshakeMessages;

type
  /// <summary>
  /// The outbound face of the engine: every call that can seal a record or take sealed bytes, and
  /// the handshake controls that emit flights, with the queries a writer needs to stop. WantsWrite
  /// is True when TakeOutgoing would return bytes or drop a failed alert. Contracts are those of
  /// ITlsEngine.
  /// </summary>
  ITlsEngineOutbound = interface(IInterface)
    ['{70F9B9A9-9120-495A-9A84-90C17E656C1B}']
    procedure StartHandshake;
    procedure SetCertificateVerdict(AAccept: Boolean; AAlert: TTlsAlertDescription);
    procedure Write(const AData: TBytes; AOffset, ALength: Int32);
    function WriteEarlyData(const AData: TBytes; AOffset, ALength: Int32): Int32;
    procedure RequestKeyUpdate(ARequest: TKeyUpdateRequest);
    procedure SendClose;
    procedure SendAlert(ADescription: TTlsAlertDescription); overload;
    procedure SendAlert(ADescription: TTlsAlertDescription; const AReason: string); overload;
    procedure LatchTransportFailure(const AReason: string);
    function TakeOutgoing(var ADest: TBytes; ADestOffset: Int32): Int32;
    function WantsWrite: Boolean;
    function IsTerminal: Boolean;
    function WriteClosed: Boolean;
    function LastError: TTlsError;
  end;

implementation

end.
