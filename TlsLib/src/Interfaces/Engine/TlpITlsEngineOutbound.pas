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
  TlpHandshakeMessages;

type
  /// <summary>
  /// The outbound face of the engine: every call that can seal a record or take sealed bytes, and
  /// the handshake controls that emit flights. WantsWrite is True exactly when TakeOutgoing would
  /// return bytes. Contracts are those of ITlsEngine.
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
    function WriteClosed: Boolean;
  end;

implementation

end.
