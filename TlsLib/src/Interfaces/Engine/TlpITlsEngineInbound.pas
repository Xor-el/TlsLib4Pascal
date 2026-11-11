{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpITlsEngineInbound;

{$I ..\..\Include\TlsLib.inc}

interface

uses
  SysUtils,
  TlpTlsError,
  TlpTlsConnectionInfo,
  TlpITlsEngine;

type
  /// <summary>
  /// The inbound face of the engine: feeding the wire, reading application data and events, and
  /// the queries over what has been received. Once the handshake is complete no call here seals a
  /// record; what the inbound path provokes (a fatal alert) waits for the outbound side's
  /// TakeOutgoing. During the handshake ProcessInput still seals its flights. Contracts are those
  /// of ITlsEngine.
  /// </summary>
  ITlsEngineInbound = interface(IInterface)
    ['{AA3AE817-05FC-46BE-BA1A-3CB403A43F9A}']
    function ProcessInput(const AWire: TBytes; AOffset, ALength: Int32): TTlsOutcome;
    function ReadAppData(var ADest: TBytes; ADestOffset, AMaxLength: Int32): Int32;
    function PendingAppData: Int32;
    function ReadEarlyData(var ADest: TBytes; ADestOffset, AMaxLength: Int32): Int32;
    function PendingEarlyData: Int32;
    function NextEvent(out AEvent: ITlsEvent): Boolean;
    function ConnectionInfo: TTlsConnectionInfo;
    function WantsRead: Boolean;
    function IsHandshaking: Boolean;
    function AwaitingCertificateVerdict: Boolean;
    function IsTerminal: Boolean;
    function IsClosed: Boolean;
    function IsInboundClosed: Boolean;
    function LastError: TTlsError;
    function ExportKeyingMaterial(const ALabel: string;
      ALength: Int32): TBytes; overload;
    function ExportKeyingMaterial(const ALabel: string; const AContext: TBytes;
      ALength: Int32): TBytes; overload;
    function ExportEarlyKeyingMaterial(const ALabel: string; const AContext: TBytes;
      ALength: Int32): TBytes;
  end;

implementation

end.
