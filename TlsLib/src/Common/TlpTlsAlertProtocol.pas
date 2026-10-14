{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpTlsAlertProtocol;

{$I ..\Include\TlsLib.inc}

interface

uses
  SysUtils,
  TlpTlsAlert,
  TlpWireReader,
  TlpIWireWriter,
  TlpWireWriter;

type
  /// <summary>
  /// A decoded alert. The description is surfaced as its raw wire byte plus, when
  /// it maps to a code we know, the enum; an unrecognized code is reported as
  /// unknown rather than guessed (RFC 9846 6).
  /// </summary>
  TReceivedAlert = record
  strict private
  var
    FLevelByte: Byte;
    FDescriptionByte: Byte;
    FHasKnownDescription: Boolean;
    FDescription: TTlsAlertDescription;
  public
    class function Create(ALevelByte, ADescriptionByte: Byte): TReceivedAlert; static;
    /// <summary>True when the description byte is close_notify.</summary>
    function IsCloseNotify: Boolean;
    /// <summary>True when the level byte is fatal (2).</summary>
    function IsFatalLevel: Boolean;

    property LevelByte: Byte read FLevelByte;
    property DescriptionByte: Byte read FDescriptionByte;
    /// <summary>Whether <see cref="Description" /> holds a recognized code.</summary>
    property HasKnownDescription: Boolean read FHasKnownDescription;
    /// <summary>The mapped description; only valid when HasKnownDescription is True.</summary>
    property Description: TTlsAlertDescription read FDescription;
  end;

  /// <summary>Encodes and decodes the 2-byte alert message through the wire codec.</summary>
  TTlsAlertProtocol = class sealed(TObject)
  public
    /// <summary>The 2 alert bytes { level, description }.</summary>
    class function Encode(const AAlert: TTlsAlert): TBytes; static;
    /// <summary>
    /// Parses exactly 2 alert bytes; a shorter or longer body raises decode_error.
    /// </summary>
    class function Decode(const AData: TBytes; AOffset,
      ALength: Int32): TReceivedAlert; static;
    /// <summary>The warning-level close_notify alert used for a clean shutdown.</summary>
    class function CloseNotify: TTlsAlert; static;
  end;

implementation

{ TReceivedAlert }

class function TReceivedAlert.Create(ALevelByte,
  ADescriptionByte: Byte): TReceivedAlert;
begin
  Result.FLevelByte := ALevelByte;
  Result.FDescriptionByte := ADescriptionByte;
  Result.FHasKnownDescription := TTlsAlertDescription.TryFromByte(ADescriptionByte,
    Result.FDescription);
end;

function TReceivedAlert.IsCloseNotify: Boolean;
begin
  // close_notify (0) always maps to a known description
  Result := FHasKnownDescription and
    (FDescription = TTlsAlertDescription.CloseNotify);
end;

function TReceivedAlert.IsFatalLevel: Boolean;
var
  LFatal: TTlsAlertLevel;
begin
  LFatal := TTlsAlertLevel.Fatal;
  Result := FLevelByte = LFatal.ToByte;
end;

{ TTlsAlertProtocol }

class function TTlsAlertProtocol.Encode(const AAlert: TTlsAlert): TBytes;
var
  LWriter: IWireWriter;
  LLevel: TTlsAlertLevel;
  LDescription: TTlsAlertDescription;
begin
  Result := nil;
  LLevel := AAlert.Level;
  LDescription := AAlert.Description;
  LWriter := TWireWriter.Create;
  LWriter.WriteUInt8(LLevel.ToByte);
  LWriter.WriteUInt8(LDescription.ToByte);
  Result := LWriter.ToBytes;
end;

class function TTlsAlertProtocol.Decode(const AData: TBytes; AOffset,
  ALength: Int32): TReceivedAlert;
var
  LReader: TWireReader;
  LLevel, LDescription: Byte;
begin
  LReader := TWireReader.Create(AData, AOffset, ALength);
  LLevel := LReader.ReadUInt8;
  LDescription := LReader.ReadUInt8;
  LReader.ExpectEnd; // an alert record is exactly two bytes
  Result := TReceivedAlert.Create(LLevel, LDescription);
end;

class function TTlsAlertProtocol.CloseNotify: TTlsAlert;
begin
  Result := TTlsAlert.Create(TTlsAlertLevel.Warning, TTlsAlertDescription.CloseNotify);
end;

end.
