{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpTlsContentType;

{$I ..\Include\TlsLib.inc}

interface

type
  /// <summary>
  /// TLS record content type (RFC 9846). The ordinal is the on-wire byte, so
  /// Ord() yields the code directly. The enum is sparse - map a raw byte through
  /// <see cref="TryFromByte" /> rather than casting.
  /// </summary>
  TTlsContentType = (
    Invalid = 0,
    ChangeCipherSpec = 20,
    Alert = 21,
    Handshake = 22,
    ApplicationData = 23,
    Heartbeat = 24);

  /// <summary>Round-trip helpers between a content type and its wire byte.</summary>
  TTlsContentTypeHelper = record helper for TTlsContentType
  public
    /// <summary>This content type's on-wire byte (its ordinal).</summary>
    function ToByte: Byte;
    /// <summary>
    /// Maps a wire byte to a known content type. Returns False for an
    /// unrecognized code (never guesses); the out-param is only valid on True.
    /// Invoke through the type: TTlsContentType.TryFromByte(...).
    /// </summary>
    class function TryFromByte(AValue: Byte;
      out AContentType: TTlsContentType): Boolean; static;
  end;

implementation

{ TTlsContentTypeHelper }

function TTlsContentTypeHelper.ToByte: Byte;
begin
  Result := Byte(Ord(Self));
end;

class function TTlsContentTypeHelper.TryFromByte(AValue: Byte;
  out AContentType: TTlsContentType): Boolean;
begin
  Result := True;
  case AValue of
    0: AContentType := TTlsContentType.Invalid;
    20: AContentType := TTlsContentType.ChangeCipherSpec;
    21: AContentType := TTlsContentType.Alert;
    22: AContentType := TTlsContentType.Handshake;
    23: AContentType := TTlsContentType.ApplicationData;
    24: AContentType := TTlsContentType.Heartbeat;
  else
    Result := False;
  end;
end;

end.
