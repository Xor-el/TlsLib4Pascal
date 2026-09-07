{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpTlsAlert;

{$I ..\Include\TlsLib.inc}

interface

type
  /// <summary>TLS alert level (RFC 8446).</summary>
  TTlsAlertLevel = (Warning = 1, Fatal = 2);

  /// <summary>The on-wire byte for an alert level.</summary>
  TTlsAlertLevelHelper = record helper for TTlsAlertLevel
  public
    /// <summary>This level's on-wire byte (its ordinal).</summary>
    function ToByte: Byte;
  end;

  /// <summary>
  /// TLS alert description (RFC 8446). The ordinal is the on-wire code, so Ord()
  /// yields the byte directly. The enum is sparse - use the round-trip helpers
  /// rather than casting a raw byte.
  /// </summary>
  TTlsAlertDescription = (
    CloseNotify = 0,
    UnexpectedMessage = 10,
    BadRecordMac = 20,
    RecordOverflow = 22,
    HandshakeFailure = 40,
    BadCertificate = 42,
    UnsupportedCertificate = 43,
    CertificateRevoked = 44,
    CertificateExpired = 45,
    CertificateUnknown = 46,
    IllegalParameter = 47,
    UnknownCa = 48,
    AccessDenied = 49,
    DecodeError = 50,
    DecryptError = 51,
    ProtocolVersion = 70,
    InsufficientSecurity = 71,
    InternalError = 80,
    InappropriateFallback = 86,
    UserCanceled = 90,
    MissingExtension = 109,
    UnsupportedExtension = 110,
    UnrecognizedName = 112,
    BadCertificateStatusResponse = 113,
    UnknownPskIdentity = 115,
    CertificateRequired = 116,
    NoApplicationProtocol = 120,
    EchRequired = 121);

  /// <summary>Round-trip helpers between an alert description and its wire byte.</summary>
  TTlsAlertDescriptionHelper = record helper for TTlsAlertDescription
  public
    /// <summary>This description's on-wire byte (its ordinal).</summary>
    function ToByte: Byte;
    /// <summary>
    /// Maps a wire byte back to a known alert description. Returns False for an
    /// unrecognized code (never guesses); the out-param is only valid on True.
    /// Invoke through the type: TTlsAlertDescription.TryFromByte(...).
    /// </summary>
    class function TryFromByte(AValue: Byte;
      out ADescription: TTlsAlertDescription): Boolean; static;
  end;

  /// <summary>An immutable (level, description) pair.</summary>
  TTlsAlert = record
  strict private
    FLevel: TTlsAlertLevel;
    FDescription: TTlsAlertDescription;
  public
    class function Create(ALevel: TTlsAlertLevel;
      ADescription: TTlsAlertDescription): TTlsAlert; static;
    /// <summary>A fatal alert carrying the given description.</summary>
    class function CreateFatal(ADescription: TTlsAlertDescription): TTlsAlert; static;

    property Level: TTlsAlertLevel read FLevel;
    property Description: TTlsAlertDescription read FDescription;
  end;

implementation

{ TTlsAlertLevelHelper }

function TTlsAlertLevelHelper.ToByte: Byte;
begin
  Result := Byte(Ord(Self));
end;

{ TTlsAlertDescriptionHelper }

function TTlsAlertDescriptionHelper.ToByte: Byte;
begin
  Result := Byte(Ord(Self));
end;

class function TTlsAlertDescriptionHelper.TryFromByte(AValue: Byte;
  out ADescription: TTlsAlertDescription): Boolean;
begin
  Result := True;
  case AValue of
    0: ADescription := TTlsAlertDescription.CloseNotify;
    10: ADescription := TTlsAlertDescription.UnexpectedMessage;
    20: ADescription := TTlsAlertDescription.BadRecordMac;
    22: ADescription := TTlsAlertDescription.RecordOverflow;
    40: ADescription := TTlsAlertDescription.HandshakeFailure;
    42: ADescription := TTlsAlertDescription.BadCertificate;
    43: ADescription := TTlsAlertDescription.UnsupportedCertificate;
    44: ADescription := TTlsAlertDescription.CertificateRevoked;
    45: ADescription := TTlsAlertDescription.CertificateExpired;
    46: ADescription := TTlsAlertDescription.CertificateUnknown;
    47: ADescription := TTlsAlertDescription.IllegalParameter;
    48: ADescription := TTlsAlertDescription.UnknownCa;
    49: ADescription := TTlsAlertDescription.AccessDenied;
    50: ADescription := TTlsAlertDescription.DecodeError;
    51: ADescription := TTlsAlertDescription.DecryptError;
    70: ADescription := TTlsAlertDescription.ProtocolVersion;
    71: ADescription := TTlsAlertDescription.InsufficientSecurity;
    80: ADescription := TTlsAlertDescription.InternalError;
    86: ADescription := TTlsAlertDescription.InappropriateFallback;
    90: ADescription := TTlsAlertDescription.UserCanceled;
    109: ADescription := TTlsAlertDescription.MissingExtension;
    110: ADescription := TTlsAlertDescription.UnsupportedExtension;
    112: ADescription := TTlsAlertDescription.UnrecognizedName;
    113: ADescription := TTlsAlertDescription.BadCertificateStatusResponse;
    115: ADescription := TTlsAlertDescription.UnknownPskIdentity;
    116: ADescription := TTlsAlertDescription.CertificateRequired;
    120: ADescription := TTlsAlertDescription.NoApplicationProtocol;
    121: ADescription := TTlsAlertDescription.EchRequired;
  else
    Result := False;
  end;
end;

{ TTlsAlert }

class function TTlsAlert.Create(ALevel: TTlsAlertLevel;
  ADescription: TTlsAlertDescription): TTlsAlert;
begin
  Result.FLevel := ALevel;
  Result.FDescription := ADescription;
end;

class function TTlsAlert.CreateFatal(ADescription: TTlsAlertDescription): TTlsAlert;
begin
  Result := TTlsAlert.Create(TTlsAlertLevel.Fatal, ADescription);
end;

end.
