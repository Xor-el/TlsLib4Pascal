{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpTlsVersion;

{$I ..\Include\TlsLib.inc}

interface

const
  /// <summary>
  /// The 2-byte version codes. Only TLS 1.2 and 1.3 are ever negotiable; the
  /// older code exists solely as a legacy wire value the format requires -
  /// legacy_record_version is 0x0301 on the initial flight and 0x0303 after,
  /// and legacy_version is 0x0303 even in a 1.3 handshake (RFC 8446 5.1).
  /// </summary>
  TlsWireVersionTls10 = UInt16($0301);
  // not negotiable; names the 1.1-and-below downgrade sentinel (RFC 8446 4.1.3)
  TlsWireVersionTls11 = UInt16($0302);
  TlsWireVersionTls12 = UInt16($0303);
  TlsWireVersionTls13 = UInt16($0304);

type
  /// <summary>
  /// A protocol version as its 2-byte wire code. A small value record; build the
  /// negotiable ones through the named factories, or wrap a raw code with Create.
  /// </summary>
  TTlsVersion = record
  strict private
  var
    FValue: UInt16;
  public
    /// <summary>Wraps a raw 2-byte version code.</summary>
    class function Create(AWireValue: UInt16): TTlsVersion; static;
    class function Tls12: TTlsVersion; static;
    class function Tls13: TTlsVersion; static;
    /// <summary>The 0x0301 legacy_record_version carried on the first flight.</summary>
    class function LegacyRecordInitial: TTlsVersion; static;

    /// <summary>The 2-byte wire code.</summary>
    function WireValue: UInt16;
    /// <summary>The high byte (the "major" of the legacy major.minor pair).</summary>
    function MajorByte: Byte;
    /// <summary>The low byte (the "minor" of the legacy major.minor pair).</summary>
    function MinorByte: Byte;
    /// <summary>True only for the two negotiable protocol versions (1.2, 1.3).</summary>
    function IsSupportedProtocol: Boolean;
    function Equals(const AOther: TTlsVersion): Boolean;
  end;

implementation

{ TTlsVersion }

class function TTlsVersion.Create(AWireValue: UInt16): TTlsVersion;
begin
  Result.FValue := AWireValue;
end;

class function TTlsVersion.Tls12: TTlsVersion;
begin
  Result.FValue := TlsWireVersionTls12;
end;

class function TTlsVersion.Tls13: TTlsVersion;
begin
  Result.FValue := TlsWireVersionTls13;
end;

class function TTlsVersion.LegacyRecordInitial: TTlsVersion;
begin
  Result.FValue := TlsWireVersionTls10;
end;

function TTlsVersion.WireValue: UInt16;
begin
  Result := FValue;
end;

function TTlsVersion.MajorByte: Byte;
begin
  Result := Byte(FValue shr 8);
end;

function TTlsVersion.MinorByte: Byte;
begin
  Result := Byte(FValue);
end;

function TTlsVersion.IsSupportedProtocol: Boolean;
begin
  Result := (FValue = TlsWireVersionTls12) or (FValue = TlsWireVersionTls13);
end;

function TTlsVersion.Equals(const AOther: TTlsVersion): Boolean;
begin
  Result := FValue = AOther.FValue;
end;

end.
