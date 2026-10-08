{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlsLibTestHandshakeDecoder;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  SysUtils,
  TlpWireReader,
  TlpExtensionVector,
  TlpHandshakeMessage,
  TlpHandshakeMessages;

type
  /// <summary>
  /// Decodes the handshake bytes a test captured off an engine, so a test can assert what went on
  /// the wire without a second decoder per suite.
  /// </summary>
  TTlsLibTestHandshakeDecoder = class sealed(TObject)
  public
    /// <summary>The first handshake message framed in AFramed.</summary>
    class function HandshakeMessage(const AFramed: TBytes): TTlsHandshakeMessage; static;
    /// <summary>The extensions of the ClientHello in a flight of TLS records; empty when the flight
    /// carries none. A flight can lead with a middlebox-compat ChangeCipherSpec.</summary>
    class function ClientHelloExtensions(const AFlight: TBytes): TExtensionVector; static;
    /// <summary>The host_name of a server_name extension's data; empty when it holds none.</summary>
    class function ServerNameHost(const AServerNameData: TBytes): string; static;
  end;

implementation

class function TTlsLibTestHandshakeDecoder.HandshakeMessage(
  const AFramed: TBytes): TTlsHandshakeMessage;
var
  LReader: THandshakeMessageReader;
begin
  LReader := THandshakeMessageReader.Create;
  try
    LReader.Append(AFramed, 0, System.Length(AFramed));
    LReader.NextMessage(Result);
  finally
    LReader.Free;
  end;
end;

class function TTlsLibTestHandshakeDecoder.ClientHelloExtensions(
  const AFlight: TBytes): TExtensionVector;
var
  LPos, LRecLen, LHsLen: Int32;
  LHello: TTlsClientHello;
begin
  Result := Default(TExtensionVector);
  LPos := 0;
  // the ClientHello is the handshake record (type 22) whose first message is a ClientHello (type 1)
  while LPos + 9 <= System.Length(AFlight) do
  begin
    LRecLen := (AFlight[LPos + 3] shl 8) or AFlight[LPos + 4];
    if (AFlight[LPos] = 22) and (AFlight[LPos + 5] = 1) then
    begin
      LHsLen := (AFlight[LPos + 6] shl 16) or (AFlight[LPos + 7] shl 8) or AFlight[LPos + 8];
      LHello := THandshakeMessages.DecodeClientHello(System.Copy(AFlight, LPos + 9, LHsLen));
      Exit(TExtensionVector.Parse(LHello.Extensions));
    end;
    Inc(LPos, 5 + LRecLen);
  end;
end;

class function TTlsLibTestHandshakeDecoder.ServerNameHost(
  const AServerNameData: TBytes): string;
var
  LReader, LList, LName: TWireReader;
  LBytes: TBytes;
  LI: Int32;
begin
  Result := '';
  LReader := TWireReader.Create(AServerNameData);
  LList := LReader.OpenVector(2);
  if LList.ReadUInt8 <> 0 then
    Exit;
  LName := LList.OpenVector(2);
  LBytes := LName.ReadBytes(LName.Remaining);
  SetLength(Result, System.Length(LBytes));
  for LI := 0 to System.High(LBytes) do
    Result[LI + 1] := Char(LBytes[LI]);
end;

end.
