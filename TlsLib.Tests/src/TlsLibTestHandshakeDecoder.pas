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
    /// <summary>Locates the first handshake message of AMsgType in a flight's plaintext records, which end at a ChangeCipherSpec.</summary>
    class function FindPlaintextHandshakeMessage(const AWire: TBytes; AMsgType: Byte;
      out ARecordPos, AMsgPos, AMsgLen: Int32): Boolean; static;
    /// <summary>The ServerHello in the first handshake record of a flight of TLS records.</summary>
    class function ServerHello(const AFlight: TBytes): TTlsServerHello; static;
    /// <summary>The ClientHello of a flight that is a single record carrying only it.</summary>
    class function ClientHello(const AFlight: TBytes): TTlsClientHello; static;
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

class function TTlsLibTestHandshakeDecoder.FindPlaintextHandshakeMessage(const AWire: TBytes;
  AMsgType: Byte; out ARecordPos, AMsgPos, AMsgLen: Int32): Boolean;
var
  LRecLen, LInner: Int32;
begin
  Result := False;
  AMsgPos := 0;
  AMsgLen := 0;
  ARecordPos := 0;
  while ARecordPos + 5 <= System.Length(AWire) do
  begin
    LRecLen := (AWire[ARecordPos + 3] shl 8) or AWire[ARecordPos + 4];
    if AWire[ARecordPos] = 20 then
      Exit;
    if AWire[ARecordPos] = 22 then
    begin
      LInner := ARecordPos + 5;
      while LInner + 4 <= ARecordPos + 5 + LRecLen do
      begin
        AMsgLen := (AWire[LInner + 1] shl 16) or (AWire[LInner + 2] shl 8) or AWire[LInner + 3];
        if (AWire[LInner] = AMsgType) and (LInner + 4 + AMsgLen <= System.Length(AWire)) then
        begin
          AMsgPos := LInner;
          Exit(True);
        end;
        LInner := LInner + 4 + AMsgLen;
      end;
    end;
    Inc(ARecordPos, 5 + LRecLen);
  end;
end;

class function TTlsLibTestHandshakeDecoder.ServerHello(
  const AFlight: TBytes): TTlsServerHello;
var
  LPos, LLen: Int32;
begin
  Result := Default(TTlsServerHello);
  LPos := 0;
  // the first handshake record (type 22) carries the plaintext ServerHello
  while LPos + 5 <= System.Length(AFlight) do
  begin
    LLen := (AFlight[LPos + 3] shl 8) or AFlight[LPos + 4];
    if AFlight[LPos] = 22 then
    begin
      Result := THandshakeMessages.DecodeServerHello(
        HandshakeMessage(System.Copy(AFlight, LPos + 5, LLen)).Body);
      Exit;
    end;
    Inc(LPos, 5 + LLen);
  end;
end;

class function TTlsLibTestHandshakeDecoder.ClientHello(
  const AFlight: TBytes): TTlsClientHello;
begin
  // record header 5, handshake header 4
  Result := THandshakeMessages.DecodeClientHello(
    System.Copy(AFlight, 9, System.Length(AFlight) - 9));
end;

end.
