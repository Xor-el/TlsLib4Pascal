{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpSessionExtensions;

{$I ..\Include\TlsLib.inc}

interface

uses
  SysUtils,
  TlpTlsLibExceptions,
  TlpWireReader,
  TlpWireVectorMarker,
  TlpIWireWriter,
  TlpWireWriter,
  TlpExtensionContext,
  TlpITlsExtension;

type
  /// <summary>
  /// psk_key_exchange_modes (RFC 8446 4.2.9): the PSK exchange modes the client
  /// offers (psk_ke = 0, psk_dhe_ke = 1). Present only in the ClientHello.
  /// </summary>
  TPskKeyExchangeModesExtension = class sealed(TInterfacedObject, ITlsExtension)
  public
    function ExtensionType: UInt16;
    function ValidContexts: TTlsExtensionContexts;
    function Produce(const AContext: TExtensionContext; out ABody: TBytes): Boolean;
    procedure Consume(const AContext: TExtensionContext; const AExtensionData: TBytes);
  end;

  /// <summary>
  /// early_data (RFC 8446 4.2.10): an empty flag in the ClientHello (offering
  /// 0-RTT) and in EncryptedExtensions (accepting it), and a max_early_data_size
  /// (uint32) in a NewSessionTicket.
  /// </summary>
  TEarlyDataExtension = class sealed(TInterfacedObject, ITlsExtension)
  public
    function ExtensionType: UInt16;
    function ValidContexts: TTlsExtensionContexts;
    function Produce(const AContext: TExtensionContext; out ABody: TBytes): Boolean;
    procedure Consume(const AContext: TExtensionContext; const AExtensionData: TBytes);
  end;

  /// <summary>
  /// session_ticket (RFC 5077): the TLS 1.2 stateless-resumption extension. The
  /// client carries the opaque ticket to resume (or an empty extension to indicate
  /// support); the server echoes it empty to announce it will send a NewSessionTicket.
  /// The extension_data is the raw ticket - the extension's own length delimits it.
  /// </summary>
  TSessionTicketExtension = class sealed(TInterfacedObject, ITlsExtension)
  public
    function ExtensionType: UInt16;
    function ValidContexts: TTlsExtensionContexts;
    function Produce(const AContext: TExtensionContext; out ABody: TBytes): Boolean;
    procedure Consume(const AContext: TExtensionContext; const AExtensionData: TBytes);
  end;

  /// <summary>
  /// pre_shared_key (RFC 8446 4.2.11): the ClientHello OfferedPsks (identities +
  /// obfuscated ages + binders) and the ServerHello selected_identity. It MUST be
  /// the last ClientHello extension - the binders are computed over the transcript
  /// up to their own bytes, so the caller writes a placeholder here and back-patches
  /// the real binders after serialization.
  /// </summary>
  TPreSharedKeyExtension = class sealed(TInterfacedObject, ITlsExtension)
  public
    function ExtensionType: UInt16;
    function ValidContexts: TTlsExtensionContexts;
    function Produce(const AContext: TExtensionContext; out ABody: TBytes): Boolean;
    procedure Consume(const AContext: TExtensionContext; const AExtensionData: TBytes);
  end;

implementation

uses
  TlpCoreExtensions;

resourcestring
  SEmptyPskModes = 'psk_key_exchange_modes carries no modes';
  SBadEarlyData = 'early_data must be empty in this context';
  SBadSessionTicketEcho = 'a server session_ticket acknowledgement must carry an empty body (RFC 5077 3.2)';

{ TPskKeyExchangeModesExtension }

function TPskKeyExchangeModesExtension.ExtensionType: UInt16;
begin
  Result := TExtensionTypes.PskKeyExchangeModes;
end;

function TPskKeyExchangeModesExtension.ValidContexts: TTlsExtensionContexts;
begin
  Result := [TTlsExtensionContextKind.ClientHello];
end;

function TPskKeyExchangeModesExtension.Produce(const AContext: TExtensionContext;
  out ABody: TBytes): Boolean;
var
  LWriter: IWireWriter;
  LMarker: TWireVectorMarker;
  LMode: Byte;
begin
  ABody := nil;
  Result := System.Length(AContext.PskModes) > 0;
  if not Result then
    Exit;
  LWriter := TWireWriter.Create;
  LMarker := LWriter.OpenVector(1); // ke_modes<1..255>
  for LMode in AContext.PskModes do
    LWriter.WriteUInt8(LMode);
  LWriter.CloseVector(LMarker);
  ABody := LWriter.ToBytes;
end;

procedure TPskKeyExchangeModesExtension.Consume(const AContext: TExtensionContext;
  const AExtensionData: TBytes);
var
  LReader, LModes: TWireReader;
  LCount: Int32;
begin
  LReader := TWireReader.Create(AExtensionData);
  LModes := LReader.OpenVector(1);
  LReader.ExpectEnd;
  AContext.PskModes := nil;
  LCount := 0;
  while not LModes.EndReached do
  begin
    SetLength(AContext.PskModes, LCount + 1);
    AContext.PskModes[LCount] := LModes.ReadUInt8;
    Inc(LCount);
  end;
  if LCount = 0 then
    raise EDecodeErrorTlsLibException.CreateRes(@SEmptyPskModes);
end;

{ TEarlyDataExtension }

function TEarlyDataExtension.ExtensionType: UInt16;
begin
  Result := TExtensionTypes.EarlyData;
end;

function TEarlyDataExtension.ValidContexts: TTlsExtensionContexts;
begin
  Result := [TTlsExtensionContextKind.ClientHello,
    TTlsExtensionContextKind.EncryptedExtensions,
    TTlsExtensionContextKind.NewSessionTicket];
end;

function TEarlyDataExtension.Produce(const AContext: TExtensionContext;
  out ABody: TBytes): Boolean;
var
  LWriter: IWireWriter;
begin
  ABody := nil;
  case AContext.MessageContext of
    TTlsExtensionContextKind.ClientHello:
      Result := AContext.EarlyDataOffered;
    TTlsExtensionContextKind.EncryptedExtensions:
      Result := AContext.EarlyDataAccepted;
    TTlsExtensionContextKind.NewSessionTicket:
      begin
        Result := AContext.EarlyDataMaxSize > 0;
        if Result then
        begin
          LWriter := TWireWriter.Create;
          LWriter.WriteUInt32(AContext.EarlyDataMaxSize);
          ABody := LWriter.ToBytes;
        end;
      end;
  else
    Result := False;
  end;
end;

procedure TEarlyDataExtension.Consume(const AContext: TExtensionContext;
  const AExtensionData: TBytes);
var
  LReader: TWireReader;
begin
  if AContext.MessageContext = TTlsExtensionContextKind.NewSessionTicket then
  begin
    LReader := TWireReader.Create(AExtensionData);
    AContext.EarlyDataMaxSize := LReader.ReadUInt32;
    LReader.ExpectEnd;
    Exit;
  end;
  // ClientHello / EncryptedExtensions: the extension_data is empty; presence is the signal
  if System.Length(AExtensionData) <> 0 then
    raise EDecodeErrorTlsLibException.CreateRes(@SBadEarlyData);
  if AContext.MessageContext = TTlsExtensionContextKind.ClientHello then
    AContext.EarlyDataOffered := True
  else
    AContext.EarlyDataAccepted := True;
end;

{ TSessionTicketExtension }

function TSessionTicketExtension.ExtensionType: UInt16;
begin
  Result := TExtensionTypes.SessionTicket;
end;

function TSessionTicketExtension.ValidContexts: TTlsExtensionContexts;
begin
  Result := [TTlsExtensionContextKind.ClientHello,
    TTlsExtensionContextKind.ServerHello];
end;

function TSessionTicketExtension.Produce(const AContext: TExtensionContext;
  out ABody: TBytes): Boolean;
begin
  // the extension_data is exactly the ticket (empty when only signalling support or
  // when a server echoes it to announce a forthcoming NewSessionTicket)
  ABody := System.Copy(AContext.SessionTicket, 0,
    System.Length(AContext.SessionTicket));
  Result := AContext.SessionTicketOffered;
end;

procedure TSessionTicketExtension.Consume(const AContext: TExtensionContext;
  const AExtensionData: TBytes);
begin
  // a server's ServerHello echo announces a forthcoming NewSessionTicket and is empty; a non-empty
  // body there is a decode error (RFC 5077 3.2). The ClientHello carries the ticket itself.
  if (AContext.MessageContext = TTlsExtensionContextKind.ServerHello) and
    (System.Length(AExtensionData) <> 0) then
    raise EDecodeErrorTlsLibException.CreateRes(@SBadSessionTicketEcho);
  AContext.SessionTicketOffered := True;
  AContext.SessionTicket := System.Copy(AExtensionData, 0,
    System.Length(AExtensionData));
end;

{ TPreSharedKeyExtension }

function TPreSharedKeyExtension.ExtensionType: UInt16;
begin
  Result := TExtensionTypes.PreSharedKey;
end;

function TPreSharedKeyExtension.ValidContexts: TTlsExtensionContexts;
begin
  Result := [TTlsExtensionContextKind.ClientHello,
    TTlsExtensionContextKind.ServerHello];
end;

function TPreSharedKeyExtension.Produce(const AContext: TExtensionContext;
  out ABody: TBytes): Boolean;
var
  LWriter: IWireWriter;
  LIdentities, LBinders, LEntry: TWireVectorMarker;
  LI: Int32;
begin
  ABody := nil;
  if AContext.MessageContext = TTlsExtensionContextKind.ServerHello then
  begin
    Result := AContext.PskSelected;
    if not Result then
      Exit;
    LWriter := TWireWriter.Create;
    LWriter.WriteUInt16(AContext.SelectedPskIdentity);
    ABody := LWriter.ToBytes;
    Exit;
  end;
  // ClientHello OfferedPsks: identities + obfuscated ages, then the binder entries
  Result := System.Length(AContext.OfferedPskIdentities) > 0;
  if not Result then
    Exit;
  LWriter := TWireWriter.Create;
  LIdentities := LWriter.OpenVector(2);
  for LI := 0 to High(AContext.OfferedPskIdentities) do
  begin
    LEntry := LWriter.OpenVector(2);
    LWriter.WriteBytes(AContext.OfferedPskIdentities[LI]);
    LWriter.CloseVector(LEntry);
    LWriter.WriteUInt32(AContext.OfferedPskAges[LI]);
  end;
  LWriter.CloseVector(LIdentities);
  LBinders := LWriter.OpenVector(2);
  for LI := 0 to High(AContext.OfferedPskBinders) do
  begin
    LEntry := LWriter.OpenVector(1);
    LWriter.WriteBytes(AContext.OfferedPskBinders[LI]);
    LWriter.CloseVector(LEntry);
  end;
  LWriter.CloseVector(LBinders);
  ABody := LWriter.ToBytes;
end;

procedure TPreSharedKeyExtension.Consume(const AContext: TExtensionContext;
  const AExtensionData: TBytes);
var
  LReader, LIdentities, LBinders, LEntry: TWireReader;
  LIdCount, LBinderCount: Int32;
begin
  if AContext.MessageContext = TTlsExtensionContextKind.ServerHello then
  begin
    LReader := TWireReader.Create(AExtensionData);
    AContext.SelectedPskIdentity := LReader.ReadUInt16;
    LReader.ExpectEnd;
    AContext.PskSelected := True;
    Exit;
  end;
  // ClientHello (server side): parse the OfferedPsks
  LReader := TWireReader.Create(AExtensionData);
  LIdentities := LReader.OpenVector(2);
  AContext.OfferedPskIdentities := nil;
  AContext.OfferedPskAges := nil;
  LIdCount := 0;
  while not LIdentities.EndReached do
  begin
    LEntry := LIdentities.OpenVector(2);
    SetLength(AContext.OfferedPskIdentities, LIdCount + 1);
    AContext.OfferedPskIdentities[LIdCount] := LEntry.ReadBytes(LEntry.Remaining);
    SetLength(AContext.OfferedPskAges, LIdCount + 1);
    AContext.OfferedPskAges[LIdCount] := LIdentities.ReadUInt32;
    Inc(LIdCount);
  end;
  LBinders := LReader.OpenVector(2);
  LReader.ExpectEnd;
  AContext.OfferedPskBinders := nil;
  LBinderCount := 0;
  while not LBinders.EndReached do
  begin
    LEntry := LBinders.OpenVector(1);
    SetLength(AContext.OfferedPskBinders, LBinderCount + 1);
    AContext.OfferedPskBinders[LBinderCount] := LEntry.ReadBytes(LEntry.Remaining);
    Inc(LBinderCount);
  end;
end;

end.
