{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpExtensionBlockCodec;

{$I ..\Include\TlsLib.inc}

interface

uses
  SysUtils,
  TlpCodeKeyedRegistry,
  TlpTlsAlert,
  TlpTlsLibExceptions,
  TlpExtensionVector,
  TlpExtensionContext,
  TlpITlsExtension;

type
  /// <summary>The default injectable registry: a registration-ordered list of extensions.</summary>
  TExtensionRegistry = class sealed(TCodeKeyedRegistry<ITlsExtension>,
    IExtensionRegistry)
  strict private
    class function CodeOf(const AExtension: ITlsExtension): UInt16; static;
  public
    constructor Create;
  end;

  /// <summary>
  /// Owns all extension-block wire framing and the cross-extension rules of RFC 8446
  /// 4.2: the outer extensions vector, duplicate detection (decode_error), the
  /// unknown-extension skip (which also tolerates GREASE), per-message context
  /// enforcement (wrong context -> illegal_parameter), and the response-only
  /// rule that an extension the ClientHello did not offer is fatal
  /// (unsupported_extension). Individual extensions never see these concerns.
  /// </summary>
  TExtensionBlockCodec = class sealed(TInterfacedObject, IExtensionBlockCodec)
  strict private
  var
    FRegistry: IExtensionRegistry;
    class function IsResponseContext(AKind: TTlsExtensionContextKind): Boolean; static;
  public
    constructor Create(const ARegistry: IExtensionRegistry);
    /// <summary>Serializes the extensions vector for AKind from the shared context.</summary>
    function ProduceBlock(const AContext: TExtensionContext;
      AKind: TTlsExtensionContextKind): TBytes;
    /// <summary>Parses an extensions vector for AKind, applying the 4.2 rules.</summary>
    procedure ConsumeBlock(const AContext: TExtensionContext;
      AKind: TTlsExtensionContextKind; const ABlock: TBytes);
  end;

implementation

resourcestring
  SWrongContextExtension = 'an extension appears in a message it is not allowed in';
  SUnsolicitedExtension = 'the peer sent an extension that was not offered';

{ TExtensionRegistry }

constructor TExtensionRegistry.Create;
begin
  inherited Create(CodeOf);
end;

class function TExtensionRegistry.CodeOf(const AExtension: ITlsExtension): UInt16;
begin
  Result := AExtension.ExtensionType;
end;

{ TExtensionBlockCodec }

constructor TExtensionBlockCodec.Create(const ARegistry: IExtensionRegistry);
begin
  inherited Create;
  FRegistry := ARegistry;
end;

class function TExtensionBlockCodec.IsResponseContext(
  AKind: TTlsExtensionContextKind): Boolean;
begin
  // ServerHello/EncryptedExtensions/Certificate/HelloRetryRequest are responses to the
  // ClientHello and may carry only extensions it offered. ClientHello is unprompted;
  // NewSessionTicket is server-originated post-handshake; and a CertificateRequest carries
  // the server's own constraints (signature_algorithms, certificate_authorities, oid_filters
  // per RFC 8446 4.3.2), which are not gated by client offers - only by each extension's
  // ValidContexts.
  Result := (AKind <> TTlsExtensionContextKind.ClientHello) and
    (AKind <> TTlsExtensionContextKind.NewSessionTicket) and
    (AKind <> TTlsExtensionContextKind.CertificateRequest);
end;

function TExtensionBlockCodec.ProduceBlock(const AContext: TExtensionContext;
  AKind: TTlsExtensionContextKind): TBytes;
var
  LVector: TExtensionVector;
  LAll: TArray<ITlsExtension>;
  LExt: ITlsExtension;
  LBody: TBytes;
  LI: Int32;
begin
  AContext.MessageContext := AKind;
  LVector := TExtensionVector.Empty;
  LAll := FRegistry.Items;
  for LI := 0 to High(LAll) do
  begin
    LExt := LAll[LI];
    if not (AKind in LExt.ValidContexts) then
      Continue;
    if not LExt.Produce(AContext, LBody) then
      Continue;
    LVector.Append(TExtensionEntry.Create(LExt.ExtensionType, LBody));
    if AKind = TTlsExtensionContextKind.ClientHello then
      AContext.MarkOffered(LExt.ExtensionType);
  end;
  Result := LVector.Encode;
end;

procedure TExtensionBlockCodec.ConsumeBlock(const AContext: TExtensionContext;
  AKind: TTlsExtensionContextKind; const ABlock: TBytes);
var
  LVector: TExtensionVector;
  LEntry: TExtensionEntry;
  LType: UInt16;
  LExt: ITlsExtension;
  LI: Int32;
begin
  AContext.MessageContext := AKind;
  // an omitted extensions field (no bytes at all, distinct from a present-but-empty
  // extensions<0..> vector) carries no extensions; only a TLS 1.2 ClientHello/ServerHello may
  // end after compression_method (RFC 5246 7.4.1) - accept it there as the empty offer it is.
  // Every other message (EncryptedExtensions, Certificate, ...) carries a mandatory extensions
  // vector, so an absent one is a decode_error - which TExtensionVector.Parse raises, since it
  // does not treat an empty field as the empty vector
  if (System.Length(ABlock) = 0) and
    (AKind in [TTlsExtensionContextKind.ClientHello,
    TTlsExtensionContextKind.ServerHello]) then
    Exit;

  // the codec owns the structural pass: TExtensionVector.Parse rejects a repeated type
  // (illegal_parameter), bounds the count (decode_error) and forbids trailing bytes
  // (decode_error) - before any semantic rule below, so a duplicated type, even an
  // unoffered/bogus one, is reported as the duplicate it is rather than as unsolicited
  LVector := TExtensionVector.Parse(ABlock);

  // semantic pass: record which types an inbound ClientHello carried (symmetric with the
  // produce path, so the server can enforce presence rules such as RFC 8446 9.2's mutually-
  // required extensions), reject a response extension the ClientHello never offered, and
  // dispatch each known type to its handler (an unknown type, incl. GREASE, is skipped)
  for LI := 0 to LVector.Count - 1 do
  begin
    LEntry := LVector.Entries[LI];
    LType := LEntry.ExtensionType;
    if AKind = TTlsExtensionContextKind.ClientHello then
      AContext.MarkOffered(LType);

    if IsResponseContext(AKind) and not AContext.WasOffered(LType) then
      raise EFatalAlertTlsLibException.CreateRes(
        TTlsAlertDescription.UnsupportedExtension, @SUnsolicitedExtension);

    if FRegistry.TryGet(LType, LExt) then
    begin
      // a recognized extension in a message it is not specified for is illegal_parameter,
      // distinct from the unsolicited-response case above (RFC 8446 4.2)
      if not (AKind in LExt.ValidContexts) then
        raise EFatalAlertTlsLibException.CreateRes(
          TTlsAlertDescription.IllegalParameter, @SWrongContextExtension);
      LExt.Consume(AContext, LEntry.Data);
    end;
  end;
end;

end.
