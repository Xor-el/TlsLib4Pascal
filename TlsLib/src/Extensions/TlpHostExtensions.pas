{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpHostExtensions;

{$I ..\Include\TlsLib.inc}

interface

uses
  SysUtils,
  TlpArrayUtilities,
  TlpTlsAlert,
  TlpTlsLibExceptions,
  TlpExtensionContext,
  TlpCoreExtensions,
  TlpGrease,
  TlpITlsExtension,
  TlpITlsHostExtension;

type
  /// <summary>The side of the handshake an engine plays: it sends host extensions in the messages
  /// its role sends and requires them in the messages the other role sends.</summary>
  TTlsHostExtensionRole = (Client, Server);

  /// <summary>
  /// Builds host extensions and wires them into an engine's extension registry. A host
  /// extension is data: the codec places it by its declared messages, the peer's copy is read
  /// back through <see cref="ITlsHostExtensionResults" />, and no host code runs in the handshake.
  /// </summary>
  TTlsHostExtensions = class sealed(TObject)
  strict private
    class procedure Validate(const AExtension: ITlsHostExtension); static;
  public
    /// <summary>A host extension of AExtensionType sent in ASendIn with ABody, which the peer must
    /// carry in ARequiredIn. Raises when the type is a GREASE value or ech_outer_extensions, a set
    /// names a message a host extension cannot ride, or the body exceeds 65535 bytes. A type the
    /// core registry holds is refused when an engine is created.</summary>
    class function Make(AExtensionType: UInt16; ASendIn: TTlsExtensionContexts;
      const ABody: TBytes; ARequiredIn: TTlsExtensionContexts): ITlsHostExtension; static;
    /// <summary>Validates AExtensions for ARole (any implementer, read once; a type listed twice, a
    /// message ARole never sends in SendIn, or one the other role never sends in RequiredIn raises)
    /// and returns the registry entries that carry them, with AResults reading the peer's copies
    /// back.</summary>
    class function Adapt(const AExtensions: TArray<ITlsHostExtension>;
      ARole: TTlsHostExtensionRole;
      out AResults: ITlsHostExtensionResults): TArray<ITlsExtension>; static;
  end;

implementation

const
  ClientSentKinds: TTlsExtensionContexts = [TTlsExtensionContextKind.ClientHello];
  ServerSentKinds: TTlsExtensionContexts = [TTlsExtensionContextKind.HelloRetryRequest,
    TTlsExtensionContextKind.EncryptedExtensions, TTlsExtensionContextKind.CertificateRequest,
    TTlsExtensionContextKind.NewSessionTicket];
  MaxHostExtensionBody = Int32($FFFF);

resourcestring
  SReservedHostExtensionType =
    'a host extension cannot use a GREASE value or ech_outer_extensions as its type';
  SHostExtensionKindNotSupported = 'a host extension can ride only a ClientHello, ' +
    'HelloRetryRequest, EncryptedExtensions, CertificateRequest or NewSessionTicket';
  SHostExtensionBodyTooLong = 'a host extension body must not exceed 65535 bytes';
  SHostExtensionKindWrongRole = 'a client sends host extensions only in the ClientHello and ' +
    'requires them only in messages a server sends; a server does the reverse';
  SDuplicateHostExtension = 'two host extensions share one extension type';
  SNilHostExtension = 'a host extension is nil';
  SRequiredHostExtensionMissing = 'the peer omitted a required host extension';

type
  THostExtension = class sealed(TInterfacedObject, ITlsHostExtension)
  strict private
  var
    FType: UInt16;
    FSendIn: TTlsExtensionContexts;
    FBody: TBytes;
    FRequiredIn: TTlsExtensionContexts;
  public
    constructor Create(AExtensionType: UInt16; ASendIn: TTlsExtensionContexts;
      const ABody: TBytes; ARequiredIn: TTlsExtensionContexts);
    function ExtensionType: UInt16;
    function SendIn: TTlsExtensionContexts;
    function Body: TBytes;
    function RequiredIn: TTlsExtensionContexts;
  end;

  /// <summary>The registry entry for one host extension. It remembers the peer's copy per
  /// message kind, answers a message other than the ClientHello only once the peer's ClientHello
  /// carried the type, and fails the handshake when a required copy is absent.</summary>
  THostExtensionAdapter = class sealed(TInterfacedObject, ITlsExtension,
    IExtensionBlockObserver, ITlsHostExtensionResults)
  strict private
  var
    FType: UInt16;
    FSendIn: TTlsExtensionContexts;
    FRequiredIn: TTlsExtensionContexts;
    FBody: TBytes;
    FPeerSeen: TTlsExtensionContexts;
    FPeerBodies: array[TTlsExtensionContextKind] of TBytes;
  public
    constructor Create(const AExtension: ITlsHostExtension);
    function ExtensionType: UInt16;
    function ValidContexts: TTlsExtensionContexts;
    function Produce(const AContext: TExtensionContext; out ABody: TBytes): Boolean;
    procedure Consume(const AContext: TExtensionContext; const AExtensionData: TBytes);
    procedure BlockStarted(AKind: TTlsExtensionContextKind);
    procedure BlockConsumed(AKind: TTlsExtensionContextKind);
    function TryGetPeerExtension(AType: UInt16; out ABody: TBytes): Boolean;
  end;

  THostExtensionResults = class sealed(TInterfacedObject, ITlsHostExtensionResults)
  strict private
  var
    FAdapters: TArray<ITlsHostExtensionResults>;
  public
    constructor Create(const AAdapters: TArray<ITlsHostExtensionResults>);
    function TryGetPeerExtension(AType: UInt16; out ABody: TBytes): Boolean;
  end;

{ THostExtension }

constructor THostExtension.Create(AExtensionType: UInt16;
  ASendIn: TTlsExtensionContexts; const ABody: TBytes;
  ARequiredIn: TTlsExtensionContexts);
begin
  inherited Create;
  FType := AExtensionType;
  FSendIn := ASendIn;
  FBody := System.Copy(ABody);
  FRequiredIn := ARequiredIn;
end;

function THostExtension.ExtensionType: UInt16;
begin
  Result := FType;
end;

function THostExtension.SendIn: TTlsExtensionContexts;
begin
  Result := FSendIn;
end;

function THostExtension.Body: TBytes;
begin
  Result := System.Copy(FBody);
end;

function THostExtension.RequiredIn: TTlsExtensionContexts;
begin
  Result := FRequiredIn;
end;

{ THostExtensionAdapter }

constructor THostExtensionAdapter.Create(const AExtension: ITlsHostExtension);
begin
  inherited Create;
  FType := AExtension.ExtensionType;
  FSendIn := AExtension.SendIn;
  FRequiredIn := AExtension.RequiredIn;
  FBody := AExtension.Body;
end;

function THostExtensionAdapter.ExtensionType: UInt16;
begin
  Result := FType;
end;

function THostExtensionAdapter.ValidContexts: TTlsExtensionContexts;
begin
  Result := FSendIn + FRequiredIn;
  // an answer implies the peer's offer, so a sender of any other message accepts the ClientHello
  if FSendIn - [TTlsExtensionContextKind.ClientHello] <> [] then
    Include(Result, TTlsExtensionContextKind.ClientHello);
end;

function THostExtensionAdapter.Produce(const AContext: TExtensionContext;
  out ABody: TBytes): Boolean;
begin
  // only a ClientHello is unprompted: every other message answers a peer that offered the type
  Result := (AContext.MessageContext in FSendIn) and
    ((AContext.MessageContext = TTlsExtensionContextKind.ClientHello) or
    (TTlsExtensionContextKind.ClientHello in FPeerSeen));
  if Result then
    ABody := System.Copy(FBody)
  else
    ABody := nil;
end;

procedure THostExtensionAdapter.Consume(const AContext: TExtensionContext;
  const AExtensionData: TBytes);
begin
  Include(FPeerSeen, AContext.MessageContext);
  FPeerBodies[AContext.MessageContext] := System.Copy(AExtensionData);
end;

procedure THostExtensionAdapter.BlockStarted(AKind: TTlsExtensionContextKind);
begin
  // a repeated block of a kind (a second ClientHello) replaces what the first one carried
  Exclude(FPeerSeen, AKind);
  FPeerBodies[AKind] := nil;
end;

procedure THostExtensionAdapter.BlockConsumed(AKind: TTlsExtensionContextKind);
begin
  if (AKind in FRequiredIn) and not (AKind in FPeerSeen) then
    raise EFatalAlertTlsLibException.CreateRes(
      TTlsAlertDescription.MissingExtension, @SRequiredHostExtensionMissing);
end;

function THostExtensionAdapter.TryGetPeerExtension(AType: UInt16;
  out ABody: TBytes): Boolean;
var
  LKind: TTlsExtensionContextKind;
begin
  Result := False;
  ABody := nil;
  if AType <> FType then
    Exit;
  // the earliest message that carried it wins, so a later copy never replaces what was read
  for LKind := Low(TTlsExtensionContextKind) to High(TTlsExtensionContextKind) do
    if LKind in FPeerSeen then
    begin
      ABody := System.Copy(FPeerBodies[LKind]);
      Exit(True);
    end;
end;

{ THostExtensionResults }

constructor THostExtensionResults.Create(
  const AAdapters: TArray<ITlsHostExtensionResults>);
begin
  inherited Create;
  FAdapters := System.Copy(AAdapters);
end;

function THostExtensionResults.TryGetPeerExtension(AType: UInt16;
  out ABody: TBytes): Boolean;
var
  LI: Int32;
begin
  Result := False;
  ABody := nil;
  for LI := 0 to High(FAdapters) do
    if FAdapters[LI].TryGetPeerExtension(AType, ABody) then
      Exit(True);
end;

{ TTlsHostExtensions }

class procedure TTlsHostExtensions.Validate(const AExtension: ITlsHostExtension);
begin
  if TGrease.IsGrease(AExtension.ExtensionType) or
    (AExtension.ExtensionType = TExtensionTypes.EchOuterExtensions) then
    raise EArgumentTlsLibException.CreateRes(@SReservedHostExtensionType);
  if not ((AExtension.SendIn <= (ClientSentKinds + ServerSentKinds)) and
    (AExtension.RequiredIn <= (ClientSentKinds + ServerSentKinds))) then
    raise EArgumentTlsLibException.CreateRes(@SHostExtensionKindNotSupported);
  if System.Length(AExtension.Body) > MaxHostExtensionBody then
    raise EArgumentTlsLibException.CreateRes(@SHostExtensionBodyTooLong);
end;

class function TTlsHostExtensions.Make(AExtensionType: UInt16;
  ASendIn: TTlsExtensionContexts; const ABody: TBytes;
  ARequiredIn: TTlsExtensionContexts): ITlsHostExtension;
begin
  Result := THostExtension.Create(AExtensionType, ASendIn, ABody, ARequiredIn)
    as ITlsHostExtension;
  Validate(Result);
end;

class function TTlsHostExtensions.Adapt(const AExtensions: TArray<ITlsHostExtension>;
  ARole: TTlsHostExtensionRole;
  out AResults: ITlsHostExtensionResults): TArray<ITlsExtension>;
var
  LExt: ITlsExtension;
  LSnapshot: ITlsHostExtension;
  LSnapshots: TArray<ITlsHostExtension>;
  LResults: TArray<ITlsHostExtensionResults>;
  LSendable, LReceivable: TTlsExtensionContexts;
  LI, LJ: Int32;
begin
  Result := nil;
  LResults := nil;
  LSnapshots := nil;
  if ARole = TTlsHostExtensionRole.Client then
  begin
    LSendable := ClientSentKinds;
    LReceivable := ServerSentKinds;
  end
  else
  begin
    LSendable := ServerSentKinds;
    LReceivable := ClientSentKinds;
  end;
  for LI := 0 to High(AExtensions) do
  begin
    if AExtensions[LI] = nil then
      raise EArgumentTlsLibException.CreateRes(@SNilHostExtension);
    // read the implementer once: what is validated is what the adapter carries
    LSnapshot := THostExtension.Create(AExtensions[LI].ExtensionType, AExtensions[LI].SendIn,
      AExtensions[LI].Body, AExtensions[LI].RequiredIn) as ITlsHostExtension;
    Validate(LSnapshot);
    if not ((LSnapshot.SendIn <= LSendable) and (LSnapshot.RequiredIn <= LReceivable)) then
      raise EArgumentTlsLibException.CreateRes(@SHostExtensionKindWrongRole);
    for LJ := 0 to High(LSnapshots) do
      if LSnapshots[LJ].ExtensionType = LSnapshot.ExtensionType then
        raise EArgumentTlsLibException.CreateRes(@SDuplicateHostExtension);
    TArrayUtilities.Append<ITlsHostExtension>(LSnapshots, LSnapshot);
    LExt := THostExtensionAdapter.Create(LSnapshot) as ITlsExtension;
    TArrayUtilities.Append<ITlsExtension>(Result, LExt);
    TArrayUtilities.Append<ITlsHostExtensionResults>(LResults,
      LExt as ITlsHostExtensionResults);
  end;
  AResults := THostExtensionResults.Create(LResults) as ITlsHostExtensionResults;
end;

end.
