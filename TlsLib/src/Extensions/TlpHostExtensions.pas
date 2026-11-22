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
    /// <summary>Validates AExtensions (any implementer, a type listed twice raises) and returns the
    /// registry entries that carry them, with AResults reading the peer's copies back.</summary>
    class function Adapt(const AExtensions: TArray<ITlsHostExtension>;
      out AResults: ITlsHostExtensionResults): TArray<ITlsExtension>; static;
  end;

implementation

const
  HostExtensionKinds: TTlsExtensionContexts = [TTlsExtensionContextKind.ClientHello,
    TTlsExtensionContextKind.HelloRetryRequest, TTlsExtensionContextKind.EncryptedExtensions,
    TTlsExtensionContextKind.CertificateRequest, TTlsExtensionContextKind.NewSessionTicket];
  MaxHostExtensionBody = Int32($FFFF);

resourcestring
  SReservedHostExtensionType =
    'a host extension cannot use a GREASE value or ech_outer_extensions as its type';
  SHostExtensionKindNotSupported = 'a host extension can ride only a ClientHello, ' +
    'HelloRetryRequest, EncryptedExtensions, CertificateRequest or NewSessionTicket';
  SHostExtensionBodyTooLong = 'a host extension body must not exceed 65535 bytes';
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
  // an offer may be answered by any message that answers one, and an answer implies an offer
  if TTlsExtensionContextKind.ClientHello in FSendIn then
    Result := Result + (HostExtensionKinds - [TTlsExtensionContextKind.ClientHello]);
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
  // the latest message that carried it wins
  for LKind := High(TTlsExtensionContextKind) downto Low(TTlsExtensionContextKind) do
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
  if not ((AExtension.SendIn <= HostExtensionKinds) and
    (AExtension.RequiredIn <= HostExtensionKinds)) then
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
  out AResults: ITlsHostExtensionResults): TArray<ITlsExtension>;
var
  LExt: ITlsExtension;
  LResults: TArray<ITlsHostExtensionResults>;
  LI, LJ: Int32;
begin
  Result := nil;
  LResults := nil;
  for LI := 0 to High(AExtensions) do
  begin
    if AExtensions[LI] = nil then
      raise EArgumentTlsLibException.CreateRes(@SNilHostExtension);
    Validate(AExtensions[LI]);
    for LJ := 0 to LI - 1 do
      if AExtensions[LJ].ExtensionType = AExtensions[LI].ExtensionType then
        raise EArgumentTlsLibException.CreateRes(@SDuplicateHostExtension);
    LExt := THostExtensionAdapter.Create(AExtensions[LI]) as ITlsExtension;
    TArrayUtilities.Append<ITlsExtension>(Result, LExt);
    TArrayUtilities.Append<ITlsHostExtensionResults>(LResults,
      LExt as ITlsHostExtensionResults);
  end;
  AResults := THostExtensionResults.Create(LResults) as ITlsHostExtensionResults;
end;

end.
