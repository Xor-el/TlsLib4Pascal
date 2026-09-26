{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpEchClientOrchestrator;

{$I ..\Include\TlsLib.inc}

interface

uses
  SysUtils,
  TlpArrayUtilities,
  TlpSecureMemory,
  TlpTlsAlert,
  TlpTlsLibExceptions,
  TlpICryptoProvider,
  TlpCryptoDomainTypes,
  TlpTls13KeySchedule,
  TlpITranscriptHash,
  TlpTranscriptHash,
  TlpIWireWriter,
  TlpWireWriter,
  TlpWireVectorMarker,
  TlpExtensionVector,
  TlpCoreExtensions,
  TlpHandshakeMessage,
  TlpHandshakeMessages,
  TlpISession,
  TlpIEch,
  TlpIEchClientOrchestrator,
  TlpEchConfig,
  TlpEchExtension,
  TlpEchClient;

type
  /// <summary>
  /// The <see cref="IEchClientOrchestrator" /> implementation: owns the per-connection ECH
  /// state and mechanics for one 1.3 client handshake (see the interface for the contract).
  /// </summary>
  TEchClientOrchestrator = class sealed(TInterfacedObject, IEchClientOrchestrator)
  strict private
  var
    FCrypto: ICryptoProvider;
    FPolicy: IEchClientPolicy;
    FEch: IEchClientHandshake;
    FStatus: TEchStatus;
    FActive: Boolean;
    FGrease: Boolean;
    FGreaseEchExt: TBytes;
    FHrrAccepted: Boolean;
    FHrrDecided: Boolean;
    FInnerRandom: TBytes;
    FInnerTranscript: ITranscriptHash;
    FSentInnerRaw: TBytes;
    FSentOuterEchExt: TBytes;
    FGreasePskIdentities: TArray<TBytes>;
    FGreasePskAges: TArray<TBytes>;
    FSelectedConfig: TEchConfig;
    FSelectedSuite: IHpkeSuite;
    FRetryConfigs: TBytes;
    function BuildGreaseEch: TBytes;
    procedure MintGreasePskIdentities(const APskOffers: TArray<IPreSharedKey>);
    function BuildGreasePskData(const APskOffers: TArray<IPreSharedKey>): TBytes;
    function LocateHrrEchConfirmation(const ARaw: TBytes; out AOffset: Int32): Boolean;
    function FindEchInEncryptedExtensions(const AEeBody: TBytes;
      out AData: TBytes): Boolean;
    function HashUnder(AHash: THashAlgorithm; const AData: TBytes): TBytes;
    class function ServerNameData(const AHost: string): TBytes; static;
  public
    /// <summary>Resolves the ECH posture once (RFC 9849 sec. 6.2 / 6.1): a usable config makes
    /// the connection ECH-active with a fresh inner random and sealer; else GREASE if enabled;
    /// else fail closed. A nil policy leaves ECH not offered.</summary>
    constructor Create(const ACrypto: ICryptoProvider; const APolicy: IEchClientPolicy);
    /// <summary>Creates the inner transcript before the inner ClientHello is built (a single
    /// offered PSK pre-activates it so its binder MACs the inner history).</summary>
    procedure PrepareInnerTranscript(APreActivated: Boolean; AHash: THashAlgorithm);
    /// <summary>Builds the ClientHelloOuter for AMode from the already-built, binder-patched inner
    /// hello AInnerFramed (which it also records as SentInnerRaw), the outer random and session id,
    /// and the offered PSKs (whose count/lengths the GREASE decoy mirrors).</summary>
    function BuildClientHelloOuter(AMode: TEchChMode; const AInnerFramed, AOuterRandom,
      ALegacySessionId: TBytes; const APskOffers: TArray<IPreSharedKey>): TBytes;
    /// <summary>Decides ECH accept vs reject from the ServerHello accept confirmation (RFC 9849
    /// sec. 7.2): activates/rebuilds only the inner transcript under AHash, checks the confirmation
    /// on a clone, cross-checks any HelloRetryRequest verdict, sets Status, and returns True on
    /// accept. It does NOT append the ServerHello to any transcript - the machine adopts the inner
    /// transcript (InnerTranscript) and inner random on accept, or the public_name on reject, and
    /// appends the ServerHello itself.</summary>
    function DecideServerHello(const AServerHelloRaw, AServerRandom: TBytes;
      AHash: THashAlgorithm; ARebuildInnerUnderHash: Boolean): Boolean;
    /// <summary>On a HelloRetryRequest under ECH: decides accept/reject from the HRR ech accept
    /// confirmation and rebases the inner transcript to message_hash(Hash(innerCH1)), HRR.</summary>
    procedure DecideHelloRetryRequest(const AHello: TTlsServerHello;
      const AMessage: TTlsHandshakeMessage; AHash: THashAlgorithm);
    /// <summary>Under GREASE, validate the HelloRetryRequest ech syntactically without acting on
    /// it: a present-but-not-8-byte ech is a decode_error (RFC 9849 sec. 6.2.1).</summary>
    procedure NoteHelloRetryRequestGrease(const ARaw: TBytes);
    /// <summary>Applies the EncryptedExtensions ech rule: unsolicited on accept
    /// (unsupported_extension), retry_configs captured on reject (unless this was a retry),
    /// validated-and-ignored under GREASE.</summary>
    procedure NoteEncryptedExtensions(const AEeBody: TBytes);
    /// <summary>Prunes the GREASE-PSK decoys to the surviving offer indices, keeping them
    /// index-aligned with the machine's pruned pre_shared_key offers across a HelloRetryRequest.</summary>
    procedure KeepPskDecoys(const AKeptIndices: TArray<Int32>);
    function Active: Boolean;
    function Grease: Boolean;
    function Status: TEchStatus;
    function RetryConfigs: TBytes;
    function HrrAccepted: Boolean;
    function HrrDecided: Boolean;
    function InnerRandom: TBytes;
    function InnerTranscript: ITranscriptHash;
    function SentInnerRaw: TBytes;
    function GreaseEchExt: TBytes;
    function InnerEchExt: TBytes;
    function PublicName: string;
  end;

implementation

resourcestring
  SEchExtensionUnregistered = 'the extension registry has no encrypted_client_hello ' +
    'handler, so an ECH ClientHello cannot be built (fail-closed)';
  SEchHrrConfirmationMismatch = 'the ServerHello ECH decision disagrees with the HelloRetryRequest';
  SEchAcceptRetryConfigs = 'the server sent retry_configs after accepting ECH';
  SEchNoUsableConfig = 'the configured ECHConfigList has no usable config (unsupported HPKE ' +
    'suite, invalid public key, or a mandatory unknown extension) and ECH GREASE is not ' +
    'enabled; enable GREASE to connect without ECH';

{ TEchClientOrchestrator }

constructor TEchClientOrchestrator.Create(const ACrypto: ICryptoProvider;
  const APolicy: IEchClientPolicy);
begin
  inherited Create;
  FCrypto := ACrypto;
  FPolicy := APolicy;
  FStatus := TEchStatus.NotOffered;
  // the policy resolved the (config, suite) once at Build; with none usable but GREASE enabled,
  // offer a decoy ech instead (RFC 9849 sec. 6.2), generated once so a HelloRetryRequest re-sends
  // it verbatim
  if APolicy = nil then
    Exit;
  if APolicy.Usable then
  begin
    FSelectedConfig := APolicy.SelectedConfig;
    FSelectedSuite := APolicy.SelectedSuite;
    FActive := True;
    FInnerRandom := ACrypto.Primitives.GetRandom.GenerateBytes(32);
    FEch := TEchClientHandshake.Create(ACrypto, FSelectedConfig, FSelectedSuite);
  end
  else if APolicy.GreaseEnabled then
  begin
    // GREASE needs at least one HPKE suite to imitate; a provider that instantiates none simply
    // sends no decoy rather than failing the handshake
    FGreaseEchExt := BuildGreaseEch;
    if System.Length(FGreaseEchExt) > 0 then
    begin
      FGrease := True;
      FStatus := TEchStatus.Greased;
    end;
  end
  else
    // ECH was requested but no config is usable and GREASE is off: fail closed rather than
    // silently send the true SNI in the clear, defeating the ECH the caller asked for. A
    // caller that would rather connect without ECH enables GREASE to opt into that
    raise EArgumentTlsLibException.CreateRes(@SEchNoUsableConfig);
end;

function TEchClientOrchestrator.Active: Boolean;
begin
  Result := FActive;
end;

function TEchClientOrchestrator.Grease: Boolean;
begin
  Result := FGrease;
end;

function TEchClientOrchestrator.Status: TEchStatus;
begin
  Result := FStatus;
end;

function TEchClientOrchestrator.RetryConfigs: TBytes;
begin
  Result := FRetryConfigs;
end;

function TEchClientOrchestrator.HrrAccepted: Boolean;
begin
  Result := FHrrAccepted;
end;

function TEchClientOrchestrator.HrrDecided: Boolean;
begin
  Result := FHrrDecided;
end;

function TEchClientOrchestrator.InnerRandom: TBytes;
begin
  // a copy: the caller keeps this past the orchestrator's in-place wipe of its inner buffers
  Result := System.Copy(FInnerRandom);
end;

function TEchClientOrchestrator.InnerTranscript: ITranscriptHash;
begin
  Result := FInnerTranscript;
end;

function TEchClientOrchestrator.SentInnerRaw: TBytes;
begin
  // a copy: the caller records this past the orchestrator's in-place wipe of the sent inner
  Result := System.Copy(FSentInnerRaw);
end;

function TEchClientOrchestrator.GreaseEchExt: TBytes;
begin
  Result := FGreaseEchExt;
end;

function TEchClientOrchestrator.InnerEchExt: TBytes;
begin
  Result := TEchExtension.EncodeInner;
end;

function TEchClientOrchestrator.PublicName: string;
begin
  Result := FSelectedConfig.PublicName;
end;

class function TEchClientOrchestrator.ServerNameData(const AHost: string): TBytes;
var
  LWriter: IWireWriter;
  LList, LName: TWireVectorMarker;
  LI: Int32;
begin
  LWriter := TWireWriter.Create;
  LList := LWriter.OpenVector(2);
  LWriter.WriteUInt8(0); // host_name
  LName := LWriter.OpenVector(2);
  for LI := 1 to System.Length(AHost) do
    LWriter.WriteUInt8(Byte(Ord(AHost[LI])));
  LWriter.CloseVector(LName);
  LWriter.CloseVector(LList);
  Result := LWriter.ToBytes;
end;

function TEchClientOrchestrator.HashUnder(AHash: THashAlgorithm;
  const AData: TBytes): TBytes;
var
  LHash: IHash;
begin
  LHash := FCrypto.Primitives.CreateHash(AHash);
  LHash.Update(AData, 0, System.Length(AData));
  Result := LHash.DoFinal;
end;

function TEchClientOrchestrator.BuildGreaseEch: TBytes;
const
  GreaseKem = THpkeKem.DHKEM_X25519_HKDF_SHA256;
var
  LOuter: TEchOuterClientHello;
  LRandom: IRandom;
  LEnc, LSel: TBytes;
  LSuites: TArray<THpkeSuiteId>;
  LSuite: THpkeSuiteId;
  LPayloadLength: Int32;
begin
  LRandom := FCrypto.Primitives.GetRandom;
  // enc is a real KEM encapsulation against a throwaway recipient (not a bare public key), so the
  // decoy is a valid encapsulation for any KEM, not only a DH one where the two happen to coincide
  LEnc := FCrypto.Hpke.RandomEncapsulation(GreaseKem);
  if System.Length(LEnc) = 0 then
    Exit(nil);
  // draw the suite from the ones the provider actually supports (RFC 9849 sec. 6.2), so a fixed
  // value cannot fingerprint the decoy as GREASE and a newly-supported algorithm is picked up
  // automatically - the provider is the single source of the HPKE vocabulary
  LSuites := FCrypto.Hpke.SupportedSuites(GreaseKem);
  if System.Length(LSuites) = 0 then
    Exit(nil);
  LSel := LRandom.GenerateBytes(2);
  LSuite := LSuites[LSel[0] mod System.Length(LSuites)];
  // a sealed ClientHelloInner is padded to a multiple of 32 bytes and then carries a 16-byte
  // AEAD tag; mirror that shape with a per-connection random length so the decoy has no fixed size
  LPayloadLength := (4 + (LSel[1] mod 5)) * 32 + 16;
  LOuter := Default(TEchOuterClientHello);
  LOuter.CipherSuite.KdfId := LSuite.Kdf;
  LOuter.CipherSuite.AeadId := LSuite.Aead;
  LOuter.ConfigId := LRandom.GenerateBytes(1)[0];
  LOuter.Enc := LEnc;
  LOuter.Payload := LRandom.GenerateBytes(LPayloadLength);
  Result := TEchExtension.EncodeOuter(LOuter);
end;

procedure TEchClientOrchestrator.MintGreasePskIdentities(
  const APskOffers: TArray<IPreSharedKey>);
var
  LRandom: IRandom;
  LI: Int32;
begin
  LRandom := FCrypto.Primitives.GetRandom;
  SetLength(FGreasePskIdentities, System.Length(APskOffers));
  SetLength(FGreasePskAges, System.Length(APskOffers));
  for LI := 0 to System.High(APskOffers) do
  begin
    FGreasePskIdentities[LI] :=
      LRandom.GenerateBytes(System.Length(APskOffers[LI].Identity));
    FGreasePskAges[LI] := LRandom.GenerateBytes(4); // retry-stable obfuscated_ticket_age
  end;
end;

function TEchClientOrchestrator.BuildGreasePskData(
  const APskOffers: TArray<IPreSharedKey>): TBytes;
var
  LWriter: IWireWriter;
  LIds, LBinders, LId, LBinder: TWireVectorMarker;
  LI: Int32;
  LRandom: IRandom;
begin
  // the identities and obfuscated ticket ages are the minted, retry-stable values (a real offer
  // re-sends both across a retry); only the binders are drawn fresh here, as a real client
  // recomputes them over the new transcript
  LRandom := FCrypto.Primitives.GetRandom;
  LWriter := TWireWriter.Create;
  LIds := LWriter.OpenVector(2);
  for LI := 0 to System.High(APskOffers) do
  begin
    LId := LWriter.OpenVector(2);
    LWriter.WriteBytes(FGreasePskIdentities[LI]);
    LWriter.CloseVector(LId);
    LWriter.WriteBytes(FGreasePskAges[LI]);
  end;
  LWriter.CloseVector(LIds);
  LBinders := LWriter.OpenVector(2);
  for LI := 0 to System.High(APskOffers) do
  begin
    LBinder := LWriter.OpenVector(1);
    LWriter.WriteBytes(LRandom.GenerateBytes(
      FCrypto.Primitives.CreateHash(APskOffers[LI].Hash).HashSize));
    LWriter.CloseVector(LBinder);
  end;
  LWriter.CloseVector(LBinders);
  Result := LWriter.ToBytes;
end;

procedure TEchClientOrchestrator.PrepareInnerTranscript(APreActivated: Boolean;
  AHash: THashAlgorithm);
begin
  FInnerTranscript := TTranscriptHash.Create;
  if APreActivated then
    FInnerTranscript.Activate(FCrypto.Primitives.CreateHash(AHash));
end;

function TEchClientOrchestrator.BuildClientHelloOuter(AMode: TEchChMode;
  const AInnerFramed, AOuterRandom, ALegacySessionId: TBytes;
  const APskOffers: TArray<IPreSharedKey>): TBytes;
var
  LInnerBody, LOuterBody, LEnc, LEncodedInner, LPayload: TBytes;
  LMsg: TTlsClientHello;
  LEntries, LOuterEntries: TExtensionVector;
  LEchIdx, LPayloadLen: Int32;
  LOuterEch: TEchOuterClientHello;
begin
  // the inner ClientHello was built and binder-patched by the machine; keep it for the inner
  // transcript and parse its entries to derive the outer (RFC 9849 sec. 6.1)
  FSentInnerRaw := AInnerFramed;
  LInnerBody := System.Copy(AInnerFramed, 4, System.Length(AInnerFramed) - 4);
  LMsg := THandshakeMessages.DecodeClientHello(LInnerBody);
  LEntries := TExtensionVector.Parse(LMsg.Extensions);

  // the outer entries: shared extensions stay byte-identical (so they compress), server_name
  // becomes the public_name, the marker becomes the outer ech extension, and the real
  // pre_shared_key becomes a same-shape GREASE offer (RFC 9849 sec. 6.1.2)
  LOuterEntries := LEntries;
  if LOuterEntries.Contains(TExtensionTypes.ServerName) then
    LOuterEntries.SetData(LOuterEntries.IndexOf(TExtensionTypes.ServerName),
      ServerNameData(FSelectedConfig.PublicName));
  if LOuterEntries.Contains(TExtensionTypes.PreSharedKey) then
  begin
    // a retry keeps CH1's GREASE PSK identities and ages (RFC 8446 4.1.2), minted on the first
    // flight; the binders are regenerated each hello so a decoy's CH2 does not carry CH1's binders
    // verbatim the way a real one never would
    if AMode = TEchChMode.Initial then
      MintGreasePskIdentities(APskOffers);
    LOuterEntries.SetData(LOuterEntries.IndexOf(TExtensionTypes.PreSharedKey),
      BuildGreasePskData(APskOffers));
  end;
  // the ClientHelloOuter always presents the public_name (RFC 9849 sec. 6.1), even when the
  // inner offers no server_name; prepend it so the outer is a well-formed public handshake
  if not LOuterEntries.Contains(TExtensionTypes.ServerName) then
    LOuterEntries.InsertAt(0, TExtensionEntry.Create(TExtensionTypes.ServerName,
      ServerNameData(FSelectedConfig.PublicName)));
  LEchIdx := LOuterEntries.IndexOf(TExtensionTypes.EncryptedClientHello);
  // the inner was built with the ech marker via the registry, so it must be present here; its
  // absence means the injected extension registry omits encrypted_client_hello - a build-time
  // misconfiguration, not a wire condition. Fail closed rather than write past the vector.
  if LEchIdx < 0 then
    raise EFatalAlertTlsLibException.CreateRes(
      TTlsAlertDescription.InternalError, @SEchExtensionUnregistered);

  // a rejecting HelloRetryRequest: the server ignored our ech, so CH2's outer ech extension is
  // an exact copy of CH1's (RFC 9849 sec. 6.1.5); the rest of the outer carries the retry's new
  // key_share and cookie, but the ech payload is never re-sealed
  if AMode = TEchChMode.RetryReject then
  begin
    LOuterEntries.SetData(LEchIdx, FSentOuterEchExt);
    LMsg.Random := AOuterRandom;
    LMsg.LegacySessionId := ALegacySessionId;
    LMsg.Extensions := LOuterEntries.Encode;
    Result := THandshakeFraming.Frame(TTlsHandshakeType.ClientHello,
      THandshakeMessages.EncodeClientHello(LMsg));
    Exit;
  end;

  // set up the sealer (fresh enc), or on an accepting HelloRetryRequest reuse the CH1 context
  // with an empty enc and re-seal at seq=1 (RFC 9849 sec. 6.1.5). Then build the encoded inner
  // (compression compares against the outer; the differing ech and server_name never compress)
  if AMode = TEchChMode.RetryAccept then
    LEnc := nil
  else
    LEnc := FEch.SetupSeal;
  LOuterEch := Default(TEchOuterClientHello);
  LOuterEch.CipherSuite.KdfId := FSelectedSuite.Kdf;
  LOuterEch.CipherSuite.AeadId := FSelectedSuite.Aead;
  LOuterEch.ConfigId := FSelectedConfig.ConfigId;
  LOuterEch.Enc := LEnc;
  LOuterEntries.SetData(LEchIdx, TEchExtension.EncodeOuter(LOuterEch));
  LEncodedInner := FEch.BuildEncodedInner(LInnerBody, LOuterEntries);

  // size the payload (plaintext + AEAD tag), place a zero placeholder, and serialize the
  // ClientHelloOuterAAD (RFC 9849 sec. 5.2): the outer body with the ech payload zeroed
  LPayloadLen := System.Length(LEncodedInner) + FSelectedSuite.AeadTagLength;
  System.SetLength(LOuterEch.Payload, LPayloadLen);
  LOuterEntries.SetData(LEchIdx, TEchExtension.EncodeOuter(LOuterEch));
  LMsg.Random := AOuterRandom;
  LMsg.LegacySessionId := ALegacySessionId;
  LMsg.Extensions := LOuterEntries.Encode;
  LOuterBody := THandshakeMessages.EncodeClientHello(LMsg);

  // seal, then patch the real payload into the outer ech extension
  LPayload := FEch.Seal(LOuterBody, LEncodedInner);
  LOuterEch.Payload := LPayload;
  LOuterEntries.SetData(LEchIdx, TEchExtension.EncodeOuter(LOuterEch));
  // keep the outer ech extension so a rejecting HelloRetryRequest can echo it verbatim
  FSentOuterEchExt := LOuterEntries.Entries[LEchIdx].Data;
  LMsg.Extensions := LOuterEntries.Encode;
  Result := THandshakeFraming.Frame(TTlsHandshakeType.ClientHello,
    THandshakeMessages.EncodeClientHello(LMsg));
end;

function TEchClientOrchestrator.DecideServerHello(const AServerHelloRaw,
  AServerRandom: TBytes; AHash: THashAlgorithm;
  ARebuildInnerUnderHash: Boolean): Boolean;
var
  LModifiedSh, LConfHash: TBytes;
  LInnerClone: ITranscriptHash;
  LI: Int32;
begin
  // (re)activate ONLY the inner transcript under the selected hash; the machine handles the
  // outer transcript. When a single pre-activated PSK fixed a hash the server then declined for a
  // different one, rebuild the inner from the raw sent inner (RFC 8446 4.4.1) so the confirmation
  // and key schedule use the right PRF.
  if ARebuildInnerUnderHash then
  begin
    FInnerTranscript := TTranscriptHash.Create(FCrypto.Primitives.CreateHash(AHash));
    FInnerTranscript.Update(FSentInnerRaw);
  end
  else if not FInnerTranscript.IsActive then
    FInnerTranscript.Activate(FCrypto.Primitives.CreateHash(AHash));
  // the accept confirmation is over the inner transcript through a ServerHello whose
  // confirmation bytes of the random are zeroed (RFC 9849 sec. 7.2); computed on a clone so the
  // real ServerHello is appended (by the machine) only to the surviving transcript
  LModifiedSh := System.Copy(AServerHelloRaw);
  for LI := 0 to TEchExtension.ConfirmationLength - 1 do
    LModifiedSh[TEchExtension.FramedServerHelloConfirmationOffset + LI] := 0;
  LInnerClone := FInnerTranscript.Clone;
  LInnerClone.Update(LModifiedSh);
  LConfHash := LInnerClone.CurrentHash;
  Result := TEchClientHandshake.AcceptConfirmationMatches(
    FCrypto.Primitives.CreateHkdf(AHash), FInnerRandom, LConfHash, AServerRandom);
  // if a HelloRetryRequest already decided ECH accept/reject, the ServerHello MUST agree
  // (RFC 9849 sec. 5): a divergence is illegal_parameter
  if FHrrDecided and (Result <> FHrrAccepted) then
    raise EFatalAlertTlsLibException.CreateRes(
      TTlsAlertDescription.IllegalParameter, @SEchHrrConfirmationMismatch);
  if Result then
    FStatus := TEchStatus.Accepted
  else
    FStatus := TEchStatus.Rejected;
end;

function TEchClientOrchestrator.FindEchInEncryptedExtensions(
  const AEeBody: TBytes; out AData: TBytes): Boolean;
var
  LVector: TExtensionVector;
  LEntry: TExtensionEntry;
begin
  AData := nil;
  LVector := TExtensionVector.Parse(AEeBody);
  Result := LVector.TryFind(TExtensionTypes.EncryptedClientHello, LEntry);
  if Result then
    AData := LEntry.Data;
end;

procedure TEchClientOrchestrator.NoteEncryptedExtensions(const AEeBody: TBytes);
var
  LEchData: TBytes;
  LHasEch: Boolean;
begin
  // an encrypted_client_hello in EncryptedExtensions carries retry_configs, valid only in
  // response to the outer ClientHello (a reject). On accept the server processed the inner, so
  // it is an unsolicited extension - unsupported_extension (RFC 9849 sec. 5). On reject, capture
  // the retry_configs unless this handshake was itself a retry (the one-retry cap, sec. 6.1.6).
  LHasEch := FindEchInEncryptedExtensions(AEeBody, LEchData);
  if FStatus = TEchStatus.Accepted then
  begin
    if LHasEch then
      raise EFatalAlertTlsLibException.CreateRes(
        TTlsAlertDescription.UnsupportedExtension, @SEchAcceptRetryConfigs);
  end
  else if LHasEch and (FStatus = TEchStatus.Rejected) then
  begin
    // the retry_configs MUST be a syntactically valid ECHConfigList (RFC 9849 sec. 6.1.6); a
    // malformed one is a decode_error. They are surfaced only on a first attempt - a retry
    // ignores any new configs (the one-retry cap, sec. 6.1.6) but still validates them.
    TEchConfigList.Parse(LEchData);
    if (FPolicy <> nil) and (not FPolicy.IsRetryAttempt) then
      FRetryConfigs := LEchData;
  end
  else if LHasEch and (FStatus = TEchStatus.Greased) then
    // GREASE ignores the retry_configs value (RFC 9849 sec. 6.2), but the extension must still
    // be a well-formed ECHConfigList; a malformed one is a decode_error (Parse raises it)
    TEchConfigList.Parse(LEchData);
end;

function TEchClientOrchestrator.LocateHrrEchConfirmation(const ARaw: TBytes;
  out AOffset: Int32): Boolean;
begin
  Result := TEchExtension.LocateHrrConfirmation(ARaw, AOffset);
end;

procedure TEchClientOrchestrator.DecideHelloRetryRequest(
  const AHello: TTlsServerHello; const AMessage: TTlsHandshakeMessage;
  AHash: THashAlgorithm);
var
  LInnerCh1Hash, LHrrZeroed, LExpected, LActual: TBytes;
  LConf: ITranscriptHash;
  LEchOffset, LI: Int32;
  LHasEch: Boolean;
begin
  FHrrDecided := True;
  // the HRR carries the accept confirmation as its 8-byte encrypted_client_hello payload; its
  // absence means the server did not accept ECH on CH1. The extension's position is not fixed
  // by the RFC, so it is found by parsing rather than assumed to be the last 8 bytes.
  LHrrZeroed := System.Copy(AMessage.Raw);
  LHasEch := LocateHrrEchConfirmation(LHrrZeroed, LEchOffset);
  if LHasEch then
  begin
    LActual := System.Copy(LHrrZeroed, LEchOffset, TEchExtension.ConfirmationLength);
    // transcript_hrr_ech_conf = message_hash(Hash(innerCH1)) then the HRR with that
    // confirmation payload zeroed (RFC 9849 sec. 7.2.1)
    for LI := 0 to TEchExtension.ConfirmationLength - 1 do
      LHrrZeroed[LEchOffset + LI] := 0;
    LInnerCh1Hash := HashUnder(AHash, FSentInnerRaw);
    LConf := TTranscriptHash.Create;
    LConf.SeedWithMessageHash(FCrypto.Primitives.CreateHash(AHash), LInnerCh1Hash);
    LConf.Update(LHrrZeroed);
    LExpected := TTls13KeySchedule.EchHrrAcceptConfirmation(
      FCrypto.Primitives.CreateHkdf(AHash), FInnerRandom, LConf.CurrentHash);
    FHrrAccepted := TSecureMemory.ConstantTimeAreEqual(LExpected, LActual);
  end
  else
  begin
    FHrrAccepted := False;
    LInnerCh1Hash := HashUnder(AHash, FSentInnerRaw);
  end;

  // rebase the inner transcript to message_hash(Hash(innerCH1)), then the HRR (as received)
  FInnerTranscript.SeedWithMessageHash(
    FCrypto.Primitives.CreateHash(AHash), LInnerCh1Hash);
  FInnerTranscript.Update(AMessage.Raw);
end;

procedure TEchClientOrchestrator.NoteHelloRetryRequestGrease(const ARaw: TBytes);
var
  LDummyOffset: Int32;
begin
  LocateHrrEchConfirmation(ARaw, LDummyOffset);
end;

procedure TEchClientOrchestrator.KeepPskDecoys(const AKeptIndices: TArray<Int32>);
var
  LIds, LAges: TArray<TBytes>;
  LI: Int32;
begin
  // the minted GREASE PSK identities and ages (outer decoy) are index-aligned with the machine's
  // pre_shared_key offers; when it prunes offers across a HelloRetryRequest, prune the decoys to
  // the same survivors so each keeps the outer identity and age it carried on CH1. A no-op when
  // no decoys were minted (no PSK offer, or not an ECH handshake).
  if System.Length(FGreasePskIdentities) = 0 then
    Exit;
  LIds := nil;
  LAges := nil;
  for LI := 0 to System.High(AKeptIndices) do
  begin
    TArrayUtilities.Append<TBytes>(LIds, FGreasePskIdentities[AKeptIndices[LI]]);
    TArrayUtilities.Append<TBytes>(LAges, FGreasePskAges[AKeptIndices[LI]]);
  end;
  FGreasePskIdentities := LIds;
  FGreasePskAges := LAges;
end;

end.
