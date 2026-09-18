{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpSessionTicketStrategy;

{$I ..\Include\TlsLib.inc}

interface

uses
  SysUtils,
  TlpTlsVersion,
  TlpCryptoDomainTypes,
  TlpICryptoProvider,
  TlpISecretBuffer,
  TlpSecretBuffer,
  TlpSecureMemory,
  TlpWireReader,
  TlpWireVectorMarker,
  TlpIWireWriter,
  TlpWireWriter,
  TlpISession,
  TlpSession;

type
  /// <summary>
  /// The stateful ticket strategy: an opaque handle into an <see cref="ISessionStore" />.
  /// Seal stores the session and returns its handle; Open removes it (true single-use).
  /// </summary>
  TStoreTicketStrategy = class sealed(TInterfacedObject, ISessionTicketStrategy)
  strict private
  var
    FStore: ISessionStore;
  public
    constructor Create(const AStore: ISessionStore);
    function Seal(const ASession: IResumableSession): TBytes;
    function Open(const ATicket: TBytes; out ASession: IResumableSession): Boolean;
  end;

  /// <summary>
  /// The stateless STEK ticket strategy (the default): AEAD-seals the serialized session
  /// under the current session-ticket key. A ticket is key_name || nonce || AEAD, so no
  /// server state is kept; the AEAD tag authenticates it (constant-time) and the key name
  /// selects a key from the manager's bounded decrypt window. A ticket whose key has
  /// rotated out, or that fails authentication, opens as False.
  /// </summary>
  TStekTicketStrategy = class sealed(TInterfacedObject, ISessionTicketStrategy)
  strict private
  var
    FProvider: ICryptoProvider;
    FKeys: ISessionTicketKeyManager;
    class function SerializeSession(const ASession: IResumableSession): TBytes; static;
    class function DeserializeSession(const AData: TBytes;
      out ASession: IResumableSession): Boolean; static;
    class procedure SerializeChain(const AWriter: IWireWriter;
      const AChain: TArray<TBytes>); static;
    class function DeserializeChain(var AReader: TWireReader): TArray<TBytes>; static;
  public
    constructor Create(const AProvider: ICryptoProvider;
      const AKeys: ISessionTicketKeyManager);
    function Seal(const ASession: IResumableSession): TBytes;
    function Open(const ATicket: TBytes; out ASession: IResumableSession): Boolean;
  end;

  /// <summary>Selects the server's ticket strategy: a configured store upgrades the
  /// stateless STEK default to true single-use handles.</summary>
  TSessionTicketStrategies = class sealed(TObject)
  public
    /// <summary>The store strategy when AStore is set, else the STEK strategy when AKeys
    /// is set, else nil (resumption disabled).</summary>
    class function ForServer(const AProvider: ICryptoProvider;
      const AKeys: ISessionTicketKeyManager;
      const AStore: ISessionStore): ISessionTicketStrategy; static;
  end;

implementation

const
  // bumped when the ticket layout changes; an older ticket fails the version check on Open and
  // simply draws a full handshake. 2 added the SNI host_name (virtual-hosting guard); 3 added the
  // peer certificate chain (so a resumed mTLS connection can surface the client's identity)
  TicketFormatVersion = Byte(3);
  TicketNonceLength = Int32(12); // AES-256-GCM nonce
  // the serialized session carries the peer chain the client volunteered; cap it so an oversized
  // chain does not bloat the ticket and the resumed ClientHello that re-presents it. Past the cap
  // the server issues no ticket for that connection rather than a chain-reduced one
  MaxSerializedSessionLength = Int32(16384);

{ TStoreTicketStrategy }

constructor TStoreTicketStrategy.Create(const AStore: ISessionStore);
begin
  inherited Create;
  FStore := AStore;
end;

function TStoreTicketStrategy.Seal(const ASession: IResumableSession): TBytes;
begin
  Result := FStore.Put(ASession);
end;

function TStoreTicketStrategy.Open(const ATicket: TBytes;
  out ASession: IResumableSession): Boolean;
begin
  Result := FStore.Take(ATicket, ASession);
end;

{ TStekTicketStrategy }

constructor TStekTicketStrategy.Create(const AProvider: ICryptoProvider;
  const AKeys: ISessionTicketKeyManager);
begin
  inherited Create;
  FProvider := AProvider;
  FKeys := AKeys;
end;

class function TStekTicketStrategy.SerializeSession(
  const ASession: IResumableSession): TBytes;
var
  LWriter: IWireWriter;
  LMarker: TWireVectorMarker;
  LIssued: UInt64;
  LResumption, LMaster: TBytes;
begin
  Result := nil;
  LWriter := TWireWriter.Create;
  LWriter.WriteUInt8(TicketFormatVersion);
  LWriter.WriteUInt16(ASession.Version.WireValue);
  LWriter.WriteUInt16(ASession.CipherSuite);
  LWriter.WriteUInt8(Byte(Ord(ASession.Hash)));
  LWriter.WriteUInt16(ASession.NamedGroup);
  LWriter.WriteUInt32(ASession.TicketLifetime);
  LWriter.WriteUInt32(ASession.TicketAgeAdd);
  LIssued := ASession.IssuedAtMillis;
  LWriter.WriteUInt32(UInt32(LIssued shr 32));
  LWriter.WriteUInt32(UInt32(LIssued and $FFFFFFFF));
  LWriter.WriteUInt32(ASession.MaxEarlyData);
  if ASession.ExtendedMasterSecret then
    LWriter.WriteUInt8(1)
  else
    LWriter.WriteUInt8(0);
  LMarker := LWriter.OpenVector(2);
  LWriter.WriteBytes(TEncoding.ASCII.GetBytes(ASession.Alpn));
  LWriter.CloseVector(LMarker);
  // the SNI host_name the session was issued under, bound so a ticket cannot resume as a
  // different virtual host
  LMarker := LWriter.OpenVector(2);
  LWriter.WriteBytes(TEncoding.UTF8.GetBytes(ASession.ServerName));
  LWriter.CloseVector(LMarker);
  LResumption := nil;
  if ASession.ResumptionSecret <> nil then
    LResumption := ASession.ResumptionSecret.ToBytes;
  LMarker := LWriter.OpenVector(2);
  LWriter.WriteBytes(LResumption);
  LWriter.CloseVector(LMarker);
  TSecureMemory.WipeBytes(LResumption);
  LMaster := nil;
  if ASession.MasterSecret <> nil then
    LMaster := ASession.MasterSecret.ToBytes;
  LMarker := LWriter.OpenVector(2);
  LWriter.WriteBytes(LMaster);
  LWriter.CloseVector(LMarker);
  TSecureMemory.WipeBytes(LMaster);
  LMarker := LWriter.OpenVector(1);
  LWriter.WriteBytes(ASession.SessionId);
  LWriter.CloseVector(LMarker);
  LMarker := LWriter.OpenVector(2);
  LWriter.WriteBytes(ASession.SessionTicket);
  LWriter.CloseVector(LMarker);
  SerializeChain(LWriter, ASession.PeerCertificates);
  Result := LWriter.ToBytes;
end;

class procedure TStekTicketStrategy.SerializeChain(const AWriter: IWireWriter;
  const AChain: TArray<TBytes>);
var
  LChain, LCert: TWireVectorMarker;
  LI: Int32;
begin
  // the peer certificate chain as TLS certificate_list: a 3-byte outer length, each cert a
  // 3-byte-length opaque entry, leaf-first, exactly as the peer sent it
  LChain := AWriter.OpenVector(3);
  for LI := 0 to System.Length(AChain) - 1 do
  begin
    LCert := AWriter.OpenVector(3);
    AWriter.WriteBytes(AChain[LI]);
    AWriter.CloseVector(LCert);
  end;
  AWriter.CloseVector(LChain);
end;

class function TStekTicketStrategy.DeserializeChain(
  var AReader: TWireReader): TArray<TBytes>;
var
  LChain, LCert: TWireReader;
  LList: TArray<TBytes>;
  LCount: Int32;
begin
  Result := nil;
  LList := nil;
  LCount := 0;
  LChain := AReader.OpenVector(3);
  while LChain.Remaining > 0 do
  begin
    LCert := LChain.OpenVector(3);
    SetLength(LList, LCount + 1);
    LList[LCount] := LCert.ReadBytes(LCert.Remaining);
    Inc(LCount);
  end;
  Result := LList;
end;

class function TStekTicketStrategy.DeserializeSession(const AData: TBytes;
  out ASession: IResumableSession): Boolean;
var
  LReader, LVec: TWireReader;
  LVersion, LSuite, LGroup: UInt16;
  LHashByte, LEms: Byte;
  LHash: THashAlgorithm;
  LLifetime, LAgeAdd, LMaxEarly, LHi, LLo: UInt32;
  LIssued: UInt64;
  LAlpn, LServerName: string;
  LResumption, LMaster, LSessionId, LSessionTicket: TBytes;
  LPeerChain: TArray<TBytes>;
begin
  ASession := nil;
  Result := False;
  LReader := TWireReader.Create(AData);
  if LReader.ReadUInt8 <> TicketFormatVersion then
    Exit;
  LVersion := LReader.ReadUInt16;
  LSuite := LReader.ReadUInt16;
  LHashByte := LReader.ReadUInt8;
  if LHashByte > Byte(Ord(High(THashAlgorithm))) then
    Exit;
  LHash := THashAlgorithm(LHashByte);
  LGroup := LReader.ReadUInt16;
  LLifetime := LReader.ReadUInt32;
  LAgeAdd := LReader.ReadUInt32;
  LHi := LReader.ReadUInt32;
  LLo := LReader.ReadUInt32;
  LIssued := (UInt64(LHi) shl 32) or UInt64(LLo);
  LMaxEarly := LReader.ReadUInt32;
  LEms := LReader.ReadUInt8;
  LVec := LReader.OpenVector(2);
  LAlpn := TEncoding.ASCII.GetString(LVec.ReadBytes(LVec.Remaining));
  LVec := LReader.OpenVector(2);
  LServerName := TEncoding.UTF8.GetString(LVec.ReadBytes(LVec.Remaining));
  LVec := LReader.OpenVector(2);
  LResumption := LVec.ReadBytes(LVec.Remaining);
  LVec := LReader.OpenVector(2);
  LMaster := LVec.ReadBytes(LVec.Remaining);
  LVec := LReader.OpenVector(1);
  LSessionId := LVec.ReadBytes(LVec.Remaining);
  LVec := LReader.OpenVector(2);
  LSessionTicket := LVec.ReadBytes(LVec.Remaining);
  LPeerChain := DeserializeChain(LReader);

  try
    // an authenticated body with trailing bytes is a format mismatch, not a valid ticket -> full
    // handshake
    if LReader.Remaining <> 0 then
      Exit;
    if LVersion = TlsWireVersionTls13 then
      ASession := TResumableSession.CreateTls13(LSuite, LHash,
        TSecretBuffer.From(LResumption), LGroup, LAlpn, LServerName, nil, LLifetime, LAgeAdd,
        LIssued, LMaxEarly, LPeerChain)
    else if LVersion = TlsWireVersionTls12 then
      ASession := TResumableSession.CreateTls12(LSuite, LHash,
        TSecretBuffer.From(LMaster), LSessionId, LSessionTicket, LEms <> 0, LAlpn, LServerName,
        LLifetime, LAgeAdd, LIssued, LPeerChain)
    else
      Exit;
  finally
    TSecureMemory.WipeBytes(LResumption);
    TSecureMemory.WipeBytes(LMaster);
  end;
  Result := ASession <> nil;
end;

function TStekTicketStrategy.Seal(const ASession: IResumableSession): TBytes;
var
  LKeyName, LNonce, LPlain, LCipher: TBytes;
  LKey: ISecretBuffer;
  LAead: IAead;
begin
  Result := nil;
  if not FKeys.CurrentKey(LKeyName, LKey) then
    Exit;
  LPlain := SerializeSession(ASession);
  // an oversized peer chain would bloat the ticket and the resumed ClientHello; decline to issue
  // rather than degrade it (the caller emits no ticket, leaving the client to full-handshake)
  if System.Length(LPlain) > MaxSerializedSessionLength then
  begin
    TSecureMemory.WipeBytes(LPlain);
    Exit;
  end;
  LNonce := FProvider.Primitives.GetRandom.GenerateBytes(TicketNonceLength);
  LAead := FProvider.Primitives.CreateAead(TAeadAlgorithm.AES_256_GCM);
  LAead.Init(LKey);
  try
    // the key name is authenticated as associated data (it is not secret)
    LCipher := LAead.Seal(LNonce, LKeyName, LPlain);
  finally
    TSecureMemory.WipeBytes(LPlain);
  end;
  SetLength(Result, System.Length(LKeyName) + System.Length(LNonce) +
    System.Length(LCipher));
  Move(LKeyName[0], Result[0], System.Length(LKeyName));
  Move(LNonce[0], Result[System.Length(LKeyName)], System.Length(LNonce));
  Move(LCipher[0], Result[System.Length(LKeyName) + System.Length(LNonce)],
    System.Length(LCipher));
end;

function TStekTicketStrategy.Open(const ATicket: TBytes;
  out ASession: IResumableSession): Boolean;
var
  LKeyName, LNonce, LCipher, LPlain: TBytes;
  LKey: ISecretBuffer;
  LAead: IAead;
  LNameLen: Int32;
begin
  ASession := nil;
  Result := False;
  LNameLen := FKeys.KeyNameLength;
  LAead := FProvider.Primitives.CreateAead(TAeadAlgorithm.AES_256_GCM);
  // key_name || nonce || ciphertext+tag; reject anything shorter than the framing
  if System.Length(ATicket) < LNameLen + TicketNonceLength + LAead.TagSize then
    Exit;
  LKeyName := System.Copy(ATicket, 0, LNameLen);
  if not FKeys.KeyByName(LKeyName, LKey) then
    Exit; // unknown or rotated-out key -> full handshake
  LNonce := System.Copy(ATicket, LNameLen, TicketNonceLength);
  LCipher := System.Copy(ATicket, LNameLen + TicketNonceLength,
    System.Length(ATicket) - LNameLen - TicketNonceLength);
  LAead.Init(LKey);
  try
    LPlain := LAead.Open(LNonce, LKeyName, LCipher);
  except
    // authentication failure (tampered / wrong key) -> full handshake
    Exit;
  end;
  try
    try
      Result := DeserializeSession(LPlain, ASession);
    except
      // belt to the version check's braces: an authenticated body that still fails to parse
      // (a future layout change, a truncated ticket) is unusable, never fatal -> full handshake
      ASession := nil;
      Result := False;
    end;
  finally
    TSecureMemory.WipeBytes(LPlain);
  end;
end;

{ TSessionTicketStrategies }

class function TSessionTicketStrategies.ForServer(const AProvider: ICryptoProvider;
  const AKeys: ISessionTicketKeyManager;
  const AStore: ISessionStore): ISessionTicketStrategy;
begin
  // a configured store upgrades the stateless STEK default to stateful single-use handles
  if AStore <> nil then
    Result := TStoreTicketStrategy.Create(AStore)
  else if AKeys <> nil then
    Result := TStekTicketStrategy.Create(AProvider, AKeys)
  else
    Result := nil;
end;

end.
