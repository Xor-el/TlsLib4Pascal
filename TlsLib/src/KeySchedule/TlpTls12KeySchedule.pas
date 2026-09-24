{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpTls12KeySchedule;

{$I ..\Include\TlsLib.inc}

interface

uses
  SysUtils,
  TlpArrayUtilities,
  TlpBinaryPrimitives,
  TlpCryptoDomainTypes,
  TlpISecretBuffer,
  TlpSecretBuffer,
  TlpICryptoProvider,
  TlpIKeySchedule,
  TlpTrafficKeys,
  TlpTlsLibExceptions,
  TlpSecureMemory;

type
  /// <summary>
  /// The TLS 1.2 key schedule (RFC 5246 6.3 / RFC 7627): PRF-derived master secret
  /// (plain or Extended Master Secret), the key_block split into the AEAD write
  /// keys and implicit-nonce salts that feed the record layer, and the Finished
  /// verify_data. All secrets are ISecretBuffer; intermediate blocks are wiped.
  /// </summary>
  TTls12KeySchedule = class sealed(TInterfacedObject, IKeySchedule,
    ITls12KeySchedule)
  strict private
  var
    FPrf: ITls12Prf;
    FKeyLength: Int32;
    FSaltLength: Int32;
    FPreMaster: ISecretBuffer;
    FClientRandom: TBytes;
    FServerRandom: TBytes;
    FMasterSecret: ISecretBuffer;
    FClientKey: ISecretBuffer;
    FServerKey: ISecretBuffer;
    FClientSalt: ISecretBuffer;
    FServerSalt: ISecretBuffer;
    function Prf(const ASecret: ISecretBuffer; const ALabel: string;
      const ASeed: TBytes; ALength: Int32): ISecretBuffer;
    procedure DeriveMaster(const ALabel: string; const ASeed: TBytes);
    procedure GuardMaster;
    class procedure GuardExportArgs(const ALabel: string; ALength: Int32); static;
    function DoExportKeyingMaterial(const ALabel: string; const AContext: TBytes;
      AUseContext: Boolean; ALength: Int32): TBytes;
  public
    /// <summary>AHash is the PRF hash; AKeyLength the AEAD key size; AAead selects the
    /// implicit-nonce length from the key_block - a 4-byte salt for AES-GCM (RFC 5288) or
    /// the full 12-byte write IV for ChaCha20-Poly1305 (RFC 7905).</summary>
    constructor Create(const ACryptoProvider: ICryptoProvider; AHash: THashAlgorithm;
      AKeyLength: Int32; AAead: TAeadAlgorithm);

    // IKeySchedule
    function TrafficKeys(AEpoch: TTlsEpoch; ADirection: TTlsDirection): ITrafficKeys;
    function ComputeVerifyData(ADirection: TTlsDirection;
      const ATranscriptHash: TBytes): TBytes;
    function VerifyFinished(ADirection: TTlsDirection;
      const ATranscriptHash, APeerVerifyData: TBytes): Boolean;
    function ExportKeyingMaterial(const ALabel: string;
      ALength: Int32): TBytes; overload;
    function ExportKeyingMaterial(const ALabel: string; const AContext: TBytes;
      ALength: Int32): TBytes; overload;

    // ITls12KeySchedule
    procedure SetPreMasterSecret(const APreMasterSecret: ISecretBuffer);
    procedure SetMasterSecret(const AMasterSecret: ISecretBuffer);
    procedure SetRandoms(const AClientRandom, AServerRandom: TBytes);
    procedure DeriveMasterSecret;
    procedure DeriveExtendedMasterSecret(const ASessionHash: TBytes);
    procedure DeriveKeyBlock;
    function MasterSecret: ISecretBuffer;
    procedure ForgetHandshakeSecrets;
  end;

implementation

const
  Tls12MasterSecretLength = Int32(48);
  Tls12VerifyDataLength = Int32(12);
  Tls12AeadSaltLength = Int32(4);
  // ChaCha20-Poly1305 has no explicit nonce; its whole 12-byte write IV comes from the
  // key_block and is XORed with the sequence number per record (RFC 7905)
  Tls12ChaChaIvLength = Int32(12);

resourcestring
  SNoSuchEpoch = 'the TLS 1.2 schedule has only an application-data epoch';
  SMasterNotDerived = 'the master secret has not been derived';
  SKeyBlockNotDerived = 'the key block is unavailable (not derived, or released after the handshake)';
  SExportLengthNotPositive = 'the exported keying material length must be positive';
  SExportLabelNotAscii = 'the exporter label must be ASCII';

{ TTls12KeySchedule }

constructor TTls12KeySchedule.Create(const ACryptoProvider: ICryptoProvider;
  AHash: THashAlgorithm; AKeyLength: Int32; AAead: TAeadAlgorithm);
begin
  inherited Create;
  FPrf := ACryptoProvider.Primitives.CreateTls12Prf(AHash);
  FKeyLength := AKeyLength;
  // ChaCha20-Poly1305 draws a full 12-byte write IV from the key_block (RFC 7905); AES-GCM
  // draws only the 4-byte implicit salt, the 8-byte explicit nonce riding each record
  if AAead = TAeadAlgorithm.CHACHA20_POLY1305 then
    FSaltLength := Tls12ChaChaIvLength
  else
    FSaltLength := Tls12AeadSaltLength;
end;

function TTls12KeySchedule.Prf(const ASecret: ISecretBuffer; const ALabel: string;
  const ASeed: TBytes; ALength: Int32): ISecretBuffer;
begin
  Result := FPrf.Compute(ASecret, ALabel, ASeed, ALength);
end;

procedure TTls12KeySchedule.GuardMaster;
begin
  if FMasterSecret = nil then
    raise EInvalidOperationTlsLibException.CreateRes(@SMasterNotDerived);
end;

class procedure TTls12KeySchedule.GuardExportArgs(const ALabel: string;
  ALength: Int32);
var
  LI: Int32;
begin
  // RFC 5705 exporters need a positive length; a zero-length export is caller misuse. An empty
  // label is legal, but a non-ASCII one would be silently mangled by the ASCII encoding, so reject it
  if ALength <= 0 then
    raise EArgumentTlsLibException.CreateRes(@SExportLengthNotPositive);
  for LI := 1 to System.Length(ALabel) do
    if Ord(ALabel[LI]) > 127 then
      raise EArgumentTlsLibException.CreateRes(@SExportLabelNotAscii);
end;

procedure TTls12KeySchedule.SetRandoms(const AClientRandom, AServerRandom: TBytes);
begin
  FClientRandom := System.Copy(AClientRandom);
  FServerRandom := System.Copy(AServerRandom);
end;

procedure TTls12KeySchedule.DeriveMaster(const ALabel: string; const ASeed: TBytes);
begin
  FMasterSecret := Prf(FPreMaster, ALabel, ASeed, Tls12MasterSecretLength);
  // the pre-master secret is consumed by this one PRF; release it
  FPreMaster := nil;
end;

procedure TTls12KeySchedule.DeriveMasterSecret;
begin
  DeriveMaster('master secret',
    TArrayUtilities.Concat(FClientRandom, FServerRandom));
end;

procedure TTls12KeySchedule.DeriveExtendedMasterSecret(const ASessionHash: TBytes);
begin
  DeriveMaster('extended master secret', ASessionHash);
end;

procedure TTls12KeySchedule.DeriveKeyBlock;
var
  LBlock: ISecretBuffer;
begin
  GuardMaster;
  // AEAD suites have no MAC keys: client_key || server_key || client_salt || server_salt
  LBlock := Prf(FMasterSecret, 'key expansion',
    TArrayUtilities.Concat(FServerRandom, FClientRandom),
    2 * (FKeyLength + FSaltLength));
  FClientKey := TSecretBuffer.Slice(LBlock, 0, FKeyLength);
  FServerKey := TSecretBuffer.Slice(LBlock, FKeyLength, FKeyLength);
  FClientSalt := TSecretBuffer.Slice(LBlock, 2 * FKeyLength, FSaltLength);
  FServerSalt := TSecretBuffer.Slice(LBlock, 2 * FKeyLength + FSaltLength, FSaltLength);
end;

procedure TTls12KeySchedule.SetPreMasterSecret(const APreMasterSecret: ISecretBuffer);
begin
  FPreMaster := APreMasterSecret;
end;

procedure TTls12KeySchedule.SetMasterSecret(const AMasterSecret: ISecretBuffer);
begin
  // an abbreviated handshake reuses the stored master secret verbatim; DeriveKeyBlock
  // then re-expands the key_block under the fresh client and server randoms
  FMasterSecret := AMasterSecret;
end;

function TTls12KeySchedule.MasterSecret: ISecretBuffer;
begin
  Result := FMasterSecret;
end;

function TTls12KeySchedule.TrafficKeys(AEpoch: TTlsEpoch;
  ADirection: TTlsDirection): ITrafficKeys;
begin
  GuardMaster;
  if AEpoch <> TTlsEpoch.Application then
    raise EInvalidOperationTlsLibException.CreateRes(@SNoSuchEpoch);
  if FClientKey = nil then
    raise EInvalidOperationTlsLibException.CreateRes(@SKeyBlockNotDerived);
  if ADirection = TTlsDirection.ClientWrite then
    Result := TTrafficKeys.Create(FClientKey, FClientSalt)
  else
    Result := TTrafficKeys.Create(FServerKey, FServerSalt);
end;

function TTls12KeySchedule.ComputeVerifyData(ADirection: TTlsDirection;
  const ATranscriptHash: TBytes): TBytes;
var
  LLabel: string;
begin
  Result := nil;
  GuardMaster;
  if ADirection = TTlsDirection.ClientWrite then
    LLabel := 'client finished'
  else
    LLabel := 'server finished';
  // verify_data is a public wire value (RFC 5246 7.4.9)
  Result := Prf(FMasterSecret, LLabel, ATranscriptHash, Tls12VerifyDataLength).ToBytes;
end;

function TTls12KeySchedule.VerifyFinished(ADirection: TTlsDirection;
  const ATranscriptHash, APeerVerifyData: TBytes): Boolean;
var
  LExpected: TBytes;
begin
  LExpected := ComputeVerifyData(ADirection, ATranscriptHash);
  try
    Result := TSecureMemory.ConstantTimeAreEqual(LExpected, APeerVerifyData);
  finally
    TSecureMemory.WipeBytes(LExpected);
  end;
end;

function TTls12KeySchedule.ExportKeyingMaterial(const ALabel: string;
  ALength: Int32): TBytes;
begin
  Result := DoExportKeyingMaterial(ALabel, nil, False, ALength);
end;

function TTls12KeySchedule.ExportKeyingMaterial(const ALabel: string;
  const AContext: TBytes; ALength: Int32): TBytes;
begin
  Result := DoExportKeyingMaterial(ALabel, AContext, True, ALength);
end;

function TTls12KeySchedule.DoExportKeyingMaterial(const ALabel: string;
  const AContext: TBytes; AUseContext: Boolean; ALength: Int32): TBytes;
var
  LSeed, LContextLen: TBytes;
begin
  Result := nil;
  GuardExportArgs(ALabel, ALength);
  GuardMaster;
  LSeed := TArrayUtilities.Concat(FClientRandom, FServerRandom);
  // a supplied context contributes a 2-byte length + the context bytes to the seed, even
  // when the context is empty (a zero-length block); no context contributes nothing at all,
  // so the two cases must stay distinct (RFC 5705 4)
  if AUseContext then
  begin
    LContextLen := nil;
    SetLength(LContextLen, 2);
    TBinaryPrimitives.WriteUInt16BigEndian(LContextLen, 0,
      UInt16(System.Length(AContext)));
    LSeed := TArrayUtilities.Concat(LSeed,
      TArrayUtilities.Concat(LContextLen, AContext));
  end;
  // RFC 5705 exported keying material is returned to the caller as public output
  Result := Prf(FMasterSecret, ALabel, LSeed, ALength).ToBytes;
end;

procedure TTls12KeySchedule.ForgetHandshakeSecrets;
begin
  // release the pre-master and the key-block slices once the record layer holds its keys; keep
  // the master secret (it is the RFC 5705 exporter secret for the connection's lifetime) and the
  // public randoms (also exporter seeds)
  FPreMaster := nil;
  FClientKey := nil;
  FServerKey := nil;
  FClientSalt := nil;
  FServerSalt := nil;
end;

end.
