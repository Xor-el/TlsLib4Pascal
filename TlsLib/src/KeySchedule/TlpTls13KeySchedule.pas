{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpTls13KeySchedule;

{$I ..\Include\TlsLib.inc}

interface

uses
  SysUtils,
  TlpCryptoDomainTypes,
  TlpISecretBuffer,
  TlpSecretBuffer,
  TlpICryptoProvider,
  TlpIKeySchedule,
  TlpTrafficKeys,
  TlpHkdfLabel,
  TlpTlsLibExceptions,
  TlpSecureMemory;

type
  /// <summary>
  /// The TLS 1.3 key schedule (RFC 8446 7.1): the Early -> Handshake -> Master
  /// HKDF-Extract tree, the per-epoch traffic secrets derived from a transcript
  /// hash handed in, the (key, iv) for each, and the Finished MAC. Pure derivation
  /// - a driver installs the results into the record layer. Every secret is an
  /// ISecretBuffer; intermediate extractions are wiped.
  /// </summary>
  TTls13KeySchedule = class sealed(TInterfacedObject, IKeySchedule,
    ITls13KeySchedule)
  strict private
  var
    FCrypto: ICryptoProvider;
    FHkdf: IHkdf;
    FHash: THashAlgorithm;
    FKeyLength: Int32;
    FIvLength: Int32;
    FHashLength: Int32;
    FHashEmpty: TBytes;
    FPsk: ISecretBuffer;
    FSharedSecret: ISecretBuffer;
    FEarlySecret: ISecretBuffer;
    FHandshakeSecret: ISecretBuffer;
    FMasterSecret: ISecretBuffer;
    FClientEarlyTraffic: ISecretBuffer;
    FClientHsTraffic: ISecretBuffer;
    FServerHsTraffic: ISecretBuffer;
    FClientApTraffic: ISecretBuffer;
    FServerApTraffic: ISecretBuffer;
    FExporterMaster: ISecretBuffer;
    FResumptionMaster: ISecretBuffer;
    FHandshakeSecretsReleased: Boolean;
    function ZeroSecret: ISecretBuffer;
    function HashOf(const AData: TBytes): TBytes;
    procedure EnsureEarlySecret;
    procedure EnsureHandshakeSecret;
    procedure EnsureMasterSecret;
    function HandshakeTrafficSecret(ADirection: TTlsDirection): ISecretBuffer;
    function EpochSecret(AEpoch: TTlsEpoch; ADirection: TTlsDirection): ISecretBuffer;
    function ExpandKey(const ASecret: ISecretBuffer; const ALabel: string;
      ALength: Int32): ISecretBuffer;
    function DoExportKeyingMaterial(const ALabel: string; const AContext: TBytes;
      AUseContext: Boolean; ALength: Int32): TBytes;
    class procedure GuardExportArgs(const ALabel: string; ALength: Int32); static;
    class function EchConfirmation(const AHkdf: IHkdf; const ALabel: string;
      const AInnerRandom, ATranscriptHash: TBytes): TBytes; static;
  public
    /// <summary>AHash is the suite hash; AKeyLength the AEAD key size.</summary>
    constructor Create(const ACryptoProvider: ICryptoProvider; AHash: THashAlgorithm;
      AKeyLength: Int32);

    /// <summary>
    /// The ECH ServerHello accept confirmation (RFC 9849 sec. 7.2): the 8 bytes the
    /// backend writes over ServerHello.random[24..32] and the client recomputes.
    /// AInnerRandom is ClientHelloInner.random; ATranscriptEchConf is
    /// Transcript-Hash(ClientHelloInner...ServerHello) with those 8 random bytes zeroed.
    /// A class function because on the server the key schedule does not yet exist when
    /// the ServerHello is built; AHkdf carries the negotiated suite's hash.
    /// </summary>
    class function EchAcceptConfirmation(const AHkdf: IHkdf;
      const AInnerRandom, ATranscriptEchConf: TBytes): TBytes; static;
    /// <summary>
    /// The ECH HelloRetryRequest accept confirmation (RFC 9849 sec. 7.2.1): the 8 bytes
    /// written over the HRR encrypted_client_hello payload. AInnerRandom is
    /// ClientHelloInner1.random; ATranscriptHrrEchConf is
    /// Transcript-Hash(message_hash(ClientHelloInner1)...HelloRetryRequest) with the
    /// HRR ech payload zeroed.
    /// </summary>
    class function EchHrrAcceptConfirmation(const AHkdf: IHkdf;
      const AInnerRandom, ATranscriptHrrEchConf: TBytes): TBytes; static;

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

    // ITls13KeySchedule
    procedure SetPsk(const APsk: ISecretBuffer);
    procedure SetSharedSecret(const ASharedSecret: ISecretBuffer);
    procedure DeriveEpochSecrets(AEpoch: TTlsEpoch; const ATranscriptHash: TBytes);
    function FinishedKey(ADirection: TTlsDirection): ISecretBuffer;
    procedure AdvanceKeyUpdate(ADirection: TTlsDirection);
    procedure ForgetHandshakeSecrets;
    function HasExporterSecret: Boolean;
    procedure DeriveResumptionMasterSecret(const ATranscriptHash: TBytes);
    function ResumptionMasterSecret: ISecretBuffer;
    function ResumptionPsk(const ATicketNonce: TBytes): ISecretBuffer;
    function BinderKey(AKind: TPskBinderKind): ISecretBuffer;
    function ComputeBinder(AKind: TPskBinderKind;
      const ATruncatedTranscriptHash: TBytes): TBytes;
    function VerifyBinder(AKind: TPskBinderKind;
      const ATruncatedTranscriptHash, APeerBinder: TBytes): Boolean;
  end;

implementation

uses
  TlpEchExtension;

const
  Tls13IvLength = Int32(12);

resourcestring
  SEpochNotDerived = 'the requested epoch secrets have not been derived';
  SHandshakeSecretsReleased = 'the handshake secrets have been released';
  SResumptionMasterNotDerived = 'the resumption master secret has not been derived';
  SForgetBeforeApplication =
    'the application epoch must be derived before releasing the handshake secrets';
  SExportLengthNotPositive = 'the exported keying material length must be positive';
  SExportLabelNotAscii = 'the exporter label must be ASCII';

{ TTls13KeySchedule }

constructor TTls13KeySchedule.Create(const ACryptoProvider: ICryptoProvider;
  AHash: THashAlgorithm; AKeyLength: Int32);
var
  LHash: IHash;
begin
  inherited Create;
  FCrypto := ACryptoProvider;
  FHash := AHash;
  FKeyLength := AKeyLength;
  FIvLength := Tls13IvLength;
  FHkdf := ACryptoProvider.Primitives.CreateHkdf(AHash);
  LHash := ACryptoProvider.Primitives.CreateHash(AHash);
  FHashLength := LHash.HashSize;
  FHashEmpty := LHash.DoFinal; // hash of the empty input
end;

function TTls13KeySchedule.ZeroSecret: ISecretBuffer;
begin
  Result := TSecretBuffer.Allocate(FHashLength);
end;

function TTls13KeySchedule.HashOf(const AData: TBytes): TBytes;
var
  LHash: IHash;
begin
  Result := nil;
  LHash := FCrypto.Primitives.CreateHash(FHash);
  if System.Length(AData) > 0 then
    LHash.Update(AData, 0, System.Length(AData));
  Result := LHash.DoFinal;
end;

procedure TTls13KeySchedule.EnsureEarlySecret;
var
  LIkm: ISecretBuffer;
begin
  if FEarlySecret <> nil then
    Exit;
  if FHandshakeSecretsReleased then
    raise EInvalidOperationTlsLibException.CreateRes(@SHandshakeSecretsReleased);
  if FPsk <> nil then
    LIkm := FPsk
  else
    LIkm := ZeroSecret;
  // an empty salt is treated as HashLen zeros by the provider
  FEarlySecret := FHkdf.Extract(nil, LIkm);
  // the PSK is consumed by this one Extract; release it (the binder key derives from the early
  // secret, not the PSK)
  FPsk := nil;
end;

procedure TTls13KeySchedule.EnsureHandshakeSecret;
var
  LSalt, LIkm: ISecretBuffer;
begin
  if FHandshakeSecret <> nil then
    Exit;
  if FHandshakeSecretsReleased then
    raise EInvalidOperationTlsLibException.CreateRes(@SHandshakeSecretsReleased);
  EnsureEarlySecret;
  // the derived-secret salt is a wiped buffer end to end - no bare-bytes copy to scrub
  LSalt := THkdfLabel.DeriveSecret(FHkdf, FEarlySecret, 'derived', FHashEmpty);
  if FSharedSecret <> nil then
    LIkm := FSharedSecret
  else
    LIkm := ZeroSecret;
  FHandshakeSecret := FHkdf.Extract(LSalt, LIkm);
  // the (EC)DHE shared secret is consumed by this one Extract; release it
  FSharedSecret := nil;
end;

procedure TTls13KeySchedule.EnsureMasterSecret;
var
  LSalt: ISecretBuffer;
begin
  if FMasterSecret <> nil then
    Exit;
  if FHandshakeSecretsReleased then
    raise EInvalidOperationTlsLibException.CreateRes(@SHandshakeSecretsReleased);
  EnsureHandshakeSecret;
  LSalt := THkdfLabel.DeriveSecret(FHkdf, FHandshakeSecret, 'derived', FHashEmpty);
  FMasterSecret := FHkdf.Extract(LSalt, ZeroSecret);
end;

function TTls13KeySchedule.HandshakeTrafficSecret(ADirection: TTlsDirection): ISecretBuffer;
begin
  if ADirection = TTlsDirection.ClientWrite then
    Result := FClientHsTraffic
  else
    Result := FServerHsTraffic;
end;

function TTls13KeySchedule.EpochSecret(AEpoch: TTlsEpoch;
  ADirection: TTlsDirection): ISecretBuffer;
begin
  case AEpoch of
    TTlsEpoch.EarlyData:
      if ADirection = TTlsDirection.ClientWrite then
        Result := FClientEarlyTraffic
      else
        Result := nil;
    TTlsEpoch.Handshake:
      Result := HandshakeTrafficSecret(ADirection);
    TTlsEpoch.Application:
      if ADirection = TTlsDirection.ClientWrite then
        Result := FClientApTraffic
      else
        Result := FServerApTraffic;
  else
    Result := nil;
  end;
end;

function TTls13KeySchedule.ExpandKey(const ASecret: ISecretBuffer;
  const ALabel: string; ALength: Int32): ISecretBuffer;
begin
  Result := THkdfLabel.HkdfExpandLabel(FHkdf, ASecret, ALabel, nil, ALength);
end;

class function TTls13KeySchedule.EchConfirmation(const AHkdf: IHkdf;
  const ALabel: string; const AInnerRandom, ATranscriptHash: TBytes): TBytes;
var
  LPrk: ISecretBuffer;
begin
  // HKDF-Extract(0, ClientHelloInner.random): a HashLen-zero salt over the inner
  // random as IKM (the random is public; the seam types IKM as a secret)
  LPrk := AHkdf.Extract(nil, TSecretBuffer.From(AInnerRandom));
  Result := THkdfLabel.HkdfExpandLabel(AHkdf, LPrk, ALabel, ATranscriptHash,
    TEchExtension.ConfirmationLength).ToBytes;
end;

class function TTls13KeySchedule.EchAcceptConfirmation(const AHkdf: IHkdf;
  const AInnerRandom, ATranscriptEchConf: TBytes): TBytes;
begin
  Result := EchConfirmation(AHkdf, 'ech accept confirmation', AInnerRandom,
    ATranscriptEchConf);
end;

class function TTls13KeySchedule.EchHrrAcceptConfirmation(const AHkdf: IHkdf;
  const AInnerRandom, ATranscriptHrrEchConf: TBytes): TBytes;
begin
  Result := EchConfirmation(AHkdf, 'hrr ech accept confirmation', AInnerRandom,
    ATranscriptHrrEchConf);
end;

procedure TTls13KeySchedule.SetPsk(const APsk: ISecretBuffer);
begin
  if FHandshakeSecretsReleased then
    raise EInvalidOperationTlsLibException.CreateRes(@SHandshakeSecretsReleased);
  FPsk := APsk;
end;

procedure TTls13KeySchedule.SetSharedSecret(const ASharedSecret: ISecretBuffer);
begin
  if FHandshakeSecretsReleased then
    raise EInvalidOperationTlsLibException.CreateRes(@SHandshakeSecretsReleased);
  FSharedSecret := ASharedSecret;
end;

procedure TTls13KeySchedule.DeriveEpochSecrets(AEpoch: TTlsEpoch;
  const ATranscriptHash: TBytes);
begin
  case AEpoch of
    TTlsEpoch.EarlyData:
      begin
        EnsureEarlySecret;
        FClientEarlyTraffic := THkdfLabel.DeriveSecret(FHkdf, FEarlySecret,
          'c e traffic', ATranscriptHash);
      end;
    TTlsEpoch.Handshake:
      begin
        EnsureHandshakeSecret;
        FClientHsTraffic := THkdfLabel.DeriveSecret(FHkdf, FHandshakeSecret,
          'c hs traffic', ATranscriptHash);
        FServerHsTraffic := THkdfLabel.DeriveSecret(FHkdf, FHandshakeSecret,
          's hs traffic', ATranscriptHash);
      end;
    TTlsEpoch.Application:
      begin
        EnsureMasterSecret;
        FClientApTraffic := THkdfLabel.DeriveSecret(FHkdf, FMasterSecret,
          'c ap traffic', ATranscriptHash);
        FServerApTraffic := THkdfLabel.DeriveSecret(FHkdf, FMasterSecret,
          's ap traffic', ATranscriptHash);
        FExporterMaster := THkdfLabel.DeriveSecret(FHkdf, FMasterSecret,
          'exp master', ATranscriptHash);
      end;
  end;
end;

function TTls13KeySchedule.TrafficKeys(AEpoch: TTlsEpoch;
  ADirection: TTlsDirection): ITrafficKeys;
var
  LSecret: ISecretBuffer;
begin
  LSecret := EpochSecret(AEpoch, ADirection);
  if LSecret = nil then
    raise EInvalidOperationTlsLibException.CreateRes(@SEpochNotDerived);
  Result := TTrafficKeys.Create(ExpandKey(LSecret, 'key', FKeyLength),
    ExpandKey(LSecret, 'iv', FIvLength));
end;

function TTls13KeySchedule.FinishedKey(ADirection: TTlsDirection): ISecretBuffer;
var
  LSecret: ISecretBuffer;
begin
  LSecret := HandshakeTrafficSecret(ADirection);
  if LSecret = nil then
    raise EInvalidOperationTlsLibException.CreateRes(@SEpochNotDerived);
  Result := ExpandKey(LSecret, 'finished', FHashLength);
end;

function TTls13KeySchedule.ComputeVerifyData(ADirection: TTlsDirection;
  const ATranscriptHash: TBytes): TBytes;
var
  LHmac: IHmac;
begin
  Result := nil;
  LHmac := FCrypto.Primitives.CreateHmac(FHash);
  LHmac.Init(FinishedKey(ADirection));
  LHmac.Update(ATranscriptHash, 0, System.Length(ATranscriptHash));
  Result := LHmac.DoFinal;
end;

function TTls13KeySchedule.VerifyFinished(ADirection: TTlsDirection;
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

procedure TTls13KeySchedule.AdvanceKeyUpdate(ADirection: TTlsDirection);
var
  LOld: ISecretBuffer;
begin
  if ADirection = TTlsDirection.ClientWrite then
    LOld := FClientApTraffic
  else
    LOld := FServerApTraffic;
  if LOld = nil then
    raise EInvalidOperationTlsLibException.CreateRes(@SEpochNotDerived);
  if ADirection = TTlsDirection.ClientWrite then
    FClientApTraffic := ExpandKey(LOld, 'traffic upd', FHashLength)
  else
    FServerApTraffic := ExpandKey(LOld, 'traffic upd', FHashLength);
end;

function TTls13KeySchedule.ExportKeyingMaterial(const ALabel: string;
  ALength: Int32): TBytes;
begin
  Result := DoExportKeyingMaterial(ALabel, nil, False, ALength);
end;

function TTls13KeySchedule.ExportKeyingMaterial(const ALabel: string;
  const AContext: TBytes; ALength: Int32): TBytes;
begin
  Result := DoExportKeyingMaterial(ALabel, AContext, True, ALength);
end;

class procedure TTls13KeySchedule.GuardExportArgs(const ALabel: string;
  ALength: Int32);
var
  LI: Int32;
begin
  // RFC 8446 7.5 exporters need a positive length; a zero-length export is caller misuse. A
  // non-ASCII label would be mangled by the label encoding, so reject it
  if ALength <= 0 then
    raise EArgumentTlsLibException.CreateRes(@SExportLengthNotPositive);
  for LI := 1 to System.Length(ALabel) do
    if Ord(ALabel[LI]) > 127 then
      raise EArgumentTlsLibException.CreateRes(@SExportLabelNotAscii);
end;

function TTls13KeySchedule.DoExportKeyingMaterial(const ALabel: string;
  const AContext: TBytes; AUseContext: Boolean; ALength: Int32): TBytes;
var
  LDerived: ISecretBuffer;
  LContextHash: TBytes;
begin
  Result := nil;
  GuardExportArgs(ALabel, ALength);
  if FExporterMaster = nil then
    raise EInvalidOperationTlsLibException.CreateRes(@SEpochNotDerived);
  // TLS 1.3 always hashes a context value; no context is exactly an empty context, so the
  // AUseContext distinction that matters in TLS 1.2 has no effect here (RFC 8446 7.5)
  LDerived := THkdfLabel.DeriveSecret(FHkdf, FExporterMaster, ALabel, FHashEmpty);
  LContextHash := HashOf(AContext);
  Result := THkdfLabel.HkdfExpandLabel(FHkdf, LDerived, 'exporter', LContextHash,
    ALength).ToBytes;
end;

procedure TTls13KeySchedule.ForgetHandshakeSecrets;
begin
  if FExporterMaster = nil then
    raise EInvalidOperationTlsLibException.CreateRes(@SForgetBeforeApplication);
  FPsk := nil;
  FSharedSecret := nil;
  FEarlySecret := nil;
  FHandshakeSecret := nil;
  FMasterSecret := nil;
  FClientEarlyTraffic := nil;
  FClientHsTraffic := nil;
  FServerHsTraffic := nil;
  FHandshakeSecretsReleased := True;
end;

function TTls13KeySchedule.HasExporterSecret: Boolean;
begin
  // set when the Application epoch secrets are derived (a KeyUpdate never touches it)
  Result := FExporterMaster <> nil;
end;

procedure TTls13KeySchedule.DeriveResumptionMasterSecret(
  const ATranscriptHash: TBytes);
begin
  EnsureMasterSecret;
  FResumptionMaster := THkdfLabel.DeriveSecret(FHkdf, FMasterSecret, 'res master',
    ATranscriptHash);
end;

function TTls13KeySchedule.ResumptionMasterSecret: ISecretBuffer;
begin
  if FResumptionMaster = nil then
    raise EInvalidOperationTlsLibException.CreateRes(@SResumptionMasterNotDerived);
  Result := FResumptionMaster;
end;

function TTls13KeySchedule.ResumptionPsk(
  const ATicketNonce: TBytes): ISecretBuffer;
begin
  Result := THkdfLabel.HkdfExpandLabel(FHkdf, ResumptionMasterSecret, 'resumption',
    ATicketNonce, FHashLength);
end;

function TTls13KeySchedule.BinderKey(AKind: TPskBinderKind): ISecretBuffer;
var
  LLabel: string;
begin
  EnsureEarlySecret;
  case AKind of
    TPskBinderKind.Resumption:
      LLabel := 'res binder';
    TPskBinderKind.External:
      LLabel := 'ext binder';
  else
    LLabel := 'imp binder';
  end;
  // Derive-Secret(early_secret, label, "") - the context is Hash("")
  Result := THkdfLabel.DeriveSecret(FHkdf, FEarlySecret, LLabel, FHashEmpty);
end;

function TTls13KeySchedule.ComputeBinder(AKind: TPskBinderKind;
  const ATruncatedTranscriptHash: TBytes): TBytes;
var
  LBinderKey, LFinishedKey: ISecretBuffer;
  LHmac: IHmac;
begin
  Result := nil;
  LBinderKey := BinderKey(AKind);
  LFinishedKey := THkdfLabel.HkdfExpandLabel(FHkdf, LBinderKey, 'finished', nil,
    FHashLength);
  LHmac := FCrypto.Primitives.CreateHmac(FHash);
  LHmac.Init(LFinishedKey);
  LHmac.Update(ATruncatedTranscriptHash, 0,
    System.Length(ATruncatedTranscriptHash));
  Result := LHmac.DoFinal;
end;

function TTls13KeySchedule.VerifyBinder(AKind: TPskBinderKind;
  const ATruncatedTranscriptHash, APeerBinder: TBytes): Boolean;
var
  LExpected: TBytes;
begin
  LExpected := ComputeBinder(AKind, ATruncatedTranscriptHash);
  try
    Result := TSecureMemory.ConstantTimeAreEqual(LExpected, APeerBinder);
  finally
    TSecureMemory.WipeBytes(LExpected);
  end;
end;

end.
