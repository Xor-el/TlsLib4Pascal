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
  TlpIKeyLog,
  TlpKeyLog,
  TlpTrafficKeys,
  TlpHkdfLabel,
  TlpTlsLibExceptions,
  TlpExporterArgs,
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
    FEarlyExporterMaster: ISecretBuffer;
    FResumptionMaster: ISecretBuffer;
    FHandshakeSecretsReleased: Boolean;
    FKeyLog: IKeyLog;
    FClientRandom: TBytes;
    FClientTrafficGeneration: Int32;
    FServerTrafficGeneration: Int32;
    procedure LogSecret(const ALabel: string; const ASecret: ISecretBuffer);
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
    function ExportFrom(const AMaster: ISecretBuffer; const ALabel: string;
      const AContext: TBytes; ALength: Int32): TBytes;
  public
    /// <summary>AHash is the suite hash; AKeyLength the AEAD key size.</summary>
    constructor Create(const ACryptoProvider: ICryptoProvider; AHash: THashAlgorithm;
      AKeyLength: Int32);

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
    function CanExportEarly: Boolean;
    function ExportEarlyKeyingMaterial(const ALabel: string; const AContext: TBytes;
      ALength: Int32): TBytes;
    procedure SetPsk(const APsk: ISecretBuffer);
    procedure SetSharedSecret(const ASharedSecret: ISecretBuffer);
    procedure DeriveEpochSecrets(AEpoch: TTlsEpoch; const ATranscriptHash: TBytes);
    function FinishedKey(ADirection: TTlsDirection): ISecretBuffer;
    procedure AdvanceKeyUpdate(ADirection: TTlsDirection);
    procedure ForgetHandshakeSecrets;
    procedure SetKeyLog(const AKeyLog: IKeyLog; const AClientRandom: TBytes);
    function CanExport: Boolean;
    procedure ForgetResumptionMasterSecret;
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

const
  Tls13IvLength = Int32(12);

resourcestring
  SEpochNotDerived = 'the requested epoch secrets have not been derived';
  SHandshakeSecretsReleased = 'the handshake secrets have been released';
  SPskAfterEarlySecret = 'the pre-shared key must be set before the early secret is derived';
  SSharedSecretAfterHandshake =
    'the shared secret must be set before the handshake secret is derived';
  SResumptionMasterNotDerived = 'the resumption master secret has not been derived';
  SForgetBeforeApplication =
    'the application epoch must be derived before releasing the handshake secrets';

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

procedure TTls13KeySchedule.LogSecret(const ALabel: string;
  const ASecret: ISecretBuffer);
var
  LCopy: TBytes;
begin
  if (FKeyLog = nil) or (ASecret = nil) then
    Exit;
  // the log is a deliberate secret exposure; read a copy only when a sink is present and wipe it
  LCopy := ASecret.ToBytes;
  try
    FKeyLog.Log(ALabel, FClientRandom, LCopy);
  finally
    TSecureMemory.WipeBytes(LCopy);
  end;
end;

procedure TTls13KeySchedule.SetKeyLog(const AKeyLog: IKeyLog;
  const AClientRandom: TBytes);
begin
  FKeyLog := AKeyLog;
  FClientRandom := System.Copy(AClientRandom);
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


procedure TTls13KeySchedule.SetPsk(const APsk: ISecretBuffer);
begin
  if FHandshakeSecretsReleased then
    raise EInvalidOperationTlsLibException.CreateRes(@SHandshakeSecretsReleased);
  // setting the PSK after the early secret is derived would silently not take effect
  if FEarlySecret <> nil then
    raise EInvalidOperationTlsLibException.CreateRes(@SPskAfterEarlySecret);
  FPsk := APsk;
end;

procedure TTls13KeySchedule.SetSharedSecret(const ASharedSecret: ISecretBuffer);
begin
  if FHandshakeSecretsReleased then
    raise EInvalidOperationTlsLibException.CreateRes(@SHandshakeSecretsReleased);
  if FHandshakeSecret <> nil then
    raise EInvalidOperationTlsLibException.CreateRes(@SSharedSecretAfterHandshake);
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
        FEarlyExporterMaster := THkdfLabel.DeriveSecret(FHkdf, FEarlySecret,
          'e exp master', ATranscriptHash);
        LogSecret(KeyLogLabelClientEarlyTraffic, FClientEarlyTraffic);
        LogSecret(KeyLogLabelEarlyExporter, FEarlyExporterMaster);
      end;
    TTlsEpoch.Handshake:
      begin
        EnsureHandshakeSecret;
        FClientHsTraffic := THkdfLabel.DeriveSecret(FHkdf, FHandshakeSecret,
          'c hs traffic', ATranscriptHash);
        FServerHsTraffic := THkdfLabel.DeriveSecret(FHkdf, FHandshakeSecret,
          's hs traffic', ATranscriptHash);
        LogSecret(KeyLogLabelClientHandshakeTraffic, FClientHsTraffic);
        LogSecret(KeyLogLabelServerHandshakeTraffic, FServerHsTraffic);
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
        LogSecret(KeyLogLabelClientTraffic0, FClientApTraffic);
        LogSecret(KeyLogLabelServerTraffic0, FServerApTraffic);
        LogSecret(KeyLogLabelExporter, FExporterMaster);
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
  begin
    FClientApTraffic := ExpandKey(LOld, 'traffic upd', FHashLength);
    Inc(FClientTrafficGeneration);
    LogSecret(KeyLogLabelClientTrafficPrefix + IntToStr(FClientTrafficGeneration),
      FClientApTraffic);
  end
  else
  begin
    FServerApTraffic := ExpandKey(LOld, 'traffic upd', FHashLength);
    Inc(FServerTrafficGeneration);
    LogSecret(KeyLogLabelServerTrafficPrefix + IntToStr(FServerTrafficGeneration),
      FServerApTraffic);
  end;
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

function TTls13KeySchedule.ExportFrom(const AMaster: ISecretBuffer;
  const ALabel: string; const AContext: TBytes; ALength: Int32): TBytes;
var
  LDerived: ISecretBuffer;
  LContextHash: TBytes;
begin
  Result := nil;
  TExporterArgs.Guard(ALabel, ALength);
  if AMaster = nil then
    raise EInvalidOperationTlsLibException.CreateRes(@SEpochNotDerived);
  // TLS 1.3 always hashes a context value; no context is exactly an empty context (RFC 8446 7.5)
  LDerived := THkdfLabel.DeriveSecret(FHkdf, AMaster, ALabel, FHashEmpty);
  LContextHash := HashOf(AContext);
  Result := THkdfLabel.HkdfExpandLabel(FHkdf, LDerived, 'exporter', LContextHash,
    ALength).ToBytes;
end;

function TTls13KeySchedule.DoExportKeyingMaterial(const ALabel: string;
  const AContext: TBytes; AUseContext: Boolean; ALength: Int32): TBytes;
begin
  // AUseContext has no effect on 1.3 (no context is an empty context); it exists for the base
  // ExportKeyingMaterial overloads that also serve TLS 1.2
  Result := ExportFrom(FExporterMaster, ALabel, AContext, ALength);
end;

function TTls13KeySchedule.ExportEarlyKeyingMaterial(const ALabel: string;
  const AContext: TBytes; ALength: Int32): TBytes;
begin
  Result := ExportFrom(FEarlyExporterMaster, ALabel, AContext, ALength);
end;

function TTls13KeySchedule.CanExportEarly: Boolean;
begin
  // set when the early epoch secrets are derived (a 0-RTT handshake); never on TLS 1.2
  Result := FEarlyExporterMaster <> nil;
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

function TTls13KeySchedule.CanExport: Boolean;
begin
  // set when the Application epoch secrets are derived (a KeyUpdate never touches it)
  Result := FExporterMaster <> nil;
end;

procedure TTls13KeySchedule.ForgetResumptionMasterSecret;
begin
  FResumptionMaster := nil;
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
