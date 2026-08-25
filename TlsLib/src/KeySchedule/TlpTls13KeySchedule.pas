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
  TlpCryptoAlgorithms,
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
    FProvider: ICryptoProvider;
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
    function ZeroSecret: ISecretBuffer;
    function HashOf(const AData: TBytes): TBytes;
    procedure EnsureEarlySecret;
    procedure EnsureHandshakeSecret;
    procedure EnsureMasterSecret;
    function HandshakeTrafficSecret(ADirection: TTlsDirection): ISecretBuffer;
    function EpochSecret(AEpoch: TTlsEpoch; ADirection: TTlsDirection): ISecretBuffer;
    function ExpandKey(const ASecret: ISecretBuffer; const ALabel: string;
      ALength: Int32): ISecretBuffer;
  public
    /// <summary>AHash is the suite hash; AKeyLength the AEAD key size.</summary>
    constructor Create(const AProvider: ICryptoProvider; AHash: THashAlgorithm;
      AKeyLength: Int32);

    // IKeySchedule
    function TrafficKeys(AEpoch: TTlsEpoch; ADirection: TTlsDirection): ITrafficKeys;
    function ComputeVerifyData(ADirection: TTlsDirection;
      const ATranscriptHash: TBytes): TBytes;
    function VerifyFinished(ADirection: TTlsDirection;
      const ATranscriptHash, APeerVerifyData: TBytes): Boolean;
    function ExportKeyingMaterial(const ALabel: string; const AContext: TBytes;
      AUseContext: Boolean; ALength: Int32): TBytes;

    // ITls13KeySchedule
    procedure SetPsk(const APsk: ISecretBuffer);
    procedure SetSharedSecret(const ASharedSecret: ISecretBuffer);
    procedure DeriveEpochSecrets(AEpoch: TTlsEpoch; const ATranscriptHash: TBytes);
    function FinishedKey(ADirection: TTlsDirection): ISecretBuffer;
    procedure AdvanceKeyUpdate(ADirection: TTlsDirection);
    function ResumptionMasterSecret(const ATranscriptHash: TBytes): ISecretBuffer;
    function ResumptionPsk(const ATranscriptHash, ATicketNonce: TBytes): ISecretBuffer;
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

{ TTls13KeySchedule }

constructor TTls13KeySchedule.Create(const AProvider: ICryptoProvider;
  AHash: THashAlgorithm; AKeyLength: Int32);
var
  LHash: IHash;
begin
  inherited Create;
  FProvider := AProvider;
  FHash := AHash;
  FKeyLength := AKeyLength;
  FIvLength := Tls13IvLength;
  FHkdf := AProvider.Primitives.CreateHkdf(AHash);
  LHash := AProvider.Primitives.CreateHash(AHash);
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
  LHash := FProvider.Primitives.CreateHash(FHash);
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
  if FPsk <> nil then
    LIkm := FPsk
  else
    LIkm := ZeroSecret;
  // an empty salt is treated as HashLen zeros by the provider
  FEarlySecret := FHkdf.Extract(nil, LIkm);
end;

procedure TTls13KeySchedule.EnsureHandshakeSecret;
var
  LSalt: TBytes;
  LIkm: ISecretBuffer;
begin
  if FHandshakeSecret <> nil then
    Exit;
  EnsureEarlySecret;
  LSalt := THkdfLabel.DeriveSecret(FHkdf, FEarlySecret, 'derived', FHashEmpty).ToBytes;
  try
    if FSharedSecret <> nil then
      LIkm := FSharedSecret
    else
      LIkm := ZeroSecret;
    FHandshakeSecret := FHkdf.Extract(LSalt, LIkm);
  finally
    TSecureMemory.WipeBytes(LSalt);
  end;
end;

procedure TTls13KeySchedule.EnsureMasterSecret;
var
  LSalt: TBytes;
begin
  if FMasterSecret <> nil then
    Exit;
  EnsureHandshakeSecret;
  LSalt := THkdfLabel.DeriveSecret(FHkdf, FHandshakeSecret, 'derived', FHashEmpty).ToBytes;
  try
    FMasterSecret := FHkdf.Extract(LSalt, ZeroSecret);
  finally
    TSecureMemory.WipeBytes(LSalt);
  end;
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
  FPsk := APsk;
end;

procedure TTls13KeySchedule.SetSharedSecret(const ASharedSecret: ISecretBuffer);
begin
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
  LHmac := FProvider.Primitives.CreateHmac(FHash);
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
  const AContext: TBytes; AUseContext: Boolean; ALength: Int32): TBytes;
var
  LDerived: ISecretBuffer;
  LContextHash: TBytes;
begin
  Result := nil;
  if FExporterMaster = nil then
    raise EInvalidOperationTlsLibException.CreateRes(@SEpochNotDerived);
  // TLS 1.3 always hashes a context value; no context is exactly an empty context, so the
  // AUseContext distinction that matters in TLS 1.2 has no effect here (RFC 8446 7.5)
  LDerived := THkdfLabel.DeriveSecret(FHkdf, FExporterMaster, ALabel, FHashEmpty);
  LContextHash := HashOf(AContext);
  Result := THkdfLabel.HkdfExpandLabel(FHkdf, LDerived, 'exporter', LContextHash,
    ALength).ToBytes;
end;

function TTls13KeySchedule.ResumptionMasterSecret(
  const ATranscriptHash: TBytes): ISecretBuffer;
begin
  EnsureMasterSecret;
  Result := THkdfLabel.DeriveSecret(FHkdf, FMasterSecret, 'res master',
    ATranscriptHash);
end;

function TTls13KeySchedule.ResumptionPsk(
  const ATranscriptHash, ATicketNonce: TBytes): ISecretBuffer;
var
  LResMaster: ISecretBuffer;
begin
  LResMaster := ResumptionMasterSecret(ATranscriptHash);
  Result := THkdfLabel.HkdfExpandLabel(FHkdf, LResMaster, 'resumption',
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
  LHmac := FProvider.Primitives.CreateHmac(FHash);
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
