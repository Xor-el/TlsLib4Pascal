{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpInMemoryEchKeyStore;

{$I ..\Include\TlsLib.inc}

interface

uses
  SysUtils,
  TlpISecretBuffer,
  TlpArrayUtilities,
  TlpCryptoDomainTypes,
  TlpICryptoProvider,
  TlpEchConfig,
  TlpIEch,
  TlpSecureMemory,
  TlpTlsLibExceptions;

type
  /// <summary>
  /// The app-driven, immutable server ECH key store (RFC 9849 sec. 4.5): a fixed set of
  /// config/private-key entries and the retry_configs to advertise on reject. The operator
  /// owns the key set and rotates by building and swapping in a new store (never auto-rotated).
  /// Build one from an RFC 9934 PEM or from an explicit config plus private key.
  /// </summary>
  TInMemoryEchKeyStore = class sealed(TInterfacedObject, IEchServerKeyStore)
  strict private
  var
    FEntries: TArray<TEchKeyEntry>;
    FRetryConfigs: TBytes;
    class function SelectBlock(const ABlocks: TArray<TPemBlock>;
      const ALabel: string): TBytes; static;
    class function ComputeRetryConfigs(
      const AEntries: TArray<TEchKeyEntry>): TBytes; static;
    /// <summary>Whether ARecipientKey is the HPKE key for AConfig, by comparing its derived
    /// public key with the config's advertised public_key.</summary>
    class function KeyMatchesConfig(const ARecipientKey: IHpkeRecipientKey;
      const AConfig: TEchConfig): Boolean; static;
    /// <summary>Parses an RFC 9934 ECH PEM (a PKCS#8 PRIVATE KEY block and an ECHCONFIG
    /// block holding an ECHConfigList) into one entry per config, importing the private
    /// key for each config's KEM through AProvider. Malformed input raises.</summary>
    class function EntriesFromPem(const APem: TBytes;
      const AProvider: ICryptoProvider; AIsRetry: Boolean): TArray<TEchKeyEntry>; static;
    /// <summary>Builds one entry from a config and its prepared HPKE recipient key.</summary>
    class function Entry(const AConfig: TEchConfig;
      const ARecipientKey: IHpkeRecipientKey; AIsRetry: Boolean): TEchKeyEntry; static;
  public
    /// <summary>An immutable store over a fixed set of entries. Rotate keys by building and
    /// swapping in a new store (RFC 9849 sec. 4.5); the operator owns the key set.</summary>
    constructor Create(const AEntries: TArray<TEchKeyEntry>);
    function Entries: TArray<TEchKeyEntry>;
    function RetryConfigs: TBytes;

    /// <summary>
    /// A store built from an RFC 9934 ECH PEM: every config becomes a key the server
    /// decrypts with and advertises as retry_configs. No per-entry expiry (rotate by
    /// swapping the store); for expiry, build TEchKeyEntry values and use the constructor.
    /// </summary>
    class function FromPem(const APem: TBytes;
      const AProvider: ICryptoProvider): IEchServerKeyStore; static;
    /// <summary>
    /// A store built from an explicit ECHConfigList and its HPKE private key (the non-PEM
    /// path): every config becomes a key and a retry_config. No per-entry expiry. Raises if the
    /// private key does not match a config's public key (the mismatch the PEM path also rejects).
    /// </summary>
    class function FromConfig(const AEchConfigList: TBytes;
      const APrivateKey: ISecretBuffer;
      const AProvider: ICryptoProvider): IEchServerKeyStore; static;
  end;

implementation

resourcestring
  SMissingPemBlock = 'the ECH PEM is missing a %s block';
  SDuplicatePemBlock = 'the ECH PEM has more than one %s block';
  SEchKeyMismatch = 'the ECH private key does not match a config public key';
  SNoRetryConfigs = 'the ECH key store has entries but none is flagged is_retry, so it ' +
    'could never advertise retry_configs on a reject (RFC 9849 sec. 7.1)';
  SEchEntryInvalid = 'an ECH key store entry has a nil private key, an unsupported config ' +
    'version, or no raw config bytes';
  SEchNoUsableSuite = 'an ECH config offers no HPKE suite this provider can instantiate';
  SEchNoServableConfig = 'the ECHConfigList holds no config of a version this library serves';

{ TInMemoryEchKeyStore }

constructor TInMemoryEchKeyStore.Create(const AEntries: TArray<TEchKeyEntry>);
var
  LI: Int32;
begin
  inherited Create;
  // validate every entry here so all three construction paths (this ctor, FromPem, FromConfig)
  // share one gate: a nil key would fault mid-handshake, a foreign version or empty raw config
  // would silently reject every ECH offer
  for LI := 0 to System.High(AEntries) do
    if (AEntries[LI].RecipientKey = nil) or
      (AEntries[LI].Config.Version <> TEchConfig.SupportedVersion) or
      (System.Length(AEntries[LI].Config.Raw) = 0) then
      raise EArgumentTlsLibException.CreateRes(@SEchEntryInvalid);
  FEntries := System.Copy(AEntries);
  // the store is immutable, so the retry_configs list is fixed for its lifetime: encode once
  FRetryConfigs := ComputeRetryConfigs(FEntries);
  // a server configured with ECHConfigs MUST be able to advertise retry_configs on a reject
  // (RFC 9849 sec. 7.1); a non-empty store that flags none is_retry never could
  if (System.Length(FEntries) > 0) and (System.Length(FRetryConfigs) = 0) then
    raise EArgumentTlsLibException.CreateRes(@SNoRetryConfigs);
end;

function TInMemoryEchKeyStore.Entries: TArray<TEchKeyEntry>;
begin
  Result := System.Copy(FEntries);
end;

function TInMemoryEchKeyStore.RetryConfigs: TBytes;
begin
  Result := System.Copy(FRetryConfigs);
end;

class function TInMemoryEchKeyStore.ComputeRetryConfigs(
  const AEntries: TArray<TEchKeyEntry>): TBytes;
var
  LConfigs: TArray<TEchConfig>;
  LI, LCount: Int32;
begin
  LConfigs := nil;
  LCount := 0;
  for LI := 0 to System.High(AEntries) do
    if AEntries[LI].IsRetry then
    begin
      SetLength(LConfigs, LCount + 1);
      LConfigs[LCount] := AEntries[LI].Config;
      Inc(LCount);
    end;
  if LCount = 0 then
    Exit(nil);
  Result := TEchConfigList.Encode(LConfigs);
end;

class function TInMemoryEchKeyStore.KeyMatchesConfig(
  const ARecipientKey: IHpkeRecipientKey; const AConfig: TEchConfig): Boolean;
begin
  // the prepared key derived its own public key at import; it belongs to the config exactly when
  // that equals the config's advertised public_key
  Result := TArrayUtilities.AreEqual(ARecipientKey.PublicKey, AConfig.PublicKey);
end;

class function TInMemoryEchKeyStore.SelectBlock(const ABlocks: TArray<TPemBlock>;
  const ALabel: string): TBytes;
var
  LI, LFound: Int32;
begin
  LFound := -1;
  for LI := 0 to System.High(ABlocks) do
    if ABlocks[LI].PemType = ALabel then
    begin
      if LFound >= 0 then
        raise EArgumentTlsLibException.CreateResFmt(@SDuplicatePemBlock, [ALabel]);
      LFound := LI;
    end;
  if LFound < 0 then
    raise EArgumentTlsLibException.CreateResFmt(@SMissingPemBlock, [ALabel]);
  Result := ABlocks[LFound].Content;
end;

class function TInMemoryEchKeyStore.EntriesFromPem(const APem: TBytes;
  const AProvider: ICryptoProvider; AIsRetry: Boolean): TArray<TEchKeyEntry>;
var
  LBlocks: TArray<TPemBlock>;
  LPkcs8, LConfigListBytes: TBytes;
  LConfigs: TArray<TEchConfig>;
  LRecipient: IHpkeRecipientKey;
  LSuite: THpkeSuite;
  LI, LCount: Int32;
begin
  Result := nil;
  LBlocks := AProvider.Pem.ReadBlocks(APem);
  LPkcs8 := SelectBlock(LBlocks, 'PRIVATE KEY');
  LConfigListBytes := SelectBlock(LBlocks, 'ECHCONFIG');
  try
    LConfigs := TEchConfigList.Parse(LConfigListBytes);
    SetLength(Result, System.Length(LConfigs));
    LCount := 0;
    for LI := 0 to System.High(LConfigs) do
    begin
      // an ECHConfigList may carry configs of other versions (RFC 9849 sec. 4); this library
      // only instantiates the current one, so skip the rest rather than fail the whole load
      if LConfigs[LI].Version <> TEchConfig.SupportedVersion then
        Continue;
      // a current-version config the server cannot serve (export-only or unknown suite/KEM) is a
      // misconfiguration: it would be advertised as retry_configs yet reject every offer
      if not LConfigs[LI].TrySelectSuite(AProvider, LSuite) then
        raise EArgumentTlsLibException.CreateRes(@SEchNoUsableSuite);
      LRecipient := AProvider.Hpke.ImportRecipientKey(LConfigs[LI].KemId,
        AProvider.Hpke.ImportPrivateKey(LConfigs[LI].KemId, LPkcs8));
      // fail at load if the PEM pairs a private key with a config whose public key it does not
      // match - otherwise every ECH handshake would silently reject with no diagnosable cause
      if not KeyMatchesConfig(LRecipient, LConfigs[LI]) then
        raise EArgumentTlsLibException.CreateRes(@SEchKeyMismatch);
      Result[LCount] := Entry(LConfigs[LI], LRecipient, AIsRetry);
      Inc(LCount);
    end;
    SetLength(Result, LCount);
    // configs were supplied but none is a version this library serves - not a silent empty store
    if (System.Length(LConfigs) > 0) and (LCount = 0) then
      raise EArgumentTlsLibException.CreateRes(@SEchNoServableConfig);
  finally
    TSecureMemory.WipeBytes(LPkcs8);
  end;
end;

class function TInMemoryEchKeyStore.FromPem(const APem: TBytes;
  const AProvider: ICryptoProvider): IEchServerKeyStore;
begin
  Result := TInMemoryEchKeyStore.Create(EntriesFromPem(APem, AProvider, True))
    as IEchServerKeyStore;
end;

class function TInMemoryEchKeyStore.FromConfig(const AEchConfigList: TBytes;
  const APrivateKey: ISecretBuffer;
  const AProvider: ICryptoProvider): IEchServerKeyStore;
var
  LConfigs: TArray<TEchConfig>;
  LEntries: TArray<TEchKeyEntry>;
  LRecipient: IHpkeRecipientKey;
  LSuite: THpkeSuite;
  LI, LCount: Int32;
begin
  LConfigs := TEchConfigList.Parse(AEchConfigList);
  SetLength(LEntries, System.Length(LConfigs));
  LCount := 0;
  for LI := 0 to System.High(LConfigs) do
  begin
    // skip a config of a version this library does not model (RFC 9849 sec. 4)
    if LConfigs[LI].Version <> TEchConfig.SupportedVersion then
      Continue;
    // a current-version config with no provider-usable suite could never serve an offer
    if not LConfigs[LI].TrySelectSuite(AProvider, LSuite) then
      raise EArgumentTlsLibException.CreateRes(@SEchNoUsableSuite);
    LRecipient := AProvider.Hpke.ImportRecipientKey(LConfigs[LI].KemId, APrivateKey);
    // reject a private key that does not match the config's public key - the same undiagnosable
    // silent-reject the PEM path guards against
    if not KeyMatchesConfig(LRecipient, LConfigs[LI]) then
      raise EArgumentTlsLibException.CreateRes(@SEchKeyMismatch);
    LEntries[LCount] := Entry(LConfigs[LI], LRecipient, True);
    Inc(LCount);
  end;
  SetLength(LEntries, LCount);
  // configs were supplied but none is a version this library serves
  if (System.Length(LConfigs) > 0) and (LCount = 0) then
    raise EArgumentTlsLibException.CreateRes(@SEchNoServableConfig);
  Result := TInMemoryEchKeyStore.Create(LEntries) as IEchServerKeyStore;
end;

class function TInMemoryEchKeyStore.Entry(const AConfig: TEchConfig;
  const ARecipientKey: IHpkeRecipientKey; AIsRetry: Boolean): TEchKeyEntry;
begin
  Result.Config := AConfig;
  Result.RecipientKey := ARecipientKey;
  Result.IsRetry := AIsRetry;
end;

end.
