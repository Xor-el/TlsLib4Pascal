{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpEchKeyGen;

{$IFDEF FPC}
{$MODE DELPHI}
{$H+}
{$ENDIF}

interface

uses
  SysUtils,
  Classes,
  TlpEchConfig,
  TlpCryptoDomainTypes,
  TlpICryptoProvider,
  TlpDefaultCryptoProvider,
  TlpDataEncoding,
  // this is a standalone tool, not part of the library, so it may reach CryptoLib
  // directly (like RootGen): the KEM produces the key pair and PKCS#8 encoding the
  // neutral provider facet does not expose (it hands back only the raw scalar)
  ClpIHpkeKem,
  ClpDhKem,
  ClpHpkeTypes,
  ClpIAsymmetricCipherKeyPair,
  ClpIPkcsAsn1Objects,
  ClpPrivateKeyInfoFactory;

type
  /// <summary>The generated ECH key material in the forms an operator publishes.</summary>
  TEchKeyGenResult = record
    /// <summary>The RFC 9934 PEM: a PKCS#8 "PRIVATE KEY" block and an "ECHCONFIG" block.
    /// This is what a server loads through the ECH key store.</summary>
    Pem: TBytes;
    /// <summary>The raw ECHConfigList a client uses as its ECH configuration.</summary>
    EchConfigList: TBytes;
    /// <summary>The DNS presentation line publishing the ECHConfigList in an HTTPS
    /// record's "ech" SvcParam.</summary>
    DnsLine: string;
  end;

  /// <summary>
  /// Generates an Encrypted Client Hello key pair and the artifacts an operator needs:
  /// the RFC 9934 PEM for the server, the ECHConfigList for the client, and the DNS
  /// line to publish (RFC 9849). A standalone tool, so it reaches HPKE key generation
  /// and PKCS#8 encoding through CryptoLib directly; the byte formats it emits are the
  /// ones the library's ECH server store and client policy consume.
  /// </summary>
  TEchKeyGenerator = class sealed(TObject)
  strict private
    class function MapKem(const AName: string; out AKem: UInt16): Boolean; static;
    class function MapKdf(const AName: string; out AKdf: UInt16): Boolean; static;
    class function MapAead(const AName: string; out AAead: UInt16): Boolean; static;
    class function ParseSuite(const AText: string;
      out AKem, AKdf, AAead: UInt16): Boolean; static;
    class procedure WriteFile(const APath: string; const AData: TBytes); static;
  public
    /// <summary>
    /// Generates a single-config ECHConfigList for public_name APublicName under the
    /// HPKE suite (AKem, AKdf, AAead) with the operator-chosen config id AConfigId and
    /// the padding hint AMaximumNameLength. AProvider frames the PEM (RFC 7468) so the
    /// output matches what the server store reads. Raises for an unsupported KEM.
    /// </summary>
    class function Generate(const AProvider: ICryptoProvider;
      const APublicName: string; AConfigId: Byte; AKem, AKdf, AAead: UInt16;
      AMaximumNameLength: Byte): TEchKeyGenResult; static;
    /// <summary>
    /// The command-line entry point: parses the arguments, generates the key material,
    /// writes the PEM to the -out file, and prints the DNS line. Returns a process exit
    /// code (0 on success). Both the Delphi and FPC program wrappers call this.
    /// </summary>
    class function RunConsole: Integer; static;
  end;

implementation

{ TEchKeyGenerator }

class function TEchKeyGenerator.Generate(const AProvider: ICryptoProvider;
  const APublicName: string; AConfigId: Byte; AKem, AKdf, AAead: UInt16;
  AMaximumNameLength: Byte): TEchKeyGenResult;
var
  LKem: IHpkeKem;
  LPair: IAsymmetricCipherKeyPair;
  LPrivateInfo: IPrivateKeyInfo;
  LPublicKey, LPkcs8: TBytes;
  LSuite: TEchCipherSuite;
  LConfig: TEchConfig;
  LBlocks: TArray<TPemBlock>;
  LPublicNameBytes: TBytes;
begin
  LPublicNameBytes := TEncoding.ASCII.GetBytes(APublicName);
  if not TEchConfig.IsValidPublicName(LPublicNameBytes) then
    raise EArgumentException.Create('the public_name is not a valid LDH host name');
  LKem := TDhKem.Create(THpkeKemId(AKem)) as IHpkeKem;
  LPair := LKem.GeneratePrivateKey();
  LPublicKey := LKem.SerializePublicKey(LPair.&Public);
  LPrivateInfo := TPrivateKeyInfoFactory.CreatePrivateKeyInfo(LPair.&Private);
  LPkcs8 := LPrivateInfo.GetDerEncoded();

  LSuite.KdfId := AKdf;
  LSuite.AeadId := AAead;
  LConfig := TEchConfig.Build(TEchConfig.SupportedVersion, AConfigId, AKem,
    LPublicKey, TArray<TEchCipherSuite>.Create(LSuite), AMaximumNameLength,
    LPublicNameBytes, nil);
  Result.EchConfigList := TEchConfigList.Encode(TArray<TEchConfig>.Create(LConfig));

  LBlocks := nil;
  SetLength(LBlocks, 2);
  LBlocks[0].PemType := 'PRIVATE KEY';
  LBlocks[0].Content := LPkcs8;
  LBlocks[1].PemType := 'ECHCONFIG';
  LBlocks[1].Content := Result.EchConfigList;
  Result.Pem := AProvider.Pem.WriteBlocks(LBlocks);

  // an HTTPS record in ServiceMode (priority 1) with the ECHConfigList in the "ech"
  // SvcParam, base64 as the presentation format expects
  Result.DnsLine := APublicName + '. HTTPS 1 . ech="' +
    TDataEncoding.Base64Encode(Result.EchConfigList) + '"';
end;

class function TEchKeyGenerator.MapKem(const AName: string;
  out AKem: UInt16): Boolean;
begin
  Result := True;
  if AName = 'x25519' then
    AKem := THpkeKem.DHKEM_X25519_HKDF_SHA256
  else if AName = 'x448' then
    AKem := THpkeKem.DHKEM_X448_HKDF_SHA512
  else if AName = 'p256' then
    AKem := THpkeKem.DHKEM_P256_HKDF_SHA256
  else if AName = 'p384' then
    AKem := THpkeKem.DHKEM_P384_HKDF_SHA384
  else if AName = 'p521' then
    AKem := THpkeKem.DHKEM_P521_HKDF_SHA512
  else
    Result := False;
end;

class function TEchKeyGenerator.MapKdf(const AName: string;
  out AKdf: UInt16): Boolean;
begin
  Result := True;
  if AName = 'hkdf-sha256' then
    AKdf := THpkeKdf.HKDF_SHA256
  else if AName = 'hkdf-sha384' then
    AKdf := THpkeKdf.HKDF_SHA384
  else if AName = 'hkdf-sha512' then
    AKdf := THpkeKdf.HKDF_SHA512
  else
    Result := False;
end;

class function TEchKeyGenerator.MapAead(const AName: string;
  out AAead: UInt16): Boolean;
begin
  Result := True;
  if AName = 'aes-128-gcm' then
    AAead := THpkeAead.AES_128_GCM
  else if AName = 'aes-256-gcm' then
    AAead := THpkeAead.AES_256_GCM
  else if AName = 'chacha20-poly1305' then
    AAead := THpkeAead.CHACHA20_POLY1305
  else
    Result := False;
end;

class function TEchKeyGenerator.ParseSuite(const AText: string;
  out AKem, AKdf, AAead: UInt16): Boolean;
var
  LParts: TArray<string>;
begin
  LParts := LowerCase(AText).Split([',']);
  Result := (System.Length(LParts) = 3) and MapKem(LParts[0], AKem) and
    MapKdf(LParts[1], AKdf) and MapAead(LParts[2], AAead);
end;

class procedure TEchKeyGenerator.WriteFile(const APath: string;
  const AData: TBytes);
var
  LStream: TFileStream;
begin
  LStream := TFileStream.Create(APath, fmCreate);
  try
    if System.Length(AData) > 0 then
      LStream.WriteBuffer(AData[0], System.Length(AData));
  finally
    LStream.Free;
  end;
end;

class function TEchKeyGenerator.RunConsole: Integer;
var
  LProvider: ICryptoProvider;
  LPublicName, LOutPath, LSuite, LArg, LValue: string;
  LKem, LKdf, LAead: UInt16;
  LConfigId, LMaxNameLen: Int32;
  LHasConfigId: Boolean;
  LI: Int32;
  LResult: TEchKeyGenResult;
begin
  LPublicName := '';
  LOutPath := '';
  LSuite := 'x25519,hkdf-sha256,aes-128-gcm';
  LMaxNameLen := 0;
  LConfigId := 0;
  LHasConfigId := False;
  LI := 1;
  while LI <= ParamCount do
  begin
    LArg := ParamStr(LI);
    if LI < ParamCount then
      LValue := ParamStr(LI + 1)
    else
      LValue := '';
    if LArg = '-public_name' then
      LPublicName := LValue
    else if LArg = '-out' then
      LOutPath := LValue
    else if LArg = '-suite' then
      LSuite := LValue
    else if LArg = '-max_name_len' then
      LMaxNameLen := StrToIntDef(LValue, -1)
    else if LArg = '-config_id' then
    begin
      LConfigId := StrToIntDef(LValue, -1);
      LHasConfigId := True;
    end
    else
    begin
      WriteLn('error: unknown argument ', LArg);
      Exit(1);
    end;
    Inc(LI, 2);
  end;

  if (LPublicName = '') or (LOutPath = '') then
  begin
    WriteLn('usage: EchKeyGen -public_name <name> -out <file.pem> ' +
      '[-suite kem,kdf,aead] [-max_name_len N] [-config_id N]');
    WriteLn('  kem:  x25519 | x448 | p256 | p384 | p521');
    WriteLn('  kdf:  hkdf-sha256 | hkdf-sha384 | hkdf-sha512');
    WriteLn('  aead: aes-128-gcm | aes-256-gcm | chacha20-poly1305');
    Exit(1);
  end;
  if not ParseSuite(LSuite, LKem, LKdf, LAead) then
  begin
    WriteLn('error: invalid -suite ', LSuite);
    Exit(2);
  end;
  if (LMaxNameLen < 0) or (LMaxNameLen > 255) then
  begin
    WriteLn('error: -max_name_len must be between 0 and 255');
    Exit(2);
  end;
  if LHasConfigId and ((LConfigId < 0) or (LConfigId > 255)) then
  begin
    WriteLn('error: -config_id must be between 0 and 255');
    Exit(2);
  end;

  try
    LProvider := TDefaultCryptoProvider.Create as ICryptoProvider;
    // the config id is an operator-chosen hint; default to a random byte (the server
    // matches an incoming ECH by it, so it need only be stable, not secret)
    if not LHasConfigId then
      LConfigId := LProvider.Primitives.GetRandom.GenerateBytes(1)[0];
    LResult := Generate(LProvider, LPublicName, Byte(LConfigId), LKem, LKdf, LAead,
      Byte(LMaxNameLen));
    WriteFile(LOutPath, LResult.Pem);
    WriteLn(LResult.DnsLine);
    Result := 0;
  except
    on E: Exception do
    begin
      WriteLn('error: ', E.Message);
      Result := 4;
    end;
  end;
end;

end.
