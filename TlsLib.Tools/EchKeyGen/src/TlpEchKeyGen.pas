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
{$IF DEFINED(FPC) AND DEFINED(UNIX)}
  BaseUnix,
{$ELSEIF DEFINED(POSIX)}
  Posix.SysStat,
  Posix.Fcntl,
  Posix.Unistd,
  Posix.Errno,
{$ELSEIF DEFINED(MSWINDOWS)}
  Windows,
{$ELSE}
  {$MESSAGE ERROR 'the ECH key generator needs a Windows or POSIX target'}
{$IFEND}
  TlpEchConfig,
  TlpCryptoDomainTypes,
  TlpSecureMemory,
  TlpPem,
  TlpICryptoProvider,
  TlpDefaultCryptoProvider,
  TlpInMemoryEchKeyStore,
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
    /// <summary>The DNS presentation line publishing the ECHConfigList in the origin's HTTPS
    /// record "ech" SvcParam (the name clients connect to, RFC 9460 2.3 / 9; the "ech" key,
    /// RFC 9848 sec. 3).</summary>
    DnsLine: string;
  end;

  /// <summary>
  /// Generates an Encrypted Client Hello key pair and the artifacts an operator needs:
  /// the RFC 9934 PEM for the server, the ECHConfigList for the client, and the DNS
  /// line to publish (RFC 9848). A standalone tool, so it reaches HPKE key generation
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
    /// <summary>Creates APath exclusively and owner-only. Returns 0 and the handle, or the OS
    /// error.</summary>
    class function CreateKeyFile(const APath: string; out AHandle: THandle): Integer; static;
    /// <summary>Closes a CreateKeyFile handle. Returns 0 or the OS error; a delayed write failure
    /// surfaces here.</summary>
    class function CloseKeyFile(AHandle: THandle): Integer; static;
    /// <summary>Whether a CreateKeyFile error means the path is already taken.</summary>
    class function IsExistsError(AError: Integer): Boolean; static;
  public
    /// <summary>
    /// Generates a single-config ECHConfigList for public_name APublicName under the
    /// HPKE suite (AKem, AKdf, AAead) with the operator-chosen config id AConfigId and
    /// the padding hint AMaximumNameLength. ACryptoProvider frames the PEM (RFC 7468) so the
    /// output matches what the server store reads. The DNS line is published at AOrigin
    /// (the name clients connect to). Raises for an HPKE suite the provider cannot instantiate,
    /// an invalid name, or a PEM that does not load back through the server key store.
    /// </summary>
    class function Generate(const ACryptoProvider: ICryptoProvider;
      const APublicName, AOrigin: string; AConfigId: Byte; AKem, AKdf, AAead: UInt16;
      AMaximumNameLength: Byte): TEchKeyGenResult; static;
    /// <summary>
    /// The command-line entry point: parses the arguments, generates the key material,
    /// writes the PEM to the -out file, and prints the DNS line. Returns a process exit
    /// code (0 on success). Both the Delphi and FPC program wrappers call this.
    /// </summary>
    class function RunConsole: Integer; static;
    /// <summary>Writes AData to APath. The file is created exclusively, so an existing file or
    /// symlink at APath is refused rather than overwritten or written through, and a failed write
    /// leaves no file behind. The file is owner-only from creation, so the private key is never
    /// readable by others: mode 0600 on POSIX, and on Windows a protected access list granting only
    /// the file's owner. Public so a test can assert it.</summary>
    class procedure WritePrivateFile(const APath: string; const AData: TBytes); static;
  end;

implementation

{$IFDEF MSWINDOWS}
// declared by neither compiler's Windows unit
function ConvertStringSecurityDescriptorToSecurityDescriptorW(AText: PWideChar; ARevision: DWORD;
  out ADescriptor: Pointer; ASize: PDWORD): LongBool; stdcall;
  external 'advapi32.dll' name 'ConvertStringSecurityDescriptorToSecurityDescriptorW';
{$ENDIF MSWINDOWS}

resourcestring
  SKeyFileExists = 'the private key file "%s" already exists; it is never overwritten or ' +
    'written through a symlink';
  SKeyFileCreateFailed = 'cannot create the private key file "%s": %s';
  SKeyFileWriteFailed = 'cannot write the private key file "%s": %s';

{ TEchKeyGenerator }

class function TEchKeyGenerator.Generate(const ACryptoProvider: ICryptoProvider;
  const APublicName, AOrigin: string; AConfigId: Byte; AKem, AKdf, AAead: UInt16;
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
  LOrigin: string;
begin
  LPublicNameBytes := TEncoding.ASCII.GetBytes(APublicName);
  if not TEchConfig.IsValidPublicName(LPublicNameBytes) then
    raise EArgumentException.Create('the public_name is not a valid LDH host name');
  // the DNS record is queried at the origin (the name a client connects to and puts in the
  // inner SNI), not the public_name; validate it as an LDH host, tolerating one trailing dot
  LOrigin := AOrigin;
  if (LOrigin <> '') and (LOrigin[System.Length(LOrigin)] = '.') then
    LOrigin := System.Copy(LOrigin, 1, System.Length(LOrigin) - 1);
  if not TEchConfig.IsValidPublicName(TEncoding.ASCII.GetBytes(LOrigin)) then
    raise EArgumentException.Create('the origin is not a valid LDH host name');
  // the tool's suite vocabulary is the provider's: a config the library could neither serve nor
  // offer (an unknown KEM, an export-only AEAD) must fail here, not at server start-up after the
  // DNS record is already published
  if ACryptoProvider.Hpke.Suite(AKem, AKdf, AAead) = nil then
    raise EArgumentException.Create('the HPKE suite is not one this provider can serve');
  LKem := TDhKem.Create(THpkeKemId(AKem)) as IHpkeKem;
  LPair := LKem.GeneratePrivateKey();
  LPublicKey := LKem.SerializePublicKey(LPair.&Public);
  LPrivateInfo := TPrivateKeyInfoFactory.CreatePrivateKeyInfo(LPair.&Private);
  LPkcs8 := LPrivateInfo.GetDerEncoded();
  // the PKCS#8 DER is the raw private key; wipe this and the PEM block that aliases it once the
  // output PEM is built (Result.Pem is the caller's copy). Result itself is never wiped here.
  try
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
    Result.Pem := TPem.WriteBlocks(LBlocks);

    // load the PEM back through the server key store before it is handed out: the PKCS#8 encoding,
    // the config and the key pair must round-trip exactly as a server will read them
    TInMemoryEchKeyStore.FromPem(Result.Pem, ACryptoProvider);

    // an HTTPS record in ServiceMode (priority 1) with the ECHConfigList in the "ech"
    // SvcParam, base64 as the presentation format expects. It is published at the origin the
    // client connects to; the public_name lives only inside the ECHConfig, as the outer SNI.
    Result.DnsLine := LOrigin + '. HTTPS 1 . ech="' +
      TDataEncoding.Base64Encode(Result.EchConfigList) + '"';
  finally
    TSecureMemory.WipeBytes(LPkcs8);
    if System.Length(LBlocks) > 0 then
      TSecureMemory.WipeBytes(LBlocks[0].Content);
  end;
end;

class function TEchKeyGenerator.MapKem(const AName: string;
  out AKem: UInt16): Boolean;
begin
  Result := True;
  if AName = 'x25519' then
    AKem := THpkeKem.DHKEM_X25519_HKDF_SHA256
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

class function TEchKeyGenerator.CreateKeyFile(const APath: string;
  out AHandle: THandle): Integer;
var
{$IF DEFINED(FPC) AND DEFINED(UNIX)}
  LFd: LongInt;
{$ELSEIF DEFINED(POSIX)}
  LFd: Integer;
  LPath: UTF8String;
{$ELSE}
  LPath: UnicodeString;
  LHandle: THandle;
  LAttributes: TSecurityAttributes;
{$IFEND}
begin
  AHandle := 0;
{$IF DEFINED(FPC) AND DEFINED(UNIX)}
  // O_CREAT|O_EXCL refuses an existing file and, per POSIX, a symlink at the path (even a dangling
  // one), and the 0600 mode is set by the create itself, so the key is never briefly readable
  // by others
  LFd := FpOpen(APath, O_WRONLY or O_CREAT or O_EXCL, S_IRUSR or S_IWUSR);
  if LFd < 0 then
    Exit(fpgeterrno);
  AHandle := THandle(LFd);
{$ELSEIF DEFINED(POSIX)}
  LPath := UTF8String(APath);
  LFd := open(PAnsiChar(LPath), O_WRONLY or O_CREAT or O_EXCL, S_IRUSR or S_IWUSR);
  if LFd < 0 then
    Exit(GetLastError);
  AHandle := THandle(LFd);
{$ELSE}
  // CREATE_NEW refuses an existing file. The create applies a protected access list (nothing
  // inherited from the directory) whose one entry gives the file's owner full access, so the key
  // is never briefly readable by others; if the list cannot be built no file is made
  LAttributes := Default(TSecurityAttributes);
  LAttributes.nLength := SizeOf(LAttributes);
  if not ConvertStringSecurityDescriptorToSecurityDescriptorW('D:P(A;;FA;;;OW)', 1,
    LAttributes.lpSecurityDescriptor, nil) then
    Exit(Integer(GetLastError));
  try
    LPath := UnicodeString(APath);
    LHandle := CreateFileW(PWideChar(LPath), GENERIC_WRITE, 0, @LAttributes, CREATE_NEW,
      FILE_ATTRIBUTE_NORMAL, 0);
    if LHandle = INVALID_HANDLE_VALUE then
      Exit(Integer(GetLastError));
  finally
    LocalFree(HLOCAL(LAttributes.lpSecurityDescriptor));
  end;
  AHandle := LHandle;
{$IFEND}
  Result := 0;
end;

class function TEchKeyGenerator.CloseKeyFile(AHandle: THandle): Integer;
begin
{$IF DEFINED(FPC) AND DEFINED(UNIX)}
  if FpClose(AHandle) < 0 then
    Exit(fpgeterrno);
{$ELSEIF DEFINED(POSIX)}
  if __close(Integer(AHandle)) < 0 then
    Exit(GetLastError);
{$ELSE}
  if not CloseHandle(AHandle) then
    Exit(Integer(GetLastError));
{$IFEND}
  Result := 0;
end;

class function TEchKeyGenerator.IsExistsError(AError: Integer): Boolean;
begin
{$IF DEFINED(FPC) AND DEFINED(UNIX)}
  Result := AError = ESysEEXIST;
{$ELSEIF DEFINED(POSIX)}
  Result := AError = EEXIST;
{$ELSE}
  Result := AError = ERROR_FILE_EXISTS;
{$IFEND}
end;

class procedure TEchKeyGenerator.WritePrivateFile(const APath: string;
  const AData: TBytes);
var
  LHandle: THandle;
  LError: Integer;
  LStream: THandleStream;
begin
  LError := CreateKeyFile(APath, LHandle);
  if LError <> 0 then
  begin
    if IsExistsError(LError) then
      raise EInOutError.CreateResFmt(@SKeyFileExists, [APath]);
    raise EInOutError.CreateResFmt(@SKeyFileCreateFailed, [APath, SysErrorMessage(LError)]);
  end;
  // a failed write leaves nothing behind: a partial key file would block every rerun
  try
    LStream := THandleStream.Create(LHandle);
    try
      if System.Length(AData) > 0 then
        LStream.WriteBuffer(AData[0], System.Length(AData));
    finally
      LStream.Free;
    end;
  except
    CloseKeyFile(LHandle);
    SysUtils.DeleteFile(APath);
    raise;
  end;
  // close can report a delayed write error
  LError := CloseKeyFile(LHandle);
  if LError <> 0 then
  begin
    SysUtils.DeleteFile(APath);
    raise EInOutError.CreateResFmt(@SKeyFileWriteFailed, [APath, SysErrorMessage(LError)]);
  end;
end;

class function TEchKeyGenerator.RunConsole: Integer;
var
  LCrypto: ICryptoProvider;
  LPublicName, LOrigin, LOutPath, LSuite, LArg, LValue: string;
  LKem, LKdf, LAead: UInt16;
  LConfigId, LMaxNameLen: Int32;
  LHasConfigId: Boolean;
  LI: Int32;
  LResult: TEchKeyGenResult;
begin
  LPublicName := '';
  LOrigin := '';
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
    else if LArg = '-origin' then
      LOrigin := LValue
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

  if (LPublicName = '') or (LOrigin = '') or (LOutPath = '') then
  begin
    WriteLn('usage: EchKeyGen -public_name <name> -origin <name> -out <file.pem> ' +
      '[-suite kem,kdf,aead] [-max_name_len N] [-config_id N]');
    WriteLn('  kem:  x25519 | p256 | p384 | p521');
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
    LCrypto := TDefaultCryptoProvider.Create as ICryptoProvider;
    // the config id is an operator-chosen hint; default to a random byte (the server
    // matches an incoming ECH by it, so it need only be stable, not secret)
    if not LHasConfigId then
      LConfigId := LCrypto.Primitives.GetRandom.GenerateBytes(1)[0];
    LResult := Generate(LCrypto, LPublicName, LOrigin, Byte(LConfigId), LKem, LKdf, LAead,
      Byte(LMaxNameLen));
    try
      WritePrivateFile(LOutPath, LResult.Pem);
      WriteLn(LResult.DnsLine);
      Result := 0;
    finally
      // the PEM carries the private key; drop the in-memory copy once written to disk
      TSecureMemory.WipeBytes(LResult.Pem);
    end;
  except
    on E: Exception do
    begin
      WriteLn('error: ', E.Message);
      Result := 4;
    end;
  end;
end;

end.
