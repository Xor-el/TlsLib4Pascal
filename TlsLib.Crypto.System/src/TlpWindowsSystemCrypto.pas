{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpWindowsSystemCrypto;

{$I ..\..\TlsLib\src\Include\TlsLib.inc}

interface

{$IFDEF TLSLIB_MSWINDOWS}

uses
  Windows,
  SysUtils,
  TlpEnumUtilities,
  TlpArrayUtilities,
  TlpCryptoDomainTypes,
  TlpPem,
  TlpDer,
  TlpSystemCryptoTypes,
  TlpICryptoProvider,
  TlpICryptoBackendReport,
  TlpISigningKey,
  TlpTlsCredential,
  TlpISecretBuffer,
  TlpSecretBuffer,
  TlpSecureMemory,
  TlpTls12PrfComposition,
  TlpSystemCryptoBase,
  TlpSystemCryptoExceptions,
  TlpTlsAlert,
  TlpTlsLibExceptions;

type
  /// <summary>
  /// The Windows-native crypto composer - the OS factory's single entry point for this
  /// platform. <see cref="Compose" /> overlays CNG-backed NIST-curve key agreement on a
  /// base provider, or returns the base unchanged when CNG ECDH is unavailable on this
  /// host (bcrypt.dll or an entry point missing, or the provider cannot be opened). All
  /// Windows composition and the CNG bindings live in this unit's implementation, so the
  /// factory only dispatches and nothing outside sees a CNG type.
  /// </summary>
  TWindowsSystemCrypto = class sealed(TObject)
  public
    class function Compose(const ABase: ICryptoProvider): ICryptoProvider; static;
  end;

{$ENDIF}

implementation

{$IFDEF TLSLIB_MSWINDOWS}

const
  BCRYPT_DLL = 'bcrypt.dll';
  STATUS_SUCCESS = Integer(0);
  UncompressedPointPrefix = Byte($04); // SEC1 uncompressed EC point form

  // per-curve public/private ECC key-blob magics (bcrypt.h)
  BCRYPT_ECDH_PUBLIC_P256_MAGIC = ULONG($314B4345);
  BCRYPT_ECDH_PRIVATE_P256_MAGIC = ULONG($324B4345);
  BCRYPT_ECDH_PUBLIC_P384_MAGIC = ULONG($334B4345);
  BCRYPT_ECDH_PRIVATE_P384_MAGIC = ULONG($344B4345);
  BCRYPT_ECDH_PUBLIC_P521_MAGIC = ULONG($354B4345);
  BCRYPT_ECDH_PRIVATE_P521_MAGIC = ULONG($364B4345);
  // generic-curve ECDH magics (used by curve25519 / X25519)
  BCRYPT_ECDH_PUBLIC_GENERIC_MAGIC = ULONG($504B4345);
  BCRYPT_ECDH_PRIVATE_GENERIC_MAGIC = ULONG($564B4345);

  ECC_BLOB_HEADER_SIZE = Int32(8); // ULONG dwMagic + ULONG cbKey
  X25519_KEY_SIZE = Int32(32); // RFC 7748 raw key / secret length

  // BCRYPT_MLKEM_KEY_BLOB (bcrypt.h, Win11 24H2+): { dwMagic; cbParameterSet; cbKey }
  // then the null-terminated parameter-set name then the FIPS 203 byte-encoded key
  BCRYPT_MLKEM_PUBLIC_MAGIC = ULONG($504B4C4D);
  BCRYPT_MLKEM_PRIVATE_MAGIC = ULONG($524B4C4D);
  MLKEM_BLOB_HEADER_SIZE = Int32(12); // ULONG dwMagic + ULONG cbParameterSet + ULONG cbKey
  // ML-KEM-768 byte-encoded sizes (FIPS 203 sec. 8 table 3)
  MLKEM768_PUBLIC_KEY_SIZE = Int32(1184);
  MLKEM768_CIPHERTEXT_SIZE = Int32(1088);
  MLKEM768_SHARED_SECRET_SIZE = Int32(32);

  BCRYPT_USE_SYSTEM_PREFERRED_RNG = ULONG($00000002);
  BCRYPT_ALG_HANDLE_HMAC_FLAG = ULONG($00000008);
  // the HKDF info travels in the BCryptKeyDerivation parameter list, not as a key property
  KDF_HKDF_INFO = ULONG($14);
  BCRYPTBUFFER_VERSION = ULONG(0);
  BCRYPT_AUTH_MODE_INFO_VERSION = ULONG(1);
  STATUS_AUTH_TAG_MISMATCH = Integer($C000A002);

  // ncrypt.dll (key-storage layer) for signing-key import + sign
  NCRYPT_DLL = 'ncrypt.dll';
  NCRYPT_PAD_PKCS1_FLAG = ULONG($00000002);
  NCRYPT_PAD_PSS_FLAG = ULONG($00000008);
  NCRYPT_SILENT_FLAG = ULONG($00000040);
  // NCryptImportKey parameter list: the password for an encrypted PKCS#8 blob is passed as a
  // NCRYPTBUFFER_PKCS_SECRET buffer, so the KSP decrypts and imports in one call.
  NCRYPTBUFFER_VERSION = ULONG(0);
  NCRYPTBUFFER_PKCS_SECRET = ULONG(46);

  // crypt32.dll for importing an X.509 public key (verify), and the matching BCrypt pads
  CRYPT32_DLL = 'crypt32.dll';
  X509_ASN_ENCODING = DWORD($00000001);
  CRYPT_DECODE_ALLOC_FLAG = DWORD($00008000);
  X509_PUBLIC_KEY_INFO_STRUCT = PAnsiChar(8); // WinCrypt lpszStructType ordinal
  BCRYPT_PAD_PKCS1 = ULONG($00000002);
  BCRYPT_PAD_PSS = ULONG($00000008);
  STATUS_INVALID_SIGNATURE = Integer($C000A000);

  // crypt32 PKCS#12 import (keep the key CNG-backed and out of on-disk storage). The
  // no-persist key handle is attached to the cert context (not via prov-info), so it is
  // read directly from CERT_NCRYPT_KEY_HANDLE_PROP_ID.
  PKCS12_NO_PERSIST_KEY = DWORD($00008000);
  PKCS12_ALWAYS_CNG_KSP = DWORD($00000200);
  CERT_FIND_HAS_PRIVATE_KEY = DWORD($00150000);
  CERT_NCRYPT_KEY_HANDLE_PROP_ID = DWORD(78);

var
  // widestring parameters passed to CNG as PWideChar
  BLOB_ECCPUBLIC: WideString = 'ECCPUBLICBLOB';
  BLOB_ECCPRIVATE: WideString = 'ECCPRIVATEBLOB';
  KDF_RAW_SECRET: WideString = 'TRUNCATE';
  BCRYPT_CHAINING_MODE_PROP: WideString = 'ChainingMode';
  BCRYPT_CHAIN_MODE_GCM_VAL: WideString = 'ChainingModeGCM';
  BCRYPT_ECC_CURVE_NAME_PROP: WideString = 'ECCCurveName';
  CURVE25519_NAME: WideString = 'curve25519';
  MLKEM_ALG_NAME: WideString = 'ML-KEM';
  BCRYPT_PARAMETER_SET_NAME_PROP: WideString = 'ParameterSetName';
  MLKEM_768_PARAM_SET: WideString = '768';
  BLOB_MLKEM_PUBLIC: WideString = 'MLKEMPUBLICBLOB';
  BLOB_MLKEM_PRIVATE: WideString = 'MLKEMPRIVATEBLOB';
  NCRYPT_KSP_NAME: WideString = 'Microsoft Software Key Storage Provider';
  BLOB_PKCS8_PRIVATE: WideString = 'PKCS8_PRIVATEKEY';
  NCRYPT_ALG_NAME_PROP: WideString = 'Algorithm Name';
  HASH_ALG_SHA256: WideString = 'SHA256';
  HASH_ALG_SHA384: WideString = 'SHA384';
  HASH_ALG_SHA512: WideString = 'SHA512';
  BCRYPT_HKDF_ALG: WideString = 'HKDF';
  BCRYPT_HKDF_HASH_NAME: WideString = 'HkdfHashAlgorithm';
  BCRYPT_HKDF_PRK_AND_FINALIZE: WideString = 'HkdfPrkAndFinalize';
  BCRYPT_PUBLIC_KEY_LENGTH_PROP: WideString = 'PublicKeyLength';

resourcestring
  SInvalidPeerPoint = 'the peer public point is not a valid curve point';
  SDegenerateSharedSecret =
    'the peer key produced a degenerate all-zero shared secret';
  SCngBackendError = 'a Windows CNG operation failed (status 0x%.8x)';
  SCngUnavailable = 'Windows CNG is not available on this host';
  SAeadAuthFailed = 'AEAD authentication failed';
  SInvalidKeySize = 'AEAD key size %d does not match the required %d bytes';
  SInvalidNonceSize = 'AEAD nonce size %d does not match the required %d bytes';
  SHkdfExpandTooLong = 'HKDF-Expand output length %d exceeds 255 * HashLen (%d)';
  SInvalidScalarSize = 'private scalar size %d does not match the curve field size %d';

type
  // bcrypt.dll entry points, resolved at runtime (no static import, so an absent DLL or
  // entry point leaves the composer to fall back rather than failing the process load).
  TBCryptOpenAlgorithmProvider = function(out phAlgorithm: Pointer;
    pszAlgId, pszImplementation: PWideChar; dwFlags: ULONG): Integer; stdcall;
  TBCryptCloseAlgorithmProvider = function(hAlgorithm: Pointer;
    dwFlags: ULONG): Integer; stdcall;
  TBCryptGenerateKeyPair = function(hAlgorithm: Pointer; out phKey: Pointer;
    dwLength, dwFlags: ULONG): Integer; stdcall;
  TBCryptFinalizeKeyPair = function(hKey: Pointer; dwFlags: ULONG): Integer; stdcall;
  TBCryptExportKey = function(hKey, hExportKey: Pointer; pszBlobType: PWideChar;
    pbOutput: PByte; cbOutput: ULONG; var pcbResult: ULONG;
    dwFlags: ULONG): Integer; stdcall;
  TBCryptImportKeyPair = function(hAlgorithm, hImportKey: Pointer;
    pszBlobType: PWideChar; out phKey: Pointer; pbInput: PByte; cbInput: ULONG;
    dwFlags: ULONG): Integer; stdcall;
  TBCryptDestroyKey = function(hKey: Pointer): Integer; stdcall;
  TBCryptSecretAgreement = function(hPrivKey, hPubKey: Pointer;
    out phAgreedSecret: Pointer; dwFlags: ULONG): Integer; stdcall;
  TBCryptDeriveKey = function(hSharedSecret: Pointer; pwszKDF: PWideChar;
    pParameterList: Pointer; pbDerivedKey: PByte; cbDerivedKey: ULONG;
    var pcbResult: ULONG; dwFlags: ULONG): Integer; stdcall;
  TBCryptDestroySecret = function(hSecret: Pointer): Integer; stdcall;
  TBCryptGenRandom = function(hAlgorithm: Pointer; pbBuffer: PByte;
    cbBuffer, dwFlags: ULONG): Integer; stdcall;
  TBCryptCreateHash = function(hAlgorithm: Pointer; out phHash: Pointer;
    pbHashObject: PByte; cbHashObject: ULONG; pbSecret: PByte; cbSecret: ULONG;
    dwFlags: ULONG): Integer; stdcall;
  TBCryptHashData = function(hHash: Pointer; pbInput: PByte; cbInput: ULONG;
    dwFlags: ULONG): Integer; stdcall;
  TBCryptFinishHash = function(hHash: Pointer; pbOutput: PByte; cbOutput: ULONG;
    dwFlags: ULONG): Integer; stdcall;
  TBCryptDuplicateHash = function(hHash: Pointer; out phNewHash: Pointer;
    pbHashObject: PByte; cbHashObject: ULONG; dwFlags: ULONG): Integer; stdcall;
  TBCryptDestroyHash = function(hHash: Pointer): Integer; stdcall;
  TBCryptSetProperty = function(hObject: Pointer; pszProperty: PWideChar;
    pbInput: PByte; cbInput, dwFlags: ULONG): Integer; stdcall;
  TBCryptGenerateSymmetricKey = function(hAlgorithm: Pointer; out phKey: Pointer;
    pbKeyObject: PByte; cbKeyObject: ULONG; pbSecret: PByte; cbSecret: ULONG;
    dwFlags: ULONG): Integer; stdcall;
  TBCryptEncrypt = function(hKey: Pointer; pbInput: PByte; cbInput: ULONG;
    pPaddingInfo: Pointer; pbIV: PByte; cbIV: ULONG; pbOutput: PByte;
    cbOutput: ULONG; var pcbResult: ULONG; dwFlags: ULONG): Integer; stdcall;
  TBCryptDecrypt = function(hKey: Pointer; pbInput: PByte; cbInput: ULONG;
    pPaddingInfo: Pointer; pbIV: PByte; cbIV: ULONG; pbOutput: PByte;
    cbOutput: ULONG; var pcbResult: ULONG; dwFlags: ULONG): Integer; stdcall;
  // KEM entry points (Win11 24H2+): optional - resolved but not part of the readiness
  // gate, so their absence on older Windows leaves KEM to fall back, not the whole context
  TBCryptEncapsulate = function(hKey: Pointer; pbSecret: PByte; cbSecret: ULONG;
    var pcbSecret: ULONG; pbCipherText: PByte; cbCipherText: ULONG;
    var pcbCipherText: ULONG; dwFlags: ULONG): Integer; stdcall;
  TBCryptDecapsulate = function(hKey: Pointer; pbCipherText: PByte;
    cbCipherText: ULONG; pbSecret: PByte; cbSecret: ULONG; var pcbSecret: ULONG;
    dwFlags: ULONG): Integer; stdcall;
  TBCryptVerifySignature = function(hKey: Pointer; pPaddingInfo: Pointer;
    pbHash: PByte; cbHash: ULONG; pbSignature: PByte; cbSignature: ULONG;
    dwFlags: ULONG): Integer; stdcall;
  TBCryptKeyDerivation = function(hKey: Pointer; pParameterList: Pointer;
    pbDerivedKey: PByte; cbDerivedKey: ULONG; out pcbResult: ULONG;
    dwFlags: ULONG): Integer; stdcall;
  TBCryptGetProperty = function(hObject: Pointer; pszProperty: PWideChar;
    pbOutput: PByte; cbOutput: ULONG; out pcbResult: ULONG;
    dwFlags: ULONG): Integer; stdcall;

  // ncrypt.dll (NCrypt / KSP layer): imports a PKCS#8 key ephemerally and signs a digest.
  // Handles are ULONG_PTR (pointer-sized integers).
  TNCryptOpenStorageProvider = function(out phProvider: NativeUInt;
    pszProviderName: PWideChar; dwFlags: ULONG): Integer; stdcall;
  TNCryptImportKey = function(hProvider, hImportKey: NativeUInt;
    pszBlobType: PWideChar; pParameterList: Pointer; out phKey: NativeUInt;
    pbData: PByte; cbData, dwFlags: ULONG): Integer; stdcall;
  TNCryptGetProperty = function(hObject: NativeUInt; pszProperty: PWideChar;
    pbOutput: PByte; cbOutput: ULONG; out pcbResult: ULONG;
    dwFlags: ULONG): Integer; stdcall;
  TNCryptSignHash = function(hKey: NativeUInt; pPaddingInfo: Pointer;
    pbHashValue: PByte; cbHashValue: ULONG; pbSignature: PByte; cbSignature: ULONG;
    out pcbResult: ULONG; dwFlags: ULONG): Integer; stdcall;
  TNCryptFreeObject = function(hObject: NativeUInt): Integer; stdcall;

  // NCryptBuffer / NCryptBufferDesc (ncrypt.h): the parameter list that carries the
  // decryption password for an encrypted PKCS#8 import.
  TNCryptBuffer = record
    cbBuffer: ULONG;
    BufferType: ULONG;
    pvBuffer: Pointer;
  end;

  PNCryptBuffer = ^TNCryptBuffer;

  TNCryptBufferDesc = record
    ulVersion: ULONG;
    cBuffers: ULONG;
    pBuffers: PNCryptBuffer;
  end;

  // BCRYPT_PKCS1_PADDING_INFO / BCRYPT_PSS_PADDING_INFO (bcrypt.h), reused by NCryptSignHash.
  // pszAlgId is the hash algorithm id (e.g. "SHA256"); cbSalt (PSS) is the salt length.
  TBCryptPkcs1PaddingInfo = record
    pszAlgId: PWideChar;
  end;

  TBCryptPssPaddingInfo = record
    pszAlgId: PWideChar;
    cbSalt: ULONG;
  end;

  // the resolved ncrypt entry-point table.
  TNCryptApi = record
    OpenStorageProvider: TNCryptOpenStorageProvider;
    ImportKey: TNCryptImportKey;
    GetProperty: TNCryptGetProperty;
    SignHash: TNCryptSignHash;
    FreeObject: TNCryptFreeObject;
  end;

  // BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO (bcrypt.h). Field order and natural alignment
  // match the C struct on x86 and x64; only the one-shot fields are used.
  TBCryptAuthCipherModeInfo = record
    cbSize: ULONG;
    dwInfoVersion: ULONG;
    pbNonce: PByte;
    cbNonce: ULONG;
    pbAuthData: PByte;
    cbAuthData: ULONG;
    pbTag: PByte;
    cbTag: ULONG;
    pbMacContext: PByte;
    cbMacContext: ULONG;
    cbAAD: ULONG;
    cbData: UInt64;
    dwFlags: ULONG;
  end;

  // the resolved bcrypt entry-point table, copied by value into the objects that use it.
  TCngApi = record
    OpenAlgorithmProvider: TBCryptOpenAlgorithmProvider;
    CloseAlgorithmProvider: TBCryptCloseAlgorithmProvider;
    GenerateKeyPair: TBCryptGenerateKeyPair;
    FinalizeKeyPair: TBCryptFinalizeKeyPair;
    ExportKey: TBCryptExportKey;
    ImportKeyPair: TBCryptImportKeyPair;
    DestroyKey: TBCryptDestroyKey;
    SecretAgreement: TBCryptSecretAgreement;
    DeriveKey: TBCryptDeriveKey;
    DestroySecret: TBCryptDestroySecret;
    GenRandom: TBCryptGenRandom;
    CreateHash: TBCryptCreateHash;
    HashData: TBCryptHashData;
    FinishHash: TBCryptFinishHash;
    DuplicateHash: TBCryptDuplicateHash;
    DestroyHash: TBCryptDestroyHash;
    SetProperty: TBCryptSetProperty;
    GenerateSymmetricKey: TBCryptGenerateSymmetricKey;
    Encrypt: TBCryptEncrypt;
    Decrypt: TBCryptDecrypt;
    Encapsulate: TBCryptEncapsulate;
    Decapsulate: TBCryptDecapsulate;
    VerifySignature: TBCryptVerifySignature;
    GetProperty: TBCryptGetProperty;
    KeyDerivation: TBCryptKeyDerivation;
  end;

  // crypt32.dll: decodes an X.509 SubjectPublicKeyInfo and imports it as a BCrypt public
  // key handle usable with BCryptVerifySignature.
  TCryptDecodeObjectEx = function(dwCertEncodingType: DWORD;
    lpszStructType: PAnsiChar; pbEncoded: PByte; cbEncoded, dwFlags: DWORD;
    pDecodePara: Pointer; pvStructInfo: Pointer; var pcbStructInfo: DWORD): BOOL; stdcall;
  TCryptImportPublicKeyInfoEx2 = function(dwCertEncodingType: DWORD; pInfo: Pointer;
    dwFlags: DWORD; pvAuxInfo: Pointer; out phKey: Pointer): BOOL; stdcall;

  TCryptDataBlob = record
    cbData: DWORD;
    pbData: PByte;
  end;

  // crypt32 PKCS#12: import a PFX to an in-memory store, find the key cert, and acquire its
  // (CNG) private key handle.
  TPFXImportCertStore = function(pPFX: Pointer; szPassword: PWideChar;
    dwFlags: DWORD): Pointer; stdcall;
  TCertFindCertificateInStore = function(hCertStore: Pointer;
    dwCertEncodingType, dwFindFlags, dwFindType: DWORD; pvFindPara: Pointer;
    pPrevCertContext: Pointer): Pointer; stdcall;
  TCertGetCertificateContextProperty = function(pCertContext: Pointer;
    dwPropId: DWORD; pvData: Pointer; out pcbData: DWORD): BOOL; stdcall;
  TCertFreeCertificateContext = function(pCertContext: Pointer): BOOL; stdcall;
  TCertCloseStore = function(hCertStore: Pointer; dwFlags: DWORD): BOOL; stdcall;

  TCrypt32Api = record
    DecodeObjectEx: TCryptDecodeObjectEx;
    ImportPublicKeyInfoEx2: TCryptImportPublicKeyInfoEx2;
    PFXImportCertStore: TPFXImportCertStore;
    CertFindCertificateInStore: TCertFindCertificateInStore;
    GetCertContextProperty: TCertGetCertificateContextProperty;
    FreeCertificateContext: TCertFreeCertificateContext;
    CloseStore: TCertCloseStore;
  end;

  // shared CNG status check: a failed OS call is a backend fault (fail-closed - never a
  // silent per-operation fallback to portable code once a facet is serving natively).
  TCngError = class sealed(TObject)
    class procedure Check(AStatus: Integer); static;
  end;

  // resolves a named entry point from a runtime-loaded module.
  TModuleApi = class sealed(TObject)
    class function Proc(AModule: THandle; const AName: AnsiString): Pointer; static;
  end;

  // a single NIST prime curve as CNG parametrizes it.
  TCngCurve = record
    Name: string;
    KeyBits: ULONG;
    FieldSize: Int32;
    PubMagic: ULONG;
    PrivMagic: ULONG;
  end;

  // whether native ECDH is usable and, if so, the factory for its per-curve agreements.
  IWindowsCng = interface(IInterface)
    ['{7B3E1D2A-9C64-4A18-B5D7-0E2F6C8A4B31}']
    function TryCreateAgreement(AAlgorithm: TKeyAgreementAlgorithm;
      out AAgreement: IKeyAgreement): Boolean;
    /// <summary>Whether the given NIST curve is served from CNG on this host (its
    /// algorithm provider opened). False for a curve CNG could not open, or a non-NIST one.</summary>
    function Available(AAlgorithm: TKeyAgreementAlgorithm): Boolean;
    /// <summary>The CNG system-preferred DRBG (BCryptGenRandom). Valid only when
    /// <see cref="RandomAvailable" />.</summary>
    function Random: IRandom;
    /// <summary>Whether the CNG DRBG is usable on this host.</summary>
    function RandomAvailable: Boolean;
    /// <summary>A CNG hash for AAlgorithm, or False when CNG cannot serve it here.</summary>
    function TryCreateHash(AAlgorithm: THashAlgorithm; out AHash: IHash): Boolean;
    /// <summary>Whether the given hash is served from CNG on this host.</summary>
    function HashAvailable(AAlgorithm: THashAlgorithm): Boolean;
    /// <summary>A CNG HMAC for AAlgorithm, or False when CNG cannot serve it here.</summary>
    function TryCreateHmac(AAlgorithm: THashAlgorithm; out AHmac: IHmac): Boolean;
    /// <summary>Whether HMAC over the given hash is served from CNG on this host.</summary>
    function HmacAvailable(AAlgorithm: THashAlgorithm): Boolean;
    /// <summary>HKDF-Expand served in-module by the CNG HKDF provider (RFC 5869), gated on a
    /// startup self-test against a known vector. False when unavailable or a call is rejected,
    /// so the caller composes Expand over the CNG HMAC instead.</summary>
    function TryHkdfExpandNative(AAlgorithm: THashAlgorithm; const APrk, AInfo: TBytes;
      ALength: Int32; out AOkm: TBytes): Boolean;
    /// <summary>A CNG AEAD for AAlgorithm, or False when CNG cannot serve it here (e.g.
    /// ChaCha20-Poly1305 before Windows 11).</summary>
    function TryCreateAead(AAlgorithm: TAeadAlgorithm; out AAead: IAead): Boolean;
    /// <summary>Whether the given AEAD is served from CNG on this host.</summary>
    function AeadAvailable(AAlgorithm: TAeadAlgorithm): Boolean;
    /// <summary>A CNG KEM for AAlgorithm, or False when CNG cannot serve it here (ML-KEM
    /// needs Windows 11 24H2 or later).</summary>
    function TryCreateKem(AAlgorithm: TKemAlgorithm; out AKem: IKem): Boolean;
    /// <summary>Whether the given KEM is served from CNG on this host.</summary>
    function KemAvailable(AAlgorithm: TKemAlgorithm): Boolean;
    /// <summary>The resolved bcrypt entry-point table, so the signing engine can verify a
    /// signature (BCryptVerifySignature) over a crypt32-imported public key.</summary>
    function BcryptApi: TCngApi;
  end;

  // Shared state and blob export for the CNG asymmetric primitives (ECDH, X25519, ML-KEM):
  // the resolved API table by value, the borrowed algorithm handle, and the owning context
  // that keeps that handle alive.
  TWindowsCngKeyPrimitive = class(TInterfacedObject)
  strict protected
  var
    FApi: TCngApi;
    FAlg: Pointer;
    FKeeper: IWindowsCng;
    function ExportBlob(AKey: Pointer; const ABlobType: WideString): TBytes;
    class function Reversed(const ASource: TBytes): TBytes; static;
  public
    constructor Create(const AApi: TCngApi; AAlg: Pointer; const AKeeper: IWindowsCng);
  end;

  // A NIST prime-curve ECDH key agreement backed by Windows CNG. It is the native
  // counterpart of the portable custom-curve agreement: same neutral currency (raw
  // private material as ISecretBuffer, SEC1 uncompressed public point, the big-endian
  // x-coordinate shared secret at field width) and the same fail-closed peer-input
  // checks, so the two are interchangeable and produce identical shared secrets. The
  // resolved API table is held by value; the CNG algorithm handle is borrowed from and
  // kept alive by the owning context.
  TWindowsCngKeyAgreement = class(TWindowsCngKeyPrimitive, IKeyAgreement)
  strict private
  var
    FCurve: TCngCurve;
    function IsUncompressed(const APoint: TBytes): Boolean;
    function PeerPublicBlob(const APoint: TBytes): TBytes;
    function ScalarPrivateBlob(const AScalar: TBytes): TBytes;
    function ImportPeer(const APeerPublicKey: TBytes): Pointer;
    function DeriveBigEndianSecret(ASecret: Pointer): TBytes;
  public
    constructor Create(const AApi: TCngApi; AAlg: Pointer; const ACurve: TCngCurve;
      const AKeeper: IWindowsCng);
    function Name: string;
    procedure GenerateKeyPair(out APrivateKey: ISecretBuffer; out APublicKey: TBytes);
    function Agree(const APrivateKey: ISecretBuffer;
      const APeerPublicKey: TBytes): ISecretBuffer;
    function ValidatePublicKey(const APublicKey: TBytes): Boolean;
    function ImportPrivateKey(const ARawPrivateKey: ISecretBuffer;
      out APublicKey: TBytes): ISecretBuffer;
    function ExportPrivateKey(const APrivateKey: ISecretBuffer): ISecretBuffer;
  end;

  // X25519 (RFC 7748) key agreement via CNG's generic curve25519 ECDH. Keys are the raw
  // 32-byte little-endian u-coordinate / scalar (not SEC1); the shared secret is the CNG
  // raw agreement byte-reversed to the RFC 7748 output. Same neutral currency and
  // fail-closed checks as the portable X25519, so the two are interchangeable. The
  // algorithm handle is borrowed from and kept alive by the owning context.
  TWindowsCngX25519 = class(TWindowsCngKeyPrimitive, IKeyAgreement)
  strict private
    function PeerBlob(const APeer: TBytes): TBytes;
    function PrivateBlob(const AScalar: TBytes): TBytes;
    function DeriveSecret(ASecret: Pointer): TBytes;
  public
    function Name: string;
    procedure GenerateKeyPair(out APrivateKey: ISecretBuffer; out APublicKey: TBytes);
    function Agree(const APrivateKey: ISecretBuffer;
      const APeerPublicKey: TBytes): ISecretBuffer;
    function ValidatePublicKey(const APublicKey: TBytes): Boolean;
    function ImportPrivateKey(const ARawPrivateKey: ISecretBuffer;
      out APublicKey: TBytes): ISecretBuffer;
    function ExportPrivateKey(const APrivateKey: ISecretBuffer): ISecretBuffer;
  end;

  // ML-KEM-768 (FIPS 203) key encapsulation via CNG (Win11 24H2+). Keys and ciphertext
  // are the FIPS 203 byte-encodings, so the public key and ciphertext are interchangeable
  // with the portable ML-KEM; the decapsulation key round-trips as CNG's own opaque
  // private blob (re-imported per operation). Same neutral currency as the portable KEM.
  // The algorithm handle is borrowed from and kept alive by the owning context.
  TWindowsCngKem = class(TWindowsCngKeyPrimitive, IKem)
  strict private
    function ExtractPublicKey(const ABlob: TBytes): TBytes;
    function ImportPublic(const APeerPublicKey: TBytes): Pointer;
    function ImportPrivate(const APrivateBlob: TBytes): Pointer;
  public
    function Name: string;
    procedure GenerateKeyPair(out APrivateKey: ISecretBuffer; out APublicKey: TBytes);
    procedure Encapsulate(const APeerPublicKey: TBytes; out ACiphertext: TBytes;
      out ASharedSecret: ISecretBuffer);
    procedure Decapsulate(const APrivateKey: ISecretBuffer; const ACiphertext: TBytes;
      out ASharedSecret: ISecretBuffer);
    function ValidatePublicKey(const APublicKey: TBytes): Boolean;
  end;

  // The CNG DRBG (BCryptGenRandom, system-preferred provider - no key material or state
  // held here). Holds the resolved API table by value and pins its context alive.
  TWindowsCngRandom = class(TInterfacedObject, IRandom)
  strict private
  var
    FApi: TCngApi;
    FKeeper: IWindowsCng;
  public
    constructor Create(const AApi: TCngApi; const AKeeper: IWindowsCng);
    procedure NextBytes(var ABuffer: TBytes);
    function GenerateBytes(ALength: Int32): TBytes;
  end;

  // A CNG message digest (SHA-2), with Clone for the deferred/branching TLS transcript
  // hash. Uses a CNG-managed hash object (nil object buffer, supported Win7+); the
  // algorithm-provider handle is borrowed from and kept alive by the context.
  TWindowsCngHash = class(TInterfacedObject, IHash)
  strict private
  var
    FApi: TCngApi;
    FAlg: Pointer;
    FName: string;
    FHashSize, FBlockSize: Int32;
    FKeeper: IWindowsCng;
    FHash: Pointer;
    procedure Fresh;
  public
    constructor Create(const AApi: TCngApi; AAlg: Pointer; const AName: string;
      AHashSize, ABlockSize: Int32; const AKeeper: IWindowsCng);
    destructor Destroy; override;
    function AlgorithmName: string;
    function HashSize: Int32;
    function BlockSize: Int32;
    procedure Update(const AData: TBytes; AOffset, ALength: Int32);
    function DoFinal: TBytes;
    procedure Reset;
    function Clone: IHash;
  end;

  // A CNG HMAC (keyed SHA-2). The HMAC-flagged algorithm-provider handle is borrowed from
  // the context; the key is retained so Reset and DoFinal can re-key for reuse.
  TWindowsCngHmac = class(TInterfacedObject, IHmac)
  strict private
  var
    FApi: TCngApi;
    FAlg: Pointer;
    FName: string;
    FMacSize: Int32;
    FKeeper: IWindowsCng;
    FKey: TBytes;
    FHash: Pointer;
    procedure Fresh;
  public
    constructor Create(const AApi: TCngApi; AAlg: Pointer; const AName: string;
      AMacSize: Int32; const AKeeper: IWindowsCng);
    destructor Destroy; override;
    function AlgorithmName: string;
    function MacSize: Int32;
    procedure Init(const AKey: ISecretBuffer);
    procedure Update(const AData: TBytes; AOffset, ALength: Int32);
    function DoFinal: TBytes;
    procedure Reset;
  end;

  // RFC 5869 HKDF composed over the CNG HMAC (Extract = HMAC(salt, IKM); Expand = the HMAC
  // T-loop). The secret passes through CNG but the construction is portable, so this facet
  // reports as backend Composed.
  TWindowsCngHkdf = class(TInterfacedObject, IHkdf)
  strict private
  var
    FCng: IWindowsCng;
    FAlgorithm: THashAlgorithm;
    FMacSize: Int32;
    function NewMac: IHmac;
  public
    constructor Create(const ACng: IWindowsCng; AAlgorithm: THashAlgorithm;
      AMacSize: Int32);
    function Extract(const ASalt: TBytes;
      const AIkm: ISecretBuffer): ISecretBuffer;
    function Expand(const APrk: ISecretBuffer; const AInfo: TBytes;
      ALength: Int32): ISecretBuffer;
  end;

  // A CNG AEAD (AES-GCM, or ChaCha20-Poly1305 where CNG has it). The algorithm-provider
  // handle is borrowed from the context; the symmetric key is created on Init and reused
  // across records. Seal returns ciphertext||tag; Open raises a fatal bad_record_mac alert
  // on authentication failure, matching the portable adapter's behavior.
  TWindowsCngAead = class(TInterfacedObject, IAead)
  strict private
  var
    FApi: TCngApi;
    FAlg: Pointer;
    FCategory: TAeadUsageCategory;
    FName: string;
    FKeySize, FNonceSize, FTagSize: Int32;
    FKeeper: IWindowsCng;
    FKeyHandle: Pointer;
    procedure InitAuthInfo(out AInfo: TBCryptAuthCipherModeInfo;
      const ANonce, AAad: TBytes; ATag: PByte);
  public
    constructor Create(const AApi: TCngApi; AAlg: Pointer;
      ACategory: TAeadUsageCategory; const AName: string;
      AKeySize, ANonceSize, ATagSize: Int32; const AKeeper: IWindowsCng);
    destructor Destroy; override;
    function AlgorithmName: string;
    function UsageCategory: TAeadUsageCategory;
    function KeySize: Int32;
    function NonceSize: Int32;
    function TagSize: Int32;
    function Overhead: Int32;
    procedure Init(const AKey: ISecretBuffer);
    function Seal(const ANonce, AAad, APlaintext: TBytes): TBytes;
    function Open(const ANonce, AAad, ACiphertext: TBytes): TBytes;
  end;

  // Owns the dynamically loaded bcrypt module and the CNG algorithm-provider handles,
  // opened once and shared across the short-lived primitives it vends. Each vended object
  // keeps the context alive by reference, so a borrowed handle never outlives it. An
  // algorithm CNG cannot open is left unavailable and falls back per-algorithm to the
  // portable facet; construction raises only when bcrypt itself is absent, so the composer
  // then falls back wholesale.
  TWindowsCng = class(TInterfacedObject, IWindowsCng)
  strict private
  var
    FModule: THandle;
    FApi: TCngApi;
    FAlgP256, FAlgP384, FAlgP521: Pointer;
    FX25519: Pointer;
    FHashSha256, FHashSha384, FHashSha512: Pointer;
    FHmacSha256, FHmacSha384, FHmacSha512: Pointer;
    FAesGcm, FChaCha: Pointer;
    FMlKem: Pointer;
    FHkdfAlg: Pointer;
    FRandomOk: Boolean;
    class function LoadApi(out AModule: THandle; out AApi: TCngApi): Boolean; static;
    class function Curve(AAlgorithm: TKeyAgreementAlgorithm): TCngCurve; static;
    function TryOpenAlg(const AAlgId: WideString; AFlags: ULONG = 0): Pointer;
    function OpenAesGcm: Pointer;
    function OpenX25519: Pointer;
    function ProbeRandom: Boolean;
    /// <summary>Derives OKM from an already-computed PRK via the CNG HKDF provider's
    /// PRK-and-finalize path (Expand only). False on any CNG failure, so the caller falls back.</summary>
    function DoNativeHkdfExpand(const AHashName: WideString; const APrk, AInfo: TBytes;
      ALength: Int32; out AOkm: TBytes): Boolean;
  public
    constructor Create;
    destructor Destroy; override;
    function TryCreateAgreement(AAlgorithm: TKeyAgreementAlgorithm;
      out AAgreement: IKeyAgreement): Boolean;
    function Available(AAlgorithm: TKeyAgreementAlgorithm): Boolean;
    function Random: IRandom;
    function RandomAvailable: Boolean;
    function TryCreateHash(AAlgorithm: THashAlgorithm; out AHash: IHash): Boolean;
    function HashAvailable(AAlgorithm: THashAlgorithm): Boolean;
    function TryCreateHmac(AAlgorithm: THashAlgorithm; out AHmac: IHmac): Boolean;
    function HmacAvailable(AAlgorithm: THashAlgorithm): Boolean;
    function TryHkdfExpandNative(AAlgorithm: THashAlgorithm; const APrk, AInfo: TBytes;
      ALength: Int32; out AOkm: TBytes): Boolean;
    function TryCreateAead(AAlgorithm: TAeadAlgorithm; out AAead: IAead): Boolean;
    function AeadAvailable(AAlgorithm: TAeadAlgorithm): Boolean;
    function TryCreateKem(AAlgorithm: TKemAlgorithm; out AKem: IKem): Boolean;
    function KemAvailable(AAlgorithm: TKemAlgorithm): Boolean;
    function BcryptApi: TCngApi;
  end;

  // The Windows-native primitives facet: forwards everything to the portable inner facet
  // except NIST prime-curve key agreement, which it serves from CNG. X25519 and every
  // other primitive fall through to the inner facet unchanged (CNG can do X25519 via the
  // generic ECDH curve-name path, but it is not served here - no speed gain over the
  // portable X25519, and its RFC 7748 raw-key format is a separate encoding).
  TWindowsCryptoPrimitives = class(TForwardingCryptoPrimitives)
  strict private
  var
    FCng: IWindowsCng;
  public
    constructor Create(const AInner: ICryptoPrimitives; const ACng: IWindowsCng);
    function GetRandom: IRandom; override;
    function CreateHash(AAlgorithm: THashAlgorithm): IHash; override;
    function CreateHmac(AAlgorithm: THashAlgorithm): IHmac; override;
    function CreateHkdf(AAlgorithm: THashAlgorithm): IHkdf; override;
    function CreateTls12Prf(AAlgorithm: THashAlgorithm): ITls12Prf; override;
    function CreateAead(AAlgorithm: TAeadAlgorithm): IAead; override;
    function CreateKeyAgreement(AAlgorithm: TKeyAgreementAlgorithm): IKeyAgreement; override;
    function CreateKem(AAlgorithm: TKemAlgorithm): IKem; override;
  end;

  // Refcounted owner of one ephemeral NCrypt key handle, freed when the last sharer (the
  // signing key and any preference-narrowed copy) releases it.
  INCryptKeyOwner = interface(IInterface)
    ['{8F1B3D42-0A5C-4977-B6E1-9C2D4E7A8B31}']
    function Handle: NativeUInt;
  end;

  // Marks a signing key produced by this backend, so the Signing decorator can route a
  // CreateSignatureSigner to the same backend that imported the key - a native and a
  // portable ISigningKey handle are not interchangeable.
  IWindowsSigningKey = interface(IInterface)
    ['{2C9E5A17-6B4D-4E88-9A0F-7D3C1B2E5F60}']
    function SigningKeyOwner: INCryptKeyOwner;
  end;

  // ncrypt.dll plus the Microsoft Software KSP, opened once. Imports PKCS#8 signing keys
  // ephemerally (no key name = not persisted) and signs a digest; borrows the CNG context
  // for the pre-hash. Construction raises only when ncrypt or the provider is unavailable,
  // so signing then stays portable. Pins the CNG context alive.
  IWindowsNCrypt = interface(IInterface)
    ['{5D7A2E90-3C41-4B6F-8E2A-1F9C0B4D6A72}']
    /// <summary>Imports a PKCS#8 key the KSP can serve for signing (RSA or NIST-curve
    /// ECDSA) and reports the schemes it can sign with; False when the key is not one this
    /// facet serves natively (the caller then delegates to the portable facet). A non-empty
    /// APassword decrypts an encrypted PKCS#8 (EncryptedPrivateKeyInfo) in the same call.</summary>
    function TryImportKey(const APkcs8: TBytes; const APassword: string;
      out AKey: NativeUInt; out ASchemes: TArray<TSignatureScheme>): Boolean;
    function SignData(AKey: NativeUInt; AScheme: TSignatureScheme;
      const AData: TBytes): TBytes;
    procedure FreeKey(AKey: NativeUInt);
    /// <summary>Whether native verification (crypt32 SPKI import + BCryptVerifySignature)
    /// is usable on this host.</summary>
    function CanVerify: Boolean;
    /// <summary>Imports an X.509 SubjectPublicKeyInfo into a BCrypt public key handle;
    /// False when it cannot (the caller then verifies portably).</summary>
    function TryImportSpki(const ASpki: TBytes; out AKeyHandle: Pointer): Boolean;
    /// <summary>Verifies a signature over data with the imported public key, fail-closed
    /// (any fault or mismatch returns False).</summary>
    function VerifyData(AKeyHandle: Pointer; AScheme: TSignatureScheme;
      const AData, ASignature: TBytes): Boolean;
    procedure FreeVerifyKey(AKeyHandle: Pointer);
    /// <summary>Imports a PKCS#12 blob and adopts its private key as a native CNG-backed
    /// signing key; False when it cannot (the caller then keeps the portable key).</summary>
    function TryImportPkcs12Key(const APfx: TBytes; const APassword: string;
      out AKey: ISigningKey): Boolean;
    /// <summary>Releases a PKCS#12-acquired key: the key handle (when caller-owned), its
    /// certificate context, and the in-memory store.</summary>
    procedure FreePfxKey(AStore, ACert: Pointer; AHandle: NativeUInt;
      ACallerFree: Boolean);
  end;

  TNCryptKeyOwner = class(TInterfacedObject, INCryptKeyOwner)
  strict private
  var
    FKeeper: IWindowsNCrypt;
    FHandle: NativeUInt;
  public
    constructor Create(const AKeeper: IWindowsNCrypt; AHandle: NativeUInt);
    destructor Destroy; override;
    function Handle: NativeUInt;
  end;

  // Owns a PKCS#12-acquired CNG key. The ephemeral key's lifetime is tied to the in-memory
  // certificate store it came from, so this owner keeps the store and cert context alive
  // and closes them (freeing the key) on release.
  TPfxKeyOwner = class(TInterfacedObject, INCryptKeyOwner)
  strict private
  var
    FKeeper: IWindowsNCrypt;
    FStore: Pointer;
    FCert: Pointer;
    FHandle: NativeUInt;
    FCallerFree: Boolean;
  public
    constructor Create(const AKeeper: IWindowsNCrypt; AStore, ACert: Pointer;
      AHandle: NativeUInt; ACallerFree: Boolean);
    destructor Destroy; override;
    function Handle: NativeUInt;
  end;

  // A native (NCrypt-backed) signing key: an opaque ISigningKey plus the private marker.
  // It shares the refcounted key-handle owner with any preference-narrowed copy.
  TWindowsSigningKey = class(TInterfacedObject, ISigningKey, IWindowsSigningKey)
  strict private
  var
    FOwner: INCryptKeyOwner;
    FSchemes: TArray<TSignatureScheme>;
  public
    constructor Create(const AOwner: INCryptKeyOwner;
      const ASchemes: TArray<TSignatureScheme>);
    function CapableSchemes: TArray<TSignatureScheme>;
    function WithPreferredSchemes(const ASchemes: TArray<TSignatureScheme>): ISigningKey;
    function SigningKeyOwner: INCryptKeyOwner;
  end;

  // Buffers the to-be-signed / to-be-verified bytes for the signer and verifier below; its
  // Update satisfies the accumulate step of both ISignatureSigner and ISignatureVerifier.
  TWindowsSignatureBuffer = class(TInterfacedObject)
  strict protected
  var
    FBuffer: TBytes;
  public
    procedure Update(const AData: TBytes; AOffset, ALength: Int32);
  end;

  // Accumulates the to-be-signed bytes, then hashes (via CNG) and signs (via NCrypt).
  TWindowsSignatureSigner = class(TWindowsSignatureBuffer, ISignatureSigner)
  strict private
  var
    FKeeper: IWindowsNCrypt;
    FOwner: INCryptKeyOwner; // pins the key handle for our lifetime
    FScheme: TSignatureScheme;
    FSchemeName: string;
  public
    constructor Create(const AKeeper: IWindowsNCrypt; const AOwner: INCryptKeyOwner;
      AScheme: TSignatureScheme; const ASchemeName: string);
    function AlgorithmName: string;
    function Sign: TBytes;
  end;

  // Accumulates the to-be-verified bytes, then verifies (via crypt32-imported key + BCrypt).
  // Owns the imported public key handle, freed on release. Fail-closed: any fault is False.
  TWindowsSignatureVerifier = class(TWindowsSignatureBuffer, ISignatureVerifier)
  strict private
  var
    FKeeper: IWindowsNCrypt;
    FKeyHandle: Pointer;
    FScheme: TSignatureScheme;
    FSchemeName: string;
  public
    constructor Create(const AKeeper: IWindowsNCrypt; AKeyHandle: Pointer;
      AScheme: TSignatureScheme; const ASchemeName: string);
    destructor Destroy; override;
    function AlgorithmName: string;
    function Verify(const ASignature: TBytes): Boolean;
  end;

  TWindowsNCrypt = class(TInterfacedObject, IWindowsNCrypt)
  strict private
  var
    FModule: THandle;
    FCrypt32: THandle;
    FApi: TNCryptApi;
    FCryptApi: TCrypt32Api;
    FBcrypt: TCngApi;
    FProvider: NativeUInt;
    FCng: IWindowsCng;
    FVerifyReady: Boolean;
    FPfxReady: Boolean;
    class function LoadApi(out AModule: THandle; out AApi: TNCryptApi): Boolean; static;
    class function HashAlgForScheme(AScheme: TSignatureScheme): THashAlgorithm; static;
    class function HashIdForScheme(AScheme: TSignatureScheme): WideString; static;
    class function HashLenForScheme(AScheme: TSignatureScheme): ULONG; static;
    function KeyFieldSize(AKeyHandle: Pointer): Int32;
    class function IsPssScheme(AScheme: TSignatureScheme): Boolean; static;
    class function IsEcdsaScheme(AScheme: TSignatureScheme): Boolean; static;
    // raw r||s (from CNG) to a DER SEQUENCE{ INTEGER r, INTEGER s } as TLS carries it
    class function DerEncodeEcdsa(const ARaw: TBytes): TBytes; static;
    class function TryDerDecodeEcdsa(const ADer: TBytes; AFieldSize: Int32;
      out ARaw: TBytes): Boolean; static;
    class function Sec1CurveOid(const ASec1: TBytes; out ACurveOid: TBytes): Boolean; static;
    // wraps a PKCS#1 (RSAPrivateKey) or SEC1 (ECPrivateKey) DER into a PKCS#8 the KSP
    // imports; a PKCS#8 (plain or encrypted) or unrecognized blob passes through unchanged
    class function WrapPkcs8IfNeeded(const ADer: TBytes): TBytes; static;
    function AlgName(AKey: NativeUInt): string;
    function KeySchemes(AKey: NativeUInt;
      out ASchemes: TArray<TSignatureScheme>): Boolean;
    function HashDigest(AAlgorithm: THashAlgorithm; const AData: TBytes): TBytes;
    function SignRsaDigest(AKey: NativeUInt; AScheme: TSignatureScheme;
      const ADigest: TBytes): TBytes;
    function SignEcdsaDigest(AKey: NativeUInt; const ADigest: TBytes): TBytes;
    function VerifyHash(AKeyHandle: Pointer; AScheme: TSignatureScheme;
      const ADigest, ASignature: TBytes): Boolean;
  public
    // the schemes the Windows backend serves natively (RSA-PSS/PKCS1 + NIST-curve ECDSA,
    // both sign and verify; EdDSA has no CNG path) - the single source the report and the
    // signing decorator both consult, so their "native" view cannot drift apart.
    class function IsNativeScheme(AScheme: TSignatureScheme): Boolean; static;
    constructor Create(const ACng: IWindowsCng);
    destructor Destroy; override;
    function TryImportKey(const APkcs8: TBytes; const APassword: string;
      out AKey: NativeUInt; out ASchemes: TArray<TSignatureScheme>): Boolean;
    function SignData(AKey: NativeUInt; AScheme: TSignatureScheme;
      const AData: TBytes): TBytes;
    procedure FreeKey(AKey: NativeUInt);
    function CanVerify: Boolean;
    function TryImportSpki(const ASpki: TBytes; out AKeyHandle: Pointer): Boolean;
    function VerifyData(AKeyHandle: Pointer; AScheme: TSignatureScheme;
      const AData, ASignature: TBytes): Boolean;
    procedure FreeVerifyKey(AKeyHandle: Pointer);
    function TryImportPkcs12Key(const APfx: TBytes; const APassword: string;
      out AKey: ISigningKey): Boolean;
    procedure FreePfxKey(AStore, ACert: Pointer; AHandle: NativeUInt;
      ACallerFree: Boolean);
  end;

  // The Windows-native signing facet: a decorator over the portable signing facet. It
  // imports RSA/ECDSA PKCS#8 keys (DER or PEM, encrypted or not) into CNG and mints native
  // signers for them; every other key (Ed25519/Ed448, PKCS#1/SEC1) and all verification
  // delegate to the inner portable facet. The per-key backend is coherent: a key this facet
  // imported carries the IWindowsSigningKey marker, so its signer is native; a foreign handle
  // routes back to the inner facet that made it.
  TWindowsSigningCrypto = class(TInterfacedObject, ISigningCrypto)
  strict private
  var
    FInner: ISigningCrypto;
    FNCrypt: IWindowsNCrypt;
    class function SchemeName(AScheme: TSignatureScheme): string; static;
    // decodes a PEM PKCS#8 block to DER and imports it natively; the decoded bytes are the
    // plain or still-encrypted PKCS#8 the KSP accepts
    function TryImportPemNative(const AData: TBytes; const APassword: string;
      out AKey: ISigningKey): Boolean;
  public
    constructor Create(const AInner: ISigningCrypto;
      const ANCrypt: IWindowsNCrypt);
    function ImportSigningKey(const AData: TBytes): ISigningKey; overload;
    function ImportSigningKey(const AData: TBytes;
      const APassword: string): ISigningKey; overload;
    function ImportPkcs12(const AData: TBytes;
      const APassword: string): TTlsCredential;
    function CreateSignatureSigner(AScheme: TSignatureScheme;
      const AKey: ISigningKey): ISignatureSigner;
    function CreateSignatureVerifier(AScheme: TSignatureScheme;
      const APublicKeyDer: TBytes): ISignatureVerifier;
  end;

  // The backend map for the composed Windows provider. It answers, per algorithm and
  // facet, whether the operation runs on CNG or the portable library - computed once
  // from the construction-time probes. Today only NIST-curve ECDH is native; every other
  // entry is Portable until its facet lands, and each facet phase fills in its entries.
  TWindowsBackendReport = class(TInterfacedObject, ICryptoBackendReport)
  strict private
  var
    FCng: IWindowsCng;
    FSigningNative: Boolean;
    class function Ent(ABackend: TCryptoBackend;
      AReason: TCryptoBackendReason): TCryptoBackendEntry; static;
    class function NotNative: TCryptoBackendEntry; static;
  public
    constructor Create(const ACng: IWindowsCng; ASigningNative: Boolean);
    function RandomBackend: TCryptoBackendEntry;
    function HashBackend(AAlgorithm: THashAlgorithm): TCryptoBackendEntry;
    function HmacBackend(AAlgorithm: THashAlgorithm): TCryptoBackendEntry;
    function HkdfBackend(AAlgorithm: THashAlgorithm): TCryptoBackendEntry;
    function Tls12PrfBackend(AAlgorithm: THashAlgorithm): TCryptoBackendEntry;
    function AeadBackend(AAlgorithm: TAeadAlgorithm): TCryptoBackendEntry;
    function KeyAgreementBackend(AAlgorithm: TKeyAgreementAlgorithm): TCryptoBackendEntry;
    function KemBackend(AAlgorithm: TKemAlgorithm): TCryptoBackendEntry;
    function SigningBackend(AScheme: TSignatureScheme): TCryptoBackendEntry;
    function SigningKeyBackend(const AKey: ISigningKey): TCryptoBackendEntry;
    function FacetBackend(AFacet: TCryptoFacet): TCryptoBackendEntry;
    function Describe: string;
  end;

{ TCngError }

class procedure TCngError.Check(AStatus: Integer);
begin
  if AStatus <> STATUS_SUCCESS then
    raise ESystemCryptoBackendTlsLibException.CreateResFmt(@SCngBackendError, [AStatus]);
end;

{ TModuleApi }

class function TModuleApi.Proc(AModule: THandle; const AName: AnsiString): Pointer;
begin
  Result := GetProcAddress(AModule, PAnsiChar(AName));
end;

{ TWindowsCngKeyPrimitive }

constructor TWindowsCngKeyPrimitive.Create(const AApi: TCngApi; AAlg: Pointer;
  const AKeeper: IWindowsCng);
begin
  inherited Create;
  FApi := AApi;
  FAlg := AAlg;
  FKeeper := AKeeper; // pins the algorithm-handle / module owner for our lifetime
end;

function TWindowsCngKeyPrimitive.ExportBlob(AKey: Pointer;
  const ABlobType: WideString): TBytes;
var
  LSize, LWritten: ULONG;
begin
  Result := nil;
  LSize := 0;
  TCngError.Check(FApi.ExportKey(AKey, nil, PWideChar(ABlobType), nil, 0, LSize, 0));
  SetLength(Result, LSize);
  LWritten := 0;
  TCngError.Check(FApi.ExportKey(AKey, nil, PWideChar(ABlobType), PByte(Result),
    LSize, LWritten, 0));
  SetLength(Result, LWritten);
end;

class function TWindowsCngKeyPrimitive.Reversed(const ASource: TBytes): TBytes;
var
  LI, LN: Int32;
begin
  LN := System.Length(ASource);
  Result := nil;
  SetLength(Result, LN);
  for LI := 0 to LN - 1 do
    Result[LI] := ASource[LN - 1 - LI];
end;

{ TWindowsCngRandom }

constructor TWindowsCngRandom.Create(const AApi: TCngApi;
  const AKeeper: IWindowsCng);
begin
  inherited Create;
  FApi := AApi;
  FKeeper := AKeeper;
end;

procedure TWindowsCngRandom.NextBytes(var ABuffer: TBytes);
begin
  if System.Length(ABuffer) > 0 then
    TCngError.Check(FApi.GenRandom(nil, PByte(ABuffer), System.Length(ABuffer),
      BCRYPT_USE_SYSTEM_PREFERRED_RNG));
end;

function TWindowsCngRandom.GenerateBytes(ALength: Int32): TBytes;
begin
  Result := nil;
  SetLength(Result, ALength);
  if ALength > 0 then
    NextBytes(Result);
end;

{ TWindowsCngHash }

constructor TWindowsCngHash.Create(const AApi: TCngApi; AAlg: Pointer;
  const AName: string; AHashSize, ABlockSize: Int32; const AKeeper: IWindowsCng);
begin
  inherited Create;
  FApi := AApi;
  FAlg := AAlg;
  FName := AName;
  FHashSize := AHashSize;
  FBlockSize := ABlockSize;
  FKeeper := AKeeper;
  Fresh;
end;

procedure TWindowsCngHash.Fresh;
begin
  FHash := nil;
  // nil hash-object buffer: CNG allocates and frees it with the hash handle (Win7+)
  TCngError.Check(FApi.CreateHash(FAlg, FHash, nil, 0, nil, 0, 0));
end;

destructor TWindowsCngHash.Destroy;
begin
  if FHash <> nil then
    FApi.DestroyHash(FHash);
  inherited Destroy;
end;

function TWindowsCngHash.AlgorithmName: string;
begin
  Result := FName;
end;

function TWindowsCngHash.HashSize: Int32;
begin
  Result := FHashSize;
end;

function TWindowsCngHash.BlockSize: Int32;
begin
  Result := FBlockSize;
end;

procedure TWindowsCngHash.Update(const AData: TBytes; AOffset, ALength: Int32);
begin
  if ALength > 0 then
    TCngError.Check(FApi.HashData(FHash, @AData[AOffset], ALength, 0));
end;

function TWindowsCngHash.DoFinal: TBytes;
begin
  Result := nil;
  SetLength(Result, FHashSize);
  TCngError.Check(FApi.FinishHash(FHash, PByte(Result), FHashSize, 0));
  // finishing finalizes the handle; recreate a fresh one so the instance is reusable
  FApi.DestroyHash(FHash);
  Fresh;
end;

procedure TWindowsCngHash.Reset;
begin
  FApi.DestroyHash(FHash);
  Fresh;
end;

function TWindowsCngHash.Clone: IHash;
var
  LDup: Pointer;
  LClone: TWindowsCngHash;
begin
  LDup := nil;
  TCngError.Check(FApi.DuplicateHash(FHash, LDup, nil, 0, 0));
  LClone := TWindowsCngHash.Create(FApi, FAlg, FName, FHashSize, FBlockSize, FKeeper);
  // discard the fresh handle the constructor made; adopt the duplicated current-state one
  FApi.DestroyHash(LClone.FHash);
  LClone.FHash := LDup;
  Result := LClone;
end;

{ TWindowsCngHmac }

constructor TWindowsCngHmac.Create(const AApi: TCngApi; AAlg: Pointer;
  const AName: string; AMacSize: Int32; const AKeeper: IWindowsCng);
begin
  inherited Create;
  FApi := AApi;
  FAlg := AAlg;
  FName := AName;
  FMacSize := AMacSize;
  FKeeper := AKeeper;
end;

procedure TWindowsCngHmac.Fresh;
begin
  FHash := nil;
  // the key is embedded in the keyed hash; PByte(FKey) is nil for a zero-length key
  TCngError.Check(FApi.CreateHash(FAlg, FHash, nil, 0, PByte(FKey),
    System.Length(FKey), 0));
end;

destructor TWindowsCngHmac.Destroy;
begin
  if FHash <> nil then
    FApi.DestroyHash(FHash);
  TSecureMemory.WipeBytes(FKey);
  inherited Destroy;
end;

function TWindowsCngHmac.AlgorithmName: string;
begin
  Result := FName;
end;

function TWindowsCngHmac.MacSize: Int32;
begin
  Result := FMacSize;
end;

procedure TWindowsCngHmac.Init(const AKey: ISecretBuffer);
begin
  if FHash <> nil then
  begin
    FApi.DestroyHash(FHash);
    FHash := nil;
  end;
  TSecureMemory.WipeBytes(FKey);
  FKey := AKey.ToBytes;
  Fresh;
end;

procedure TWindowsCngHmac.Update(const AData: TBytes; AOffset, ALength: Int32);
begin
  if ALength > 0 then
    TCngError.Check(FApi.HashData(FHash, @AData[AOffset], ALength, 0));
end;

function TWindowsCngHmac.DoFinal: TBytes;
begin
  Result := nil;
  SetLength(Result, FMacSize);
  TCngError.Check(FApi.FinishHash(FHash, PByte(Result), FMacSize, 0));
  // re-key a fresh handle so the instance is reusable with the same key
  FApi.DestroyHash(FHash);
  Fresh;
end;

procedure TWindowsCngHmac.Reset;
begin
  FApi.DestroyHash(FHash);
  Fresh;
end;

{ TWindowsCngHkdf }

constructor TWindowsCngHkdf.Create(const ACng: IWindowsCng;
  AAlgorithm: THashAlgorithm; AMacSize: Int32);
begin
  inherited Create;
  FCng := ACng;
  FAlgorithm := AAlgorithm;
  FMacSize := AMacSize;
end;

function TWindowsCngHkdf.NewMac: IHmac;
begin
  if not FCng.TryCreateHmac(FAlgorithm, Result) then
    raise ESystemCryptoBackendTlsLibException.CreateRes(@SCngUnavailable);
end;

function TWindowsCngHkdf.Extract(const ASalt: TBytes;
  const AIkm: ISecretBuffer): ISecretBuffer;
var
  LSalt, LIkm, LPrk: TBytes;
  LSaltBuf: ISecretBuffer;
  LMac: IHmac;
begin
  LSalt := ASalt;
  if System.Length(LSalt) = 0 then
    SetLength(LSalt, FMacSize); // an empty salt is HashLen zero bytes
  LMac := NewMac;
  LSaltBuf := TSecretBuffer.From(LSalt);
  LMac.Init(LSaltBuf);
  LIkm := AIkm.ToBytes;
  try
    LMac.Update(LIkm, 0, System.Length(LIkm));
    LPrk := LMac.DoFinal;
    try
      Result := TSecretBuffer.From(LPrk);
    finally
      TSecureMemory.WipeBytes(LPrk);
    end;
  finally
    TSecureMemory.WipeBytes(LIkm);
  end;
end;

function TWindowsCngHkdf.Expand(const APrk: ISecretBuffer; const AInfo: TBytes;
  ALength: Int32): ISecretBuffer;
var
  LMac: IHmac;
  LOkm, LT, LCtr, LPrkBytes, LNative: TBytes;
  LPos, LTake: Int32;
  LCounter: Byte;
begin
  // RFC 5869: L must not exceed 255 * HashLen, else the block counter would wrap
  if ALength > 255 * FMacSize then
    raise EArgumentTlsLibException.CreateResFmt(@SHkdfExpandTooLong,
      [ALength, 255 * FMacSize]);
  if ALength = 0 then
    Exit(TSecretBuffer.From(nil));
  // in-module Expand when the CNG HKDF provider is available (self-tested); else the portable
  // T-loop over the CNG HMAC below
  LPrkBytes := APrk.ToBytes;
  try
    if FCng.TryHkdfExpandNative(FAlgorithm, LPrkBytes, AInfo, ALength, LNative) then
    begin
      try
        Result := TSecretBuffer.From(LNative);
      finally
        TSecureMemory.WipeBytes(LNative);
      end;
      Exit;
    end;
  finally
    TSecureMemory.WipeBytes(LPrkBytes);
  end;
  LOkm := nil;
  SetLength(LOkm, ALength);
  LMac := NewMac;
  LMac.Init(APrk);
  LT := nil;
  LCtr := nil;
  SetLength(LCtr, 1);
  LPos := 0;
  LCounter := 1;
  try
    while LPos < ALength do
    begin
      // T(i) = HMAC(PRK, T(i-1) || info || i)
      if System.Length(LT) > 0 then
        LMac.Update(LT, 0, System.Length(LT));
      if System.Length(AInfo) > 0 then
        LMac.Update(AInfo, 0, System.Length(AInfo));
      LCtr[0] := LCounter;
      LMac.Update(LCtr, 0, 1);
      TSecureMemory.WipeBytes(LT); // each T(i) is an OKM prefix; wipe before reassigning
      LT := LMac.DoFinal; // DoFinal re-keys a fresh HMAC for the next block
      LTake := System.Length(LT);
      if LPos + LTake > ALength then
        LTake := ALength - LPos;
      System.Move(LT[0], LOkm[LPos], LTake);
      Inc(LPos, LTake);
      Inc(LCounter);
    end;
    Result := TSecretBuffer.From(LOkm);
  finally
    TSecureMemory.WipeBytes(LOkm);
    TSecureMemory.WipeBytes(LT);
  end;
end;

{ TWindowsCngAead }

constructor TWindowsCngAead.Create(const AApi: TCngApi; AAlg: Pointer;
  ACategory: TAeadUsageCategory; const AName: string;
  AKeySize, ANonceSize, ATagSize: Int32; const AKeeper: IWindowsCng);
begin
  inherited Create;
  FApi := AApi;
  FAlg := AAlg;
  FCategory := ACategory;
  FName := AName;
  FKeySize := AKeySize;
  FNonceSize := ANonceSize;
  FTagSize := ATagSize;
  FKeeper := AKeeper;
end;

destructor TWindowsCngAead.Destroy;
begin
  if FKeyHandle <> nil then
    FApi.DestroyKey(FKeyHandle);
  inherited Destroy;
end;

function TWindowsCngAead.AlgorithmName: string;
begin
  Result := FName;
end;

function TWindowsCngAead.UsageCategory: TAeadUsageCategory;
begin
  Result := FCategory;
end;

function TWindowsCngAead.KeySize: Int32;
begin
  Result := FKeySize;
end;

function TWindowsCngAead.NonceSize: Int32;
begin
  Result := FNonceSize;
end;

function TWindowsCngAead.TagSize: Int32;
begin
  Result := FTagSize;
end;

function TWindowsCngAead.Overhead: Int32;
begin
  Result := FTagSize;
end;

procedure TWindowsCngAead.InitAuthInfo(out AInfo: TBCryptAuthCipherModeInfo;
  const ANonce, AAad: TBytes; ATag: PByte);
begin
  System.FillChar(AInfo, SizeOf(AInfo), 0);
  AInfo.cbSize := SizeOf(AInfo);
  AInfo.dwInfoVersion := BCRYPT_AUTH_MODE_INFO_VERSION;
  AInfo.pbNonce := PByte(ANonce);
  AInfo.cbNonce := System.Length(ANonce);
  if System.Length(AAad) > 0 then
  begin
    AInfo.pbAuthData := PByte(AAad);
    AInfo.cbAuthData := System.Length(AAad);
  end;
  AInfo.pbTag := ATag;
  AInfo.cbTag := FTagSize;
end;

procedure TWindowsCngAead.Init(const AKey: ISecretBuffer);
var
  LKey: TBytes;
begin
  if AKey.Len <> FKeySize then
    raise EArgumentTlsLibException.CreateResFmt(@SInvalidKeySize,
      [AKey.Len, FKeySize]);
  if FKeyHandle <> nil then
  begin
    FApi.DestroyKey(FKeyHandle);
    FKeyHandle := nil;
  end;
  LKey := AKey.ToBytes;
  try
    // nil key-object buffer: CNG allocates and frees it with the key handle (Win7+)
    TCngError.Check(FApi.GenerateSymmetricKey(FAlg, FKeyHandle, nil, 0, PByte(LKey),
      System.Length(LKey), 0));
  finally
    TSecureMemory.WipeBytes(LKey);
  end;
end;

function TWindowsCngAead.Seal(const ANonce, AAad, APlaintext: TBytes): TBytes;
var
  LInfo: TBCryptAuthCipherModeInfo;
  LTag: TBytes;
  LPtLen: Int32;
  LCbResult: ULONG;
  LIn, LOut: PByte;
begin
  if System.Length(ANonce) <> FNonceSize then
    raise EArgumentTlsLibException.CreateResFmt(@SInvalidNonceSize,
      [System.Length(ANonce), FNonceSize]);
  LPtLen := System.Length(APlaintext);
  LTag := nil;
  SetLength(LTag, FTagSize);
  Result := nil;
  SetLength(Result, LPtLen + FTagSize);
  InitAuthInfo(LInfo, ANonce, AAad, PByte(LTag));
  if LPtLen > 0 then
  begin
    LIn := PByte(APlaintext);
    LOut := PByte(Result);
  end
  else
  begin
    LIn := nil;
    LOut := nil;
  end;
  LCbResult := 0;
  TCngError.Check(FApi.Encrypt(FKeyHandle, LIn, LPtLen, @LInfo, nil, 0, LOut,
    LPtLen, LCbResult, 0));
  System.Move(LTag[0], Result[LPtLen], FTagSize);
end;

function TWindowsCngAead.Open(const ANonce, AAad, ACiphertext: TBytes): TBytes;
var
  LInfo: TBCryptAuthCipherModeInfo;
  LCtLen: Int32;
  LCbResult: ULONG;
  LStatus: Integer;
  LIn, LOut: PByte;
begin
  if System.Length(ANonce) <> FNonceSize then
    raise EArgumentTlsLibException.CreateResFmt(@SInvalidNonceSize,
      [System.Length(ANonce), FNonceSize]);
  if System.Length(ACiphertext) < FTagSize then
    raise EFatalAlertTlsLibException.CreateRes(TTlsAlertDescription.BadRecordMac,
      @SAeadAuthFailed);
  LCtLen := System.Length(ACiphertext) - FTagSize;
  Result := nil;
  SetLength(Result, LCtLen);
  // the received tag is the trailing FTagSize bytes of the input
  InitAuthInfo(LInfo, ANonce, AAad, @ACiphertext[LCtLen]);
  if LCtLen > 0 then
  begin
    LIn := PByte(ACiphertext);
    LOut := PByte(Result);
  end
  else
  begin
    LIn := nil;
    LOut := nil;
  end;
  LCbResult := 0;
  LStatus := FApi.Decrypt(FKeyHandle, LIn, LCtLen, @LInfo, nil, 0, LOut, LCtLen,
    LCbResult, 0);
  if LStatus = STATUS_AUTH_TAG_MISMATCH then
    raise EFatalAlertTlsLibException.CreateRes(TTlsAlertDescription.BadRecordMac,
      @SAeadAuthFailed);
  TCngError.Check(LStatus);
end;

{ TWindowsCngKeyAgreement }

constructor TWindowsCngKeyAgreement.Create(const AApi: TCngApi; AAlg: Pointer;
  const ACurve: TCngCurve; const AKeeper: IWindowsCng);
begin
  inherited Create(AApi, AAlg, AKeeper);
  FCurve := ACurve;
end;

function TWindowsCngKeyAgreement.Name: string;
begin
  Result := FCurve.Name;
end;

function TWindowsCngKeyAgreement.IsUncompressed(const APoint: TBytes): Boolean;
begin
  // an EC key share must use the uncompressed point form: RFC 8446 4.2.8.2 (TLS 1.3)
  // and RFC 8422 5.1.2 (TLS 1.2) both mandate it and forbid compressed/hybrid
  Result := (System.Length(APoint) = 1 + 2 * FCurve.FieldSize) and
    (APoint[0] = UncompressedPointPrefix);
end;

function TWindowsCngKeyAgreement.PeerPublicBlob(const APoint: TBytes): TBytes;
begin
  // BCRYPT_ECCKEY_BLOB: { dwMagic; cbKey } then X || Y (both big-endian, field width)
  Result := nil;
  SetLength(Result, ECC_BLOB_HEADER_SIZE + 2 * FCurve.FieldSize);
  PULONG(@Result[0])^ := FCurve.PubMagic;
  PULONG(@Result[4])^ := ULONG(FCurve.FieldSize);
  Move(APoint[1], Result[ECC_BLOB_HEADER_SIZE], 2 * FCurve.FieldSize);
end;

function TWindowsCngKeyAgreement.ImportPeer(const APeerPublicKey: TBytes): Pointer;
var
  LBlob: TBytes;
  LStatus: Integer;
begin
  Result := nil;
  if not IsUncompressed(APeerPublicKey) then
    raise EPeerInputTlsLibException.CreateRes(@SInvalidPeerPoint);
  LBlob := PeerPublicBlob(APeerPublicKey);
  // no BCRYPT_NO_KEY_VALIDATION flag: CNG rejects an off-curve point on import
  LStatus := FApi.ImportKeyPair(FAlg, nil, PWideChar(BLOB_ECCPUBLIC), Result,
    PByte(LBlob), System.Length(LBlob), 0);
  if LStatus <> STATUS_SUCCESS then
    raise EPeerInputTlsLibException.CreateRes(@SInvalidPeerPoint);
end;

function TWindowsCngKeyAgreement.DeriveBigEndianSecret(ASecret: Pointer): TBytes;
var
  LLittle: TBytes;
  LWritten: ULONG;
  LFieldSize: Int32;
begin
  LFieldSize := FCurve.FieldSize;
  // BCRYPT_KDF_RAW_SECRET yields the x-coordinate little-endian; request the field
  // width (TRUNCATE zero-extends) and reverse to the big-endian secret TLS expects
  LLittle := nil;
  SetLength(LLittle, LFieldSize);
  LWritten := 0;
  try
    TCngError.Check(FApi.DeriveKey(ASecret, PWideChar(KDF_RAW_SECRET), nil,
      PByte(LLittle), ULONG(LFieldSize), LWritten, 0));
    Result := Reversed(LLittle);
  finally
    TSecureMemory.WipeBytes(LLittle);
  end;
end;

procedure TWindowsCngKeyAgreement.GenerateKeyPair(out APrivateKey: ISecretBuffer;
  out APublicKey: TBytes);
var
  LKey: Pointer;
  LPublicBlob, LPrivateBlob: TBytes;
begin
  LKey := nil;
  TCngError.Check(FApi.GenerateKeyPair(FAlg, LKey, FCurve.KeyBits, 0));
  try
    TCngError.Check(FApi.FinalizeKeyPair(LKey, 0));
    LPublicBlob := ExportBlob(LKey, BLOB_ECCPUBLIC);
    APublicKey := nil;
    SetLength(APublicKey, 1 + 2 * FCurve.FieldSize);
    APublicKey[0] := UncompressedPointPrefix;
    Move(LPublicBlob[ECC_BLOB_HEADER_SIZE], APublicKey[1], 2 * FCurve.FieldSize);
    // the private blob (header + X + Y + d) is the opaque round-trip material Agree
    // re-imports; it carries the secret scalar, so it is held wipeably
    LPrivateBlob := ExportBlob(LKey, BLOB_ECCPRIVATE);
    try
      APrivateKey := TSecretBuffer.From(LPrivateBlob);
    finally
      TSecureMemory.WipeBytes(LPrivateBlob);
    end;
  finally
    FApi.DestroyKey(LKey);
  end;
end;

function TWindowsCngKeyAgreement.Agree(const APrivateKey: ISecretBuffer;
  const APeerPublicKey: TBytes): ISecretBuffer;
var
  LPrivateBlob, LSecretBytes: TBytes;
  LPrivKey, LPeerKey, LSecret: Pointer;
begin
  LPrivKey := nil;
  LPeerKey := nil;
  LSecret := nil;
  LSecretBytes := nil;
  LPrivateBlob := APrivateKey.ToBytes;
  try
    TCngError.Check(FApi.ImportKeyPair(FAlg, nil, PWideChar(BLOB_ECCPRIVATE),
      LPrivKey, PByte(LPrivateBlob), System.Length(LPrivateBlob), 0));
    try
      LPeerKey := ImportPeer(APeerPublicKey);
      try
        if FApi.SecretAgreement(LPrivKey, LPeerKey, LSecret, 0) <> STATUS_SUCCESS then
          raise EPeerInputTlsLibException.CreateRes(@SInvalidPeerPoint);
        try
          LSecretBytes := DeriveBigEndianSecret(LSecret);
          // defense in depth: never hand back a degenerate (contributory) secret
          if TSecureMemory.ConstantTimeIsAllZero(LSecretBytes) then
            raise EPeerInputTlsLibException.CreateRes(@SDegenerateSharedSecret);
          Result := TSecretBuffer.From(LSecretBytes);
        finally
          FApi.DestroySecret(LSecret);
        end;
      finally
        FApi.DestroyKey(LPeerKey);
      end;
    finally
      FApi.DestroyKey(LPrivKey);
    end;
  finally
    TSecureMemory.WipeBytes(LSecretBytes);
    TSecureMemory.WipeBytes(LPrivateBlob);
  end;
end;

function TWindowsCngKeyAgreement.ValidatePublicKey(
  const APublicKey: TBytes): Boolean;
var
  LBlob: TBytes;
  LPeerKey: Pointer;
begin
  Result := False;
  if not IsUncompressed(APublicKey) then
    Exit;
  LBlob := PeerPublicBlob(APublicKey);
  LPeerKey := nil;
  if FApi.ImportKeyPair(FAlg, nil, PWideChar(BLOB_ECCPUBLIC), LPeerKey,
    PByte(LBlob), System.Length(LBlob), 0) = STATUS_SUCCESS then
  begin
    FApi.DestroyKey(LPeerKey);
    Result := True;
  end;
end;

function TWindowsCngKeyAgreement.ScalarPrivateBlob(const AScalar: TBytes): TBytes;
begin
  // BCRYPT_ECCKEY_BLOB: { magic; cbKey } then zero X, zero Y, then d (big-endian, field
  // width). CNG derives the public point from d on import.
  Result := nil;
  SetLength(Result, ECC_BLOB_HEADER_SIZE + 3 * FCurve.FieldSize);
  System.FillChar(Result[0], System.Length(Result), 0);
  PULONG(@Result[0])^ := FCurve.PrivMagic;
  PULONG(@Result[4])^ := ULONG(FCurve.FieldSize);
  Move(AScalar[0], Result[ECC_BLOB_HEADER_SIZE + 2 * FCurve.FieldSize], FCurve.FieldSize);
end;

function TWindowsCngKeyAgreement.ImportPrivateKey(const ARawPrivateKey: ISecretBuffer;
  out APublicKey: TBytes): ISecretBuffer;
var
  LScalar, LScalarBlob, LFullPrivate, LPublicBlob: TBytes;
  LKey: Pointer;
begin
  LScalar := ARawPrivateKey.ToBytes;
  LScalarBlob := nil;
  LKey := nil;
  try
    if System.Length(LScalar) <> FCurve.FieldSize then
      raise EArgumentTlsLibException.CreateResFmt(@SInvalidScalarSize,
        [System.Length(LScalar), FCurve.FieldSize]);
    LScalarBlob := ScalarPrivateBlob(LScalar);
    TCngError.Check(FApi.ImportKeyPair(FAlg, nil, PWideChar(BLOB_ECCPRIVATE), LKey,
      PByte(LScalarBlob), System.Length(LScalarBlob), 0));
    try
      // public value: SEC1 uncompressed 0x04 || X || Y (CNG derived X,Y from d)
      LPublicBlob := ExportBlob(LKey, BLOB_ECCPUBLIC);
      APublicKey := nil;
      SetLength(APublicKey, 1 + 2 * FCurve.FieldSize);
      APublicKey[0] := UncompressedPointPrefix;
      Move(LPublicBlob[ECC_BLOB_HEADER_SIZE], APublicKey[1], 2 * FCurve.FieldSize);
      // private key handed back = the full ECCPRIVATE blob (X,Y now populated), the
      // representation Agree re-imports; held wipeably as it carries the scalar
      LFullPrivate := ExportBlob(LKey, BLOB_ECCPRIVATE);
      try
        Result := TSecretBuffer.From(LFullPrivate);
      finally
        TSecureMemory.WipeBytes(LFullPrivate);
      end;
    finally
      FApi.DestroyKey(LKey);
    end;
  finally
    TSecureMemory.WipeBytes(LScalar);
    TSecureMemory.WipeBytes(LScalarBlob);
  end;
end;

function TWindowsCngKeyAgreement.ExportPrivateKey(
  const APrivateKey: ISecretBuffer): ISecretBuffer;
var
  LBlob, LScalar: TBytes;
begin
  // extract d (the trailing field-width big-endian bytes) from the ECCPRIVATE blob
  LBlob := APrivateKey.ToBytes;
  LScalar := nil;
  try
    if System.Length(LBlob) <> ECC_BLOB_HEADER_SIZE + 3 * FCurve.FieldSize then
      raise EArgumentTlsLibException.CreateResFmt(@SInvalidScalarSize,
        [System.Length(LBlob), ECC_BLOB_HEADER_SIZE + 3 * FCurve.FieldSize]);
    SetLength(LScalar, FCurve.FieldSize);
    Move(LBlob[ECC_BLOB_HEADER_SIZE + 2 * FCurve.FieldSize], LScalar[0], FCurve.FieldSize);
    Result := TSecretBuffer.From(LScalar);
  finally
    TSecureMemory.WipeBytes(LScalar);
    TSecureMemory.WipeBytes(LBlob);
  end;
end;

{ TWindowsCngX25519 }

function TWindowsCngX25519.Name: string;
begin
  Result := 'X25519';
end;

function TWindowsCngX25519.PeerBlob(const APeer: TBytes): TBytes;
begin
  // generic ECDH public blob: { dwMagic; cbKey=32 } then X (the raw 32-byte little-endian
  // u-coordinate) then a zero Y; CNG needs both coordinate slots present on import
  Result := nil;
  SetLength(Result, ECC_BLOB_HEADER_SIZE + 2 * X25519_KEY_SIZE);
  PULONG(@Result[0])^ := BCRYPT_ECDH_PUBLIC_GENERIC_MAGIC;
  PULONG(@Result[4])^ := ULONG(X25519_KEY_SIZE);
  Move(APeer[0], Result[ECC_BLOB_HEADER_SIZE], X25519_KEY_SIZE);
  // RFC 7748 sec. 5: the receiver masks the u-coordinate's most-significant bit (byte 31,
  // little-endian). CNG does not, so a non-canonical peer key would otherwise derive a
  // secret differing from an implementation that masks (the portable one) - clear it here.
  Result[ECC_BLOB_HEADER_SIZE + X25519_KEY_SIZE - 1] :=
    Result[ECC_BLOB_HEADER_SIZE + X25519_KEY_SIZE - 1] and $7F;
end;

function TWindowsCngX25519.PrivateBlob(const AScalar: TBytes): TBytes;
var
  LOffset: Integer;
begin
  // generic ECDH private blob from the raw 32-byte scalar alone: { magic; cbKey=32 } then a
  // zero X and Y then d. CNG derives the public point from d on import (curve25519), so the
  // scalar is the whole private - matching the portable neutral currency (a bare 32-byte key)
  Result := nil;
  SetLength(Result, ECC_BLOB_HEADER_SIZE + 3 * X25519_KEY_SIZE);
  System.FillChar(Result[0], System.Length(Result), 0);
  PULONG(@Result[0])^ := BCRYPT_ECDH_PRIVATE_GENERIC_MAGIC;
  PULONG(@Result[4])^ := ULONG(X25519_KEY_SIZE);
  LOffset := ECC_BLOB_HEADER_SIZE + 2 * X25519_KEY_SIZE;
  Move(AScalar[0], Result[LOffset], X25519_KEY_SIZE);
  // RFC 7748 clamp: X25519 applies it during scalar-mult, but CNG rejects a scalar that is
  // not already in canonical clamped form, so an external key must be clamped before import
  Result[LOffset] := Result[LOffset] and 248;
  Result[LOffset + X25519_KEY_SIZE - 1] := (Result[LOffset + X25519_KEY_SIZE - 1] and 127) or 64;
end;

function TWindowsCngX25519.DeriveSecret(ASecret: Pointer): TBytes;
var
  LRaw: TBytes;
  LWritten: ULONG;
begin
  // BCRYPT_KDF_RAW_SECRET yields the agreement little-endian; reverse to the RFC 7748
  // big-endian-free output convention shared with the portable X25519
  LRaw := nil;
  SetLength(LRaw, X25519_KEY_SIZE);
  LWritten := 0;
  try
    if FApi.DeriveKey(ASecret, PWideChar(KDF_RAW_SECRET), nil, PByte(LRaw),
      ULONG(X25519_KEY_SIZE), LWritten, 0) <> STATUS_SUCCESS then
      raise EPeerInputTlsLibException.CreateRes(@SInvalidPeerPoint);
    Result := Reversed(LRaw);
  finally
    TSecureMemory.WipeBytes(LRaw);
  end;
end;

procedure TWindowsCngX25519.GenerateKeyPair(out APrivateKey: ISecretBuffer;
  out APublicKey: TBytes);
var
  LKey: Pointer;
  LPublicBlob, LPrivateBlob, LScalar: TBytes;
begin
  LKey := nil;
  TCngError.Check(FApi.GenerateKeyPair(FAlg, LKey, 255, 0));
  try
    TCngError.Check(FApi.FinalizeKeyPair(LKey, 0));
    // the raw public key is the X coordinate of the generic ECC public blob
    LPublicBlob := ExportBlob(LKey, BLOB_ECCPUBLIC);
    APublicKey := nil;
    SetLength(APublicKey, X25519_KEY_SIZE);
    Move(LPublicBlob[ECC_BLOB_HEADER_SIZE], APublicKey[0], X25519_KEY_SIZE);
    // the private key is the raw 32-byte scalar d (blob layout: header + X + Y + d), the
    // neutral currency Agree re-imports; held wipeably
    LPrivateBlob := ExportBlob(LKey, BLOB_ECCPRIVATE);
    LScalar := nil;
    SetLength(LScalar, X25519_KEY_SIZE);
    try
      Move(LPrivateBlob[ECC_BLOB_HEADER_SIZE + 2 * X25519_KEY_SIZE], LScalar[0],
        X25519_KEY_SIZE);
      APrivateKey := TSecretBuffer.From(LScalar);
    finally
      TSecureMemory.WipeBytes(LScalar);
      TSecureMemory.WipeBytes(LPrivateBlob);
    end;
  finally
    FApi.DestroyKey(LKey);
  end;
end;

function TWindowsCngX25519.Agree(const APrivateKey: ISecretBuffer;
  const APeerPublicKey: TBytes): ISecretBuffer;
var
  LScalar, LPrivateBlob, LPeerBlob, LSecretBytes: TBytes;
  LPrivKey, LPeerKey, LSecret: Pointer;
begin
  if System.Length(APeerPublicKey) <> X25519_KEY_SIZE then
    raise EPeerInputTlsLibException.CreateRes(@SInvalidPeerPoint);
  LScalar := APrivateKey.ToBytes;
  if System.Length(LScalar) <> X25519_KEY_SIZE then
    raise EPeerInputTlsLibException.CreateRes(@SInvalidPeerPoint);
  LPrivKey := nil;
  LPeerKey := nil;
  LSecret := nil;
  LSecretBytes := nil;
  LPrivateBlob := PrivateBlob(LScalar);
  LPeerBlob := PeerBlob(APeerPublicKey);
  try
    TCngError.Check(FApi.ImportKeyPair(FAlg, nil, PWideChar(BLOB_ECCPRIVATE), LPrivKey,
      PByte(LPrivateBlob), System.Length(LPrivateBlob), 0));
    try
      if FApi.ImportKeyPair(FAlg, nil, PWideChar(BLOB_ECCPUBLIC), LPeerKey,
        PByte(LPeerBlob), System.Length(LPeerBlob), 0) <> STATUS_SUCCESS then
        raise EPeerInputTlsLibException.CreateRes(@SInvalidPeerPoint);
      try
        if FApi.SecretAgreement(LPrivKey, LPeerKey, LSecret, 0) <> STATUS_SUCCESS then
          raise EPeerInputTlsLibException.CreateRes(@SInvalidPeerPoint);
        try
          LSecretBytes := DeriveSecret(LSecret);
          // RFC 7748 6.1: reject the all-zero (low-order-point) shared secret
          if TSecureMemory.ConstantTimeIsAllZero(LSecretBytes) then
            raise EPeerInputTlsLibException.CreateRes(@SDegenerateSharedSecret);
          Result := TSecretBuffer.From(LSecretBytes);
        finally
          FApi.DestroySecret(LSecret);
        end;
      finally
        FApi.DestroyKey(LPeerKey);
      end;
    finally
      FApi.DestroyKey(LPrivKey);
    end;
  finally
    TSecureMemory.WipeBytes(LSecretBytes);
    TSecureMemory.WipeBytes(LPrivateBlob);
    TSecureMemory.WipeBytes(LScalar);
  end;
end;

function TWindowsCngX25519.ValidatePublicKey(const APublicKey: TBytes): Boolean;
begin
  // RFC 7748: every 32-byte string is a valid u-coordinate; the low-order-point
  // rejection is deferred to Agree's all-zero shared-secret check
  Result := System.Length(APublicKey) = X25519_KEY_SIZE;
end;

function TWindowsCngX25519.ImportPrivateKey(const ARawPrivateKey: ISecretBuffer;
  out APublicKey: TBytes): ISecretBuffer;
var
  LScalar, LBasepoint: TBytes;
begin
  LScalar := ARawPrivateKey.ToBytes;
  try
    if System.Length(LScalar) <> X25519_KEY_SIZE then
      raise EArgumentTlsLibException.CreateResFmt(@SInvalidScalarSize,
        [System.Length(LScalar), X25519_KEY_SIZE]);
    // the public key is X25519(scalar, base point)
    LBasepoint := nil;
    SetLength(LBasepoint, X25519_KEY_SIZE);
    LBasepoint[0] := 9; // RFC 7748 base point u = 9
    APublicKey := Agree(ARawPrivateKey, LBasepoint).ToBytes;
    // the neutral currency is the raw scalar itself (matches GenerateKeyPair / Agree)
    Result := TSecretBuffer.From(LScalar);
  finally
    TSecureMemory.WipeBytes(LScalar);
  end;
end;

function TWindowsCngX25519.ExportPrivateKey(
  const APrivateKey: ISecretBuffer): ISecretBuffer;
begin
  // native X25519's private key is already the raw scalar
  Result := APrivateKey;
end;

{ TWindowsCngKem }

function TWindowsCngKem.Name: string;
begin
  Result := 'ML-KEM-768';
end;

function TWindowsCngKem.ExtractPublicKey(const ABlob: TBytes): TBytes;
var
  LParamSetLen, LKeyLen, LKeyOffset: ULONG;
begin
  // BCRYPT_MLKEM_KEY_BLOB: [dwMagic][cbParameterSet][cbKey] then the parameter-set name
  // then the FIPS 203 byte-encoded key; return just that key
  if System.Length(ABlob) < MLKEM_BLOB_HEADER_SIZE then
    raise ESystemCryptoBackendTlsLibException.CreateResFmt(@SCngBackendError, [0]);
  LParamSetLen := PULONG(@ABlob[4])^;
  LKeyLen := PULONG(@ABlob[8])^;
  LKeyOffset := ULONG(MLKEM_BLOB_HEADER_SIZE) + LParamSetLen;
  if ULONG(System.Length(ABlob)) < LKeyOffset + LKeyLen then
    raise ESystemCryptoBackendTlsLibException.CreateResFmt(@SCngBackendError, [0]);
  Result := nil;
  SetLength(Result, LKeyLen);
  if LKeyLen > 0 then
    Move(ABlob[LKeyOffset], Result[0], LKeyLen);
end;

function TWindowsCngKem.ImportPublic(const APeerPublicKey: TBytes): Pointer;
var
  LBlob: TBytes;
  LParamSetBytes, LKeyLen: ULONG;
begin
  // wrap the FIPS 203 encapsulation key in a public BCRYPT_MLKEM_KEY_BLOB for import
  LKeyLen := ULONG(System.Length(APeerPublicKey));
  LParamSetBytes := (ULONG(System.Length(MLKEM_768_PARAM_SET)) + 1) * SizeOf(WideChar);
  LBlob := nil;
  SetLength(LBlob, ULONG(MLKEM_BLOB_HEADER_SIZE) + LParamSetBytes + LKeyLen);
  System.FillChar(LBlob[0], System.Length(LBlob), 0);
  PULONG(@LBlob[0])^ := BCRYPT_MLKEM_PUBLIC_MAGIC;
  PULONG(@LBlob[4])^ := LParamSetBytes;
  PULONG(@LBlob[8])^ := LKeyLen;
  Move(PWideChar(MLKEM_768_PARAM_SET)^, LBlob[MLKEM_BLOB_HEADER_SIZE], LParamSetBytes);
  if LKeyLen > 0 then
    Move(APeerPublicKey[0], LBlob[ULONG(MLKEM_BLOB_HEADER_SIZE) + LParamSetBytes], LKeyLen);
  Result := nil;
  if FApi.ImportKeyPair(FAlg, nil, PWideChar(BLOB_MLKEM_PUBLIC), Result, PByte(LBlob),
    System.Length(LBlob), 0) <> STATUS_SUCCESS then
    raise EPeerInputTlsLibException.CreateRes(@SInvalidPeerPoint);
end;

function TWindowsCngKem.ImportPrivate(const APrivateBlob: TBytes): Pointer;
begin
  Result := nil;
  TCngError.Check(FApi.ImportKeyPair(FAlg, nil, PWideChar(BLOB_MLKEM_PRIVATE), Result,
    PByte(APrivateBlob), System.Length(APrivateBlob), 0));
end;

procedure TWindowsCngKem.GenerateKeyPair(out APrivateKey: ISecretBuffer;
  out APublicKey: TBytes);
var
  LKey: Pointer;
  LPublicBlob, LPrivateBlob: TBytes;
begin
  LKey := nil;
  TCngError.Check(FApi.GenerateKeyPair(FAlg, LKey, 0, 0));
  try
    TCngError.Check(FApi.SetProperty(LKey, PWideChar(BCRYPT_PARAMETER_SET_NAME_PROP),
      PByte(PWideChar(MLKEM_768_PARAM_SET)),
      (System.Length(MLKEM_768_PARAM_SET) + 1) * SizeOf(WideChar), 0));
    TCngError.Check(FApi.FinalizeKeyPair(LKey, 0));
    LPublicBlob := ExportBlob(LKey, BLOB_MLKEM_PUBLIC);
    APublicKey := ExtractPublicKey(LPublicBlob);
    // the decapsulation blob carries the secret key; held wipeably and re-imported per op
    LPrivateBlob := ExportBlob(LKey, BLOB_MLKEM_PRIVATE);
    try
      APrivateKey := TSecretBuffer.From(LPrivateBlob);
    finally
      TSecureMemory.WipeBytes(LPrivateBlob);
    end;
  finally
    FApi.DestroyKey(LKey);
  end;
end;

procedure TWindowsCngKem.Encapsulate(const APeerPublicKey: TBytes;
  out ACiphertext: TBytes; out ASharedSecret: ISecretBuffer);
var
  LPeerKey: Pointer;
  LSecret: TBytes;
  LCtLen, LSecretLen: ULONG;
begin
  LPeerKey := ImportPublic(APeerPublicKey);
  LSecret := nil;
  try
    ACiphertext := nil;
    SetLength(ACiphertext, MLKEM768_CIPHERTEXT_SIZE);
    SetLength(LSecret, MLKEM768_SHARED_SECRET_SIZE);
    LCtLen := 0;
    LSecretLen := 0;
    TCngError.Check(FApi.Encapsulate(LPeerKey, PByte(LSecret),
      ULONG(System.Length(LSecret)), LSecretLen, PByte(ACiphertext),
      ULONG(System.Length(ACiphertext)), LCtLen, 0));
    SetLength(ACiphertext, LCtLen);
    SetLength(LSecret, LSecretLen);
    ASharedSecret := TSecretBuffer.From(LSecret);
  finally
    TSecureMemory.WipeBytes(LSecret);
    FApi.DestroyKey(LPeerKey);
  end;
end;

procedure TWindowsCngKem.Decapsulate(const APrivateKey: ISecretBuffer;
  const ACiphertext: TBytes; out ASharedSecret: ISecretBuffer);
var
  LPrivateBlob, LSecret: TBytes;
  LPrivKey: Pointer;
  LSecretLen: ULONG;
begin
  LPrivateBlob := APrivateKey.ToBytes;
  LSecret := nil;
  try
    LPrivKey := ImportPrivate(LPrivateBlob);
    try
      SetLength(LSecret, MLKEM768_SHARED_SECRET_SIZE);
      LSecretLen := 0;
      if FApi.Decapsulate(LPrivKey, PByte(ACiphertext),
        ULONG(System.Length(ACiphertext)), PByte(LSecret),
        ULONG(System.Length(LSecret)), LSecretLen, 0) <> STATUS_SUCCESS then
        raise EPeerInputTlsLibException.CreateRes(@SInvalidPeerPoint);
      SetLength(LSecret, LSecretLen);
      ASharedSecret := TSecretBuffer.From(LSecret);
    finally
      FApi.DestroyKey(LPrivKey);
    end;
  finally
    TSecureMemory.WipeBytes(LSecret);
    TSecureMemory.WipeBytes(LPrivateBlob);
  end;
end;

function TWindowsCngKem.ValidatePublicKey(const APublicKey: TBytes): Boolean;
begin
  // the byte-encoded ML-KEM-768 encapsulation key is a fixed length; the modulus-bound
  // coefficient check is left to CNG on import during Encapsulate
  Result := System.Length(APublicKey) = MLKEM768_PUBLIC_KEY_SIZE;
end;

{ TWindowsCng }

class function TWindowsCng.LoadApi(out AModule: THandle;
  out AApi: TCngApi): Boolean;
begin
  Result := False;
  System.FillChar(AApi, SizeOf(AApi), 0);
  AModule := SafeLoadLibrary(BCRYPT_DLL, SEM_FAILCRITICALERRORS);
  if AModule = 0 then
    Exit;
  AApi.OpenAlgorithmProvider := TBCryptOpenAlgorithmProvider(
    TModuleApi.Proc(AModule, 'BCryptOpenAlgorithmProvider'));
  AApi.CloseAlgorithmProvider := TBCryptCloseAlgorithmProvider(
    TModuleApi.Proc(AModule, 'BCryptCloseAlgorithmProvider'));
  AApi.GenerateKeyPair := TBCryptGenerateKeyPair(
    TModuleApi.Proc(AModule, 'BCryptGenerateKeyPair'));
  AApi.FinalizeKeyPair := TBCryptFinalizeKeyPair(
    TModuleApi.Proc(AModule, 'BCryptFinalizeKeyPair'));
  AApi.ExportKey := TBCryptExportKey(TModuleApi.Proc(AModule, 'BCryptExportKey'));
  AApi.ImportKeyPair := TBCryptImportKeyPair(
    TModuleApi.Proc(AModule, 'BCryptImportKeyPair'));
  AApi.DestroyKey := TBCryptDestroyKey(TModuleApi.Proc(AModule, 'BCryptDestroyKey'));
  AApi.SecretAgreement := TBCryptSecretAgreement(
    TModuleApi.Proc(AModule, 'BCryptSecretAgreement'));
  AApi.DeriveKey := TBCryptDeriveKey(TModuleApi.Proc(AModule, 'BCryptDeriveKey'));
  AApi.DestroySecret := TBCryptDestroySecret(
    TModuleApi.Proc(AModule, 'BCryptDestroySecret'));
  AApi.GenRandom := TBCryptGenRandom(TModuleApi.Proc(AModule, 'BCryptGenRandom'));
  AApi.CreateHash := TBCryptCreateHash(TModuleApi.Proc(AModule, 'BCryptCreateHash'));
  AApi.HashData := TBCryptHashData(TModuleApi.Proc(AModule, 'BCryptHashData'));
  AApi.FinishHash := TBCryptFinishHash(TModuleApi.Proc(AModule, 'BCryptFinishHash'));
  AApi.DuplicateHash := TBCryptDuplicateHash(TModuleApi.Proc(AModule, 'BCryptDuplicateHash'));
  AApi.DestroyHash := TBCryptDestroyHash(TModuleApi.Proc(AModule, 'BCryptDestroyHash'));
  AApi.SetProperty := TBCryptSetProperty(TModuleApi.Proc(AModule, 'BCryptSetProperty'));
  AApi.GenerateSymmetricKey := TBCryptGenerateSymmetricKey(
    TModuleApi.Proc(AModule, 'BCryptGenerateSymmetricKey'));
  AApi.Encrypt := TBCryptEncrypt(TModuleApi.Proc(AModule, 'BCryptEncrypt'));
  AApi.Decrypt := TBCryptDecrypt(TModuleApi.Proc(AModule, 'BCryptDecrypt'));
  // optional (Win11 24H2+); intentionally excluded from the readiness gate below
  AApi.Encapsulate := TBCryptEncapsulate(TModuleApi.Proc(AModule, 'BCryptEncapsulate'));
  AApi.Decapsulate := TBCryptDecapsulate(TModuleApi.Proc(AModule, 'BCryptDecapsulate'));
  AApi.VerifySignature := TBCryptVerifySignature(
    TModuleApi.Proc(AModule, 'BCryptVerifySignature'));
  AApi.GetProperty := TBCryptGetProperty(TModuleApi.Proc(AModule, 'BCryptGetProperty'));
  AApi.KeyDerivation := TBCryptKeyDerivation(TModuleApi.Proc(AModule, 'BCryptKeyDerivation'));

  // the only universal requirement: opening and closing algorithm handles. Every feature
  // entry point is optional and gated per-facet at construction, so a stripped or older
  // bcrypt still yields whatever it can and falls back for the rest.
  Result := System.Assigned(AApi.OpenAlgorithmProvider) and
    System.Assigned(AApi.CloseAlgorithmProvider);

  if not Result then
  begin
    FreeLibrary(AModule);
    AModule := 0;
  end;
end;

class function TWindowsCng.Curve(AAlgorithm: TKeyAgreementAlgorithm): TCngCurve;
begin
  case AAlgorithm of
    TKeyAgreementAlgorithm.SECP256R1:
      begin
        Result.Name := 'secp256r1';
        Result.KeyBits := 256;
        Result.FieldSize := 32;
        Result.PubMagic := BCRYPT_ECDH_PUBLIC_P256_MAGIC;
        Result.PrivMagic := BCRYPT_ECDH_PRIVATE_P256_MAGIC;
      end;
    TKeyAgreementAlgorithm.SECP384R1:
      begin
        Result.Name := 'secp384r1';
        Result.KeyBits := 384;
        Result.FieldSize := 48;
        Result.PubMagic := BCRYPT_ECDH_PUBLIC_P384_MAGIC;
        Result.PrivMagic := BCRYPT_ECDH_PRIVATE_P384_MAGIC;
      end;
  else
    // SECP521R1
    Result.Name := 'secp521r1';
    Result.KeyBits := 521;
    Result.FieldSize := 66;
    Result.PubMagic := BCRYPT_ECDH_PUBLIC_P521_MAGIC;
    Result.PrivMagic := BCRYPT_ECDH_PRIVATE_P521_MAGIC;
  end;
end;

function TWindowsCng.TryOpenAlg(const AAlgId: WideString; AFlags: ULONG): Pointer;
begin
  // an algorithm CNG cannot open is not fatal: nil leaves it to fall back per-algorithm
  Result := nil;
  if FApi.OpenAlgorithmProvider(Result, PWideChar(AAlgId), nil, AFlags) <> STATUS_SUCCESS then
    Result := nil;
end;

function TWindowsCng.OpenAesGcm: Pointer;
begin
  // AES with the GCM chaining mode set on the provider; keys inherit it. If GCM cannot be
  // set (very old CNG) the handle is dropped and AES-GCM falls back to the portable facet.
  Result := TryOpenAlg('AES');
  if (Result <> nil) and
    (FApi.SetProperty(Result, PWideChar(BCRYPT_CHAINING_MODE_PROP),
    PByte(PWideChar(BCRYPT_CHAIN_MODE_GCM_VAL)),
    (System.Length(BCRYPT_CHAIN_MODE_GCM_VAL) + 1) * SizeOf(WideChar), 0)
    <> STATUS_SUCCESS) then
  begin
    FApi.CloseAlgorithmProvider(Result, 0);
    Result := nil;
  end;
end;

function TWindowsCng.OpenX25519: Pointer;
begin
  // generic ECDH with the curve name set to curve25519 (Windows 10+). If the curve name
  // is not settable (older Windows) the handle is dropped and X25519 falls back.
  Result := TryOpenAlg('ECDH');
  if (Result <> nil) and
    (FApi.SetProperty(Result, PWideChar(BCRYPT_ECC_CURVE_NAME_PROP),
    PByte(PWideChar(CURVE25519_NAME)),
    (System.Length(CURVE25519_NAME) + 1) * SizeOf(WideChar), 0) <> STATUS_SUCCESS) then
  begin
    FApi.CloseAlgorithmProvider(Result, 0);
    Result := nil;
  end;
end;

function TWindowsCng.ProbeRandom: Boolean;
var
  LProbe: array [0 .. 7] of Byte;
begin
  // BCryptGenRandom with the system-preferred flag needs no algorithm handle; a live test
  // call is the probe (Vista SP2+/2008+, so it succeeds wherever bcrypt itself loaded)
  Result := System.Assigned(FApi.GenRandom) and
    (FApi.GenRandom(nil, @LProbe[0], System.Length(LProbe),
    BCRYPT_USE_SYSTEM_PREFERRED_RNG) = STATUS_SUCCESS);
end;

constructor TWindowsCng.Create;
var
  LHashCore, LHashClone, LAgree, LAead, LKem: Boolean;
begin
  inherited Create;
  // only the module load (plus the universal open/close handle calls, checked in LoadApi)
  // is a hard requirement; every entry point past that is optional. Each facet opens only
  // when the specific calls it needs are present, so a Windows that lacks a newer entry
  // point loses just that facet - never the whole context, and never a crash.
  if not LoadApi(FModule, FApi) then
    raise ESystemCryptoUnsupportedTlsLibException.CreateRes(@SCngUnavailable);
  LHashCore := System.Assigned(FApi.CreateHash) and System.Assigned(FApi.HashData) and
    System.Assigned(FApi.FinishHash) and System.Assigned(FApi.DestroyHash);
  LHashClone := LHashCore and System.Assigned(FApi.DuplicateHash);
  LAgree := System.Assigned(FApi.GenerateKeyPair) and
    System.Assigned(FApi.FinalizeKeyPair) and System.Assigned(FApi.ExportKey) and
    System.Assigned(FApi.ImportKeyPair) and System.Assigned(FApi.DestroyKey) and
    System.Assigned(FApi.SecretAgreement) and System.Assigned(FApi.DeriveKey) and
    System.Assigned(FApi.DestroySecret) and System.Assigned(FApi.SetProperty);
  LAead := System.Assigned(FApi.GenerateSymmetricKey) and
    System.Assigned(FApi.Encrypt) and System.Assigned(FApi.Decrypt) and
    System.Assigned(FApi.DestroyKey) and System.Assigned(FApi.SetProperty);
  LKem := System.Assigned(FApi.GenerateKeyPair) and
    System.Assigned(FApi.FinalizeKeyPair) and System.Assigned(FApi.ExportKey) and
    System.Assigned(FApi.ImportKeyPair) and System.Assigned(FApi.DestroyKey) and
    System.Assigned(FApi.SetProperty) and System.Assigned(FApi.Encapsulate) and
    System.Assigned(FApi.Decapsulate);
  if LHashClone then // the vended hash exposes Clone (BCryptDuplicateHash)
  begin
    FHashSha256 := TryOpenAlg('SHA256');
    FHashSha384 := TryOpenAlg('SHA384');
    FHashSha512 := TryOpenAlg('SHA512');
  end;
  if LHashCore then
  begin
    FHmacSha256 := TryOpenAlg('SHA256', BCRYPT_ALG_HANDLE_HMAC_FLAG);
    FHmacSha384 := TryOpenAlg('SHA384', BCRYPT_ALG_HANDLE_HMAC_FLAG);
    FHmacSha512 := TryOpenAlg('SHA512', BCRYPT_ALG_HANDLE_HMAC_FLAG);
  end;
  if LAgree then
  begin
    FAlgP256 := TryOpenAlg('ECDH_P256');
    FAlgP384 := TryOpenAlg('ECDH_P384');
    FAlgP521 := TryOpenAlg('ECDH_P521');
    FX25519 := OpenX25519;
  end;
  if LAead then
  begin
    FAesGcm := OpenAesGcm;
    FChaCha := TryOpenAlg('CHACHA20_POLY1305');
  end;
  if LKem then
    FMlKem := TryOpenAlg(MLKEM_ALG_NAME);
  FRandomOk := ProbeRandom;
  // in-module HKDF-Expand needs the derive entry point + a symmetric key + property support
  if System.Assigned(FApi.KeyDerivation) and System.Assigned(FApi.GenerateSymmetricKey) and
    System.Assigned(FApi.SetProperty) and System.Assigned(FApi.DestroyKey) then
    FHkdfAlg := TryOpenAlg(BCRYPT_HKDF_ALG);
end;

destructor TWindowsCng.Destroy;
  procedure CloseAlg(AHandle: Pointer);
  begin
    if AHandle <> nil then
      FApi.CloseAlgorithmProvider(AHandle, 0);
  end;

begin
  if System.Assigned(FApi.CloseAlgorithmProvider) then
  begin
    CloseAlg(FHkdfAlg);
    CloseAlg(FMlKem);
    CloseAlg(FX25519);
    CloseAlg(FChaCha);
    CloseAlg(FAesGcm);
    CloseAlg(FHmacSha512);
    CloseAlg(FHmacSha384);
    CloseAlg(FHmacSha256);
    CloseAlg(FHashSha512);
    CloseAlg(FHashSha384);
    CloseAlg(FHashSha256);
    CloseAlg(FAlgP521);
    CloseAlg(FAlgP384);
    CloseAlg(FAlgP256);
  end;
  if FModule <> 0 then
    FreeLibrary(FModule);
  inherited Destroy;
end;

function TWindowsCng.TryCreateAgreement(AAlgorithm: TKeyAgreementAlgorithm;
  out AAgreement: IKeyAgreement): Boolean;
var
  LAlg: Pointer;
begin
  if (AAlgorithm = TKeyAgreementAlgorithm.X25519) and (FX25519 <> nil) then
  begin
    AAgreement := TWindowsCngX25519.Create(FApi, FX25519, Self as IWindowsCng);
    Exit(True);
  end;
  case AAlgorithm of
    TKeyAgreementAlgorithm.SECP256R1:
      LAlg := FAlgP256;
    TKeyAgreementAlgorithm.SECP384R1:
      LAlg := FAlgP384;
    TKeyAgreementAlgorithm.SECP521R1:
      LAlg := FAlgP521;
  else
    LAlg := nil;
  end;
  // a curve CNG could not open (or X25519 when the curve name is not settable) falls back
  // to the portable facet
  if LAlg = nil then
  begin
    AAgreement := nil;
    Exit(False);
  end;
  AAgreement := TWindowsCngKeyAgreement.Create(FApi, LAlg, Curve(AAlgorithm),
    Self as IWindowsCng);
  Result := True;
end;

function TWindowsCng.Available(AAlgorithm: TKeyAgreementAlgorithm): Boolean;
begin
  case AAlgorithm of
    TKeyAgreementAlgorithm.SECP256R1:
      Result := FAlgP256 <> nil;
    TKeyAgreementAlgorithm.SECP384R1:
      Result := FAlgP384 <> nil;
    TKeyAgreementAlgorithm.SECP521R1:
      Result := FAlgP521 <> nil;
    TKeyAgreementAlgorithm.X25519:
      Result := FX25519 <> nil;
  else
    Result := False;
  end;
end;

function TWindowsCng.Random: IRandom;
begin
  Result := TWindowsCngRandom.Create(FApi, Self as IWindowsCng);
end;

function TWindowsCng.RandomAvailable: Boolean;
begin
  Result := FRandomOk;
end;

function TWindowsCng.TryCreateHash(AAlgorithm: THashAlgorithm;
  out AHash: IHash): Boolean;
var
  LAlg: Pointer;
  LName: string;
  LHashSize, LBlockSize: Int32;
begin
  case AAlgorithm of
    THashAlgorithm.SHA_256:
      begin
        LAlg := FHashSha256;
        LName := 'SHA-256';
        LHashSize := 32;
        LBlockSize := 64;
      end;
    THashAlgorithm.SHA_384:
      begin
        LAlg := FHashSha384;
        LName := 'SHA-384';
        LHashSize := 48;
        LBlockSize := 128;
      end;
    THashAlgorithm.SHA_512:
      begin
        LAlg := FHashSha512;
        LName := 'SHA-512';
        LHashSize := 64;
        LBlockSize := 128;
      end;
  else
    LAlg := nil;
    LName := '';
    LHashSize := 0;
    LBlockSize := 0;
  end;
  if LAlg = nil then
  begin
    AHash := nil;
    Exit(False);
  end;
  AHash := TWindowsCngHash.Create(FApi, LAlg, LName, LHashSize, LBlockSize,
    Self as IWindowsCng);
  Result := True;
end;

function TWindowsCng.HashAvailable(AAlgorithm: THashAlgorithm): Boolean;
begin
  case AAlgorithm of
    THashAlgorithm.SHA_256:
      Result := FHashSha256 <> nil;
    THashAlgorithm.SHA_384:
      Result := FHashSha384 <> nil;
    THashAlgorithm.SHA_512:
      Result := FHashSha512 <> nil;
  else
    Result := False;
  end;
end;

function TWindowsCng.TryCreateHmac(AAlgorithm: THashAlgorithm;
  out AHmac: IHmac): Boolean;
var
  LAlg: Pointer;
  LName: string;
  LMacSize: Int32;
begin
  case AAlgorithm of
    THashAlgorithm.SHA_256:
      begin
        LAlg := FHmacSha256;
        LName := 'HMAC-SHA-256';
        LMacSize := 32;
      end;
    THashAlgorithm.SHA_384:
      begin
        LAlg := FHmacSha384;
        LName := 'HMAC-SHA-384';
        LMacSize := 48;
      end;
    THashAlgorithm.SHA_512:
      begin
        LAlg := FHmacSha512;
        LName := 'HMAC-SHA-512';
        LMacSize := 64;
      end;
  else
    LAlg := nil;
    LName := '';
    LMacSize := 0;
  end;
  if LAlg = nil then
  begin
    AHmac := nil;
    Exit(False);
  end;
  AHmac := TWindowsCngHmac.Create(FApi, LAlg, LName, LMacSize, Self as IWindowsCng);
  Result := True;
end;

function TWindowsCng.HmacAvailable(AAlgorithm: THashAlgorithm): Boolean;
begin
  case AAlgorithm of
    THashAlgorithm.SHA_256:
      Result := FHmacSha256 <> nil;
    THashAlgorithm.SHA_384:
      Result := FHmacSha384 <> nil;
    THashAlgorithm.SHA_512:
      Result := FHmacSha512 <> nil;
  else
    Result := False;
  end;
end;

function TWindowsCng.DoNativeHkdfExpand(const AHashName: WideString;
  const APrk, AInfo: TBytes; ALength: Int32; out AOkm: TBytes): Boolean;
var
  LKey: Pointer;
  LResult: ULONG;
  LHash: WideString;
  LOkm: TBytes;
  LBuf: TNCryptBuffer;
  LDesc: TNCryptBufferDesc;
  LParams: Pointer;
begin
  Result := False;
  AOkm := nil;
  if FApi.GenerateSymmetricKey(FHkdfAlg, LKey, nil, 0, PByte(APrk),
    ULONG(System.Length(APrk)), 0) <> 0 then
    Exit;
  LOkm := nil;
  LHash := AHashName; // keep the wide string alive for the property call
  try
    if FApi.SetProperty(LKey, PWideChar(BCRYPT_HKDF_HASH_NAME),
      PByte(PWideChar(LHash)), ULONG((System.Length(LHash) + 1) * SizeOf(WideChar)),
      0) <> 0 then
      Exit;
    // the key material is the PRK, so finalize (Expand) without the extract step
    if FApi.SetProperty(LKey, PWideChar(BCRYPT_HKDF_PRK_AND_FINALIZE), nil, 0, 0) <> 0 then
      Exit;
    // the info travels in the derive parameter list as one KDF_HKDF_INFO buffer
    LParams := nil;
    if System.Length(AInfo) > 0 then
    begin
      LBuf.cbBuffer := ULONG(System.Length(AInfo));
      LBuf.BufferType := KDF_HKDF_INFO;
      LBuf.pvBuffer := @AInfo[0];
      LDesc.ulVersion := BCRYPTBUFFER_VERSION;
      LDesc.cBuffers := 1;
      LDesc.pBuffers := @LBuf;
      LParams := @LDesc;
    end;
    SetLength(LOkm, ALength);
    if FApi.KeyDerivation(LKey, LParams, PByte(LOkm), ULONG(ALength), LResult, 0) <> 0 then
      Exit;
    if LResult <> ULONG(ALength) then
      Exit;
    AOkm := LOkm;
    LOkm := nil;
    Result := True;
  finally
    if LOkm <> nil then
      TSecureMemory.WipeBytes(LOkm);
    FApi.DestroyKey(LKey);
  end;
end;

function TWindowsCng.TryHkdfExpandNative(AAlgorithm: THashAlgorithm;
  const APrk, AInfo: TBytes; ALength: Int32; out AOkm: TBytes): Boolean;
var
  LName: WideString;
begin
  Result := False;
  AOkm := nil;
  if (FHkdfAlg = nil) or (ALength <= 0) then
    Exit;
  case AAlgorithm of
    THashAlgorithm.SHA_256:
      LName := HASH_ALG_SHA256;
    THashAlgorithm.SHA_384:
      LName := HASH_ALG_SHA384;
    THashAlgorithm.SHA_512:
      LName := HASH_ALG_SHA512;
  else
    Exit;
  end;
  Result := DoNativeHkdfExpand(LName, APrk, AInfo, ALength, AOkm);
end;

function TWindowsCng.TryCreateAead(AAlgorithm: TAeadAlgorithm;
  out AAead: IAead): Boolean;
var
  LAlg: Pointer;
  LCategory: TAeadUsageCategory;
  LName: string;
  LKeySize: Int32;
begin
  case AAlgorithm of
    TAeadAlgorithm.AES_128_GCM:
      begin
        LAlg := FAesGcm;
        LCategory := TAeadUsageCategory.AesGcm;
        LName := 'AES-128-GCM';
        LKeySize := 16;
      end;
    TAeadAlgorithm.AES_256_GCM:
      begin
        LAlg := FAesGcm;
        LCategory := TAeadUsageCategory.AesGcm;
        LName := 'AES-256-GCM';
        LKeySize := 32;
      end;
    TAeadAlgorithm.CHACHA20_POLY1305:
      begin
        LAlg := FChaCha;
        LCategory := TAeadUsageCategory.ChaCha20;
        LName := 'ChaCha20-Poly1305';
        LKeySize := 32;
      end;
  else
    LAlg := nil;
    LCategory := TAeadUsageCategory.AesGcm;
    LName := '';
    LKeySize := 0;
  end;
  if LAlg = nil then
  begin
    AAead := nil;
    Exit(False);
  end;
  AAead := TWindowsCngAead.Create(FApi, LAlg, LCategory, LName, LKeySize, 12, 16,
    Self as IWindowsCng);
  Result := True;
end;

function TWindowsCng.AeadAvailable(AAlgorithm: TAeadAlgorithm): Boolean;
begin
  case AAlgorithm of
    TAeadAlgorithm.AES_128_GCM, TAeadAlgorithm.AES_256_GCM:
      Result := FAesGcm <> nil;
    TAeadAlgorithm.CHACHA20_POLY1305:
      Result := FChaCha <> nil;
  else
    Result := False;
  end;
end;

function TWindowsCng.TryCreateKem(AAlgorithm: TKemAlgorithm;
  out AKem: IKem): Boolean;
begin
  if (AAlgorithm = TKemAlgorithm.ML_KEM_768) and (FMlKem <> nil) then
  begin
    AKem := TWindowsCngKem.Create(FApi, FMlKem, Self as IWindowsCng);
    Exit(True);
  end;
  AKem := nil;
  Result := False;
end;

function TWindowsCng.KemAvailable(AAlgorithm: TKemAlgorithm): Boolean;
begin
  Result := (AAlgorithm = TKemAlgorithm.ML_KEM_768) and (FMlKem <> nil);
end;

function TWindowsCng.BcryptApi: TCngApi;
begin
  Result := FApi;
end;

{ TWindowsCryptoPrimitives }

constructor TWindowsCryptoPrimitives.Create(const AInner: ICryptoPrimitives;
  const ACng: IWindowsCng);
begin
  inherited Create(AInner);
  FCng := ACng;
end;

function TWindowsCryptoPrimitives.GetRandom: IRandom;
begin
  if FCng.RandomAvailable then
    Result := FCng.Random
  else
    Result := inherited GetRandom;
end;

function TWindowsCryptoPrimitives.CreateHash(AAlgorithm: THashAlgorithm): IHash;
begin
  if not FCng.TryCreateHash(AAlgorithm, Result) then
    Result := inherited CreateHash(AAlgorithm);
end;

function TWindowsCryptoPrimitives.CreateHmac(AAlgorithm: THashAlgorithm): IHmac;
begin
  if not FCng.TryCreateHmac(AAlgorithm, Result) then
    Result := inherited CreateHmac(AAlgorithm);
end;

function TWindowsCryptoPrimitives.CreateHkdf(AAlgorithm: THashAlgorithm): IHkdf;
var
  LMacSize: Int32;
begin
  if FCng.HmacAvailable(AAlgorithm) then
  begin
    case AAlgorithm of
      THashAlgorithm.SHA_256:
        LMacSize := 32;
      THashAlgorithm.SHA_384:
        LMacSize := 48;
      THashAlgorithm.SHA_512:
        LMacSize := 64;
    else
      LMacSize := 0;
    end;
    Result := TWindowsCngHkdf.Create(FCng, AAlgorithm, LMacSize);
  end
  else
    Result := inherited CreateHkdf(AAlgorithm);
end;

function TWindowsCryptoPrimitives.CreateTls12Prf(
  AAlgorithm: THashAlgorithm): ITls12Prf;
begin
  if FCng.HmacAvailable(AAlgorithm) then
    Result := TTls12PrfComposition.Create(Self, AAlgorithm) as ITls12Prf
  else
    Result := inherited CreateTls12Prf(AAlgorithm);
end;

function TWindowsCryptoPrimitives.CreateAead(AAlgorithm: TAeadAlgorithm): IAead;
begin
  if not FCng.TryCreateAead(AAlgorithm, Result) then
    Result := inherited CreateAead(AAlgorithm);
end;

function TWindowsCryptoPrimitives.CreateKeyAgreement(
  AAlgorithm: TKeyAgreementAlgorithm): IKeyAgreement;
begin
  if not FCng.TryCreateAgreement(AAlgorithm, Result) then
    Result := inherited CreateKeyAgreement(AAlgorithm);
end;

function TWindowsCryptoPrimitives.CreateKem(AAlgorithm: TKemAlgorithm): IKem;
begin
  if not FCng.TryCreateKem(AAlgorithm, Result) then
    Result := inherited CreateKem(AAlgorithm);
end;

{ TWindowsBackendReport }

constructor TWindowsBackendReport.Create(const ACng: IWindowsCng;
  ASigningNative: Boolean);
begin
  inherited Create;
  FCng := ACng;
  FSigningNative := ASigningNative;
end;

class function TWindowsBackendReport.Ent(ABackend: TCryptoBackend;
  AReason: TCryptoBackendReason): TCryptoBackendEntry;
begin
  Result.Backend := ABackend;
  Result.Reason := AReason;
end;

class function TWindowsBackendReport.NotNative: TCryptoBackendEntry;
begin
  Result := Ent(TCryptoBackend.Portable, TCryptoBackendReason.NoNativeImpl);
end;

function TWindowsBackendReport.RandomBackend: TCryptoBackendEntry;
begin
  if FCng.RandomAvailable then
    Result := Ent(TCryptoBackend.System, TCryptoBackendReason.NotFallback)
  else
    Result := NotNative;
end;

function TWindowsBackendReport.HashBackend(
  AAlgorithm: THashAlgorithm): TCryptoBackendEntry;
begin
  if FCng.HashAvailable(AAlgorithm) then
    Result := Ent(TCryptoBackend.System, TCryptoBackendReason.NotFallback)
  else
    Result := NotNative;
end;

function TWindowsBackendReport.HmacBackend(
  AAlgorithm: THashAlgorithm): TCryptoBackendEntry;
begin
  if FCng.HmacAvailable(AAlgorithm) then
    Result := Ent(TCryptoBackend.System, TCryptoBackendReason.NotFallback)
  else
    Result := NotNative;
end;

function TWindowsBackendReport.HkdfBackend(
  AAlgorithm: THashAlgorithm): TCryptoBackendEntry;
begin
  // HKDF is assembled over the CNG HMAC: the secret passes through CNG, the loop is portable
  if FCng.HmacAvailable(AAlgorithm) then
    Result := Ent(TCryptoBackend.Composed, TCryptoBackendReason.NotFallback)
  else
    Result := NotNative;
end;

function TWindowsBackendReport.Tls12PrfBackend(
  AAlgorithm: THashAlgorithm): TCryptoBackendEntry;
begin
  // the 1.2 PRF is P_hash assembled over the CNG HMAC: the secret passes through CNG
  if FCng.HmacAvailable(AAlgorithm) then
    Result := Ent(TCryptoBackend.Composed, TCryptoBackendReason.NotFallback)
  else
    Result := NotNative;
end;

function TWindowsBackendReport.AeadBackend(
  AAlgorithm: TAeadAlgorithm): TCryptoBackendEntry;
begin
  if FCng.AeadAvailable(AAlgorithm) then
    Result := Ent(TCryptoBackend.System, TCryptoBackendReason.NotFallback)
  else
    // e.g. ChaCha20-Poly1305 before Windows 11
    Result := Ent(TCryptoBackend.Portable, TCryptoBackendReason.NotPresent);
end;

function TWindowsBackendReport.KeyAgreementBackend(
  AAlgorithm: TKeyAgreementAlgorithm): TCryptoBackendEntry;
begin
  case AAlgorithm of
    TKeyAgreementAlgorithm.SECP256R1,
    TKeyAgreementAlgorithm.SECP384R1,
    TKeyAgreementAlgorithm.SECP521R1,
    TKeyAgreementAlgorithm.X25519:
      if FCng.Available(AAlgorithm) then
        Result := Ent(TCryptoBackend.System, TCryptoBackendReason.NotFallback)
      else
        // CNG could not open the curve on this host (e.g. curve25519 before Windows 10)
        Result := Ent(TCryptoBackend.Portable, TCryptoBackendReason.NotPresent);
  else
    Result := NotNative;
  end;
end;

function TWindowsBackendReport.KemBackend(
  AAlgorithm: TKemAlgorithm): TCryptoBackendEntry;
begin
  if FCng.KemAvailable(AAlgorithm) then
    Result := Ent(TCryptoBackend.System, TCryptoBackendReason.NotFallback)
  else
    // ML-KEM needs Windows 11 24H2 or later
    Result := Ent(TCryptoBackend.Portable, TCryptoBackendReason.NotPresent);
end;

function TWindowsBackendReport.SigningBackend(
  AScheme: TSignatureScheme): TCryptoBackendEntry;
begin
  // native signing covers RSA-PSS/PKCS1 and NIST-curve ECDSA (via NCrypt); EdDSA is portable
  if FSigningNative and TWindowsNCrypt.IsNativeScheme(AScheme) then
    Result := Ent(TCryptoBackend.System, TCryptoBackendReason.NotFallback)
  else
    Result := NotNative;
end;

function TWindowsBackendReport.SigningKeyBackend(
  const AKey: ISigningKey): TCryptoBackendEntry;
begin
  // per key, not per scheme: only a key this backend natively imported carries the marker;
  // one that fell back to the portable facet signs portable regardless of its scheme
  if Supports(AKey, IWindowsSigningKey) then
    Result := Ent(TCryptoBackend.System, TCryptoBackendReason.NotFallback)
  else
    Result := NotNative;
end;

function TWindowsBackendReport.FacetBackend(
  AFacet: TCryptoFacet): TCryptoBackendEntry;
begin
  // Hpke composes over this overlay's native primitives, so it is Composed; the other higher
  // facets forward to the portable base.
  if AFacet = TCryptoFacet.Hpke then
    Result := Ent(TCryptoBackend.Composed, TCryptoBackendReason.NotFallback)
  else
    Result := NotNative;
end;

function TWindowsBackendReport.Describe: string;
var
  LNative: string;

  procedure Add(const AItem: string);
  begin
    if AItem = '' then
      Exit;
    if LNative = '' then
      LNative := AItem
    else
      LNative := LNative + ', ' + AItem;
  end;

  function Hashes: string;
  begin
    Result := '';
    if FCng.HashAvailable(THashAlgorithm.SHA_256) then
      Result := Result + ' SHA-256';
    if FCng.HashAvailable(THashAlgorithm.SHA_384) then
      Result := Result + ' SHA-384';
    if FCng.HashAvailable(THashAlgorithm.SHA_512) then
      Result := Result + ' SHA-512';
    if Result <> '' then
      Result := 'hash' + Result;
  end;

  function Aeads: string;
  begin
    Result := '';
    if FCng.AeadAvailable(TAeadAlgorithm.AES_128_GCM) then
      Result := Result + ' AES-GCM';
    if FCng.AeadAvailable(TAeadAlgorithm.CHACHA20_POLY1305) then
      Result := Result + ' ChaCha20-Poly1305';
    if Result <> '' then
      Result := 'AEAD' + Result;
  end;

  function Curves: string;
  begin
    Result := '';
    if FCng.Available(TKeyAgreementAlgorithm.SECP256R1) then
      Result := Result + ' secp256r1';
    if FCng.Available(TKeyAgreementAlgorithm.SECP384R1) then
      Result := Result + ' secp384r1';
    if FCng.Available(TKeyAgreementAlgorithm.SECP521R1) then
      Result := Result + ' secp521r1';
    if FCng.Available(TKeyAgreementAlgorithm.X25519) then
      Result := Result + ' x25519';
    if Result <> '' then
      Result := 'ECDH' + Result;
  end;

  function Kems: string;
  begin
    Result := '';
    if FCng.KemAvailable(TKemAlgorithm.ML_KEM_768) then
      Result := 'KEM ML-KEM-768';
  end;

  function Signings: string;
  begin
    if FSigningNative then
      Result := 'sign RSA ECDSA'
    else
      Result := '';
  end;

begin
  LNative := '';
  if FCng.RandomAvailable then
    Add('DRBG');
  Add(Hashes);
  Add(Aeads);
  Add(Curves);
  Add(Kems);
  Add(Signings);
  if LNative = '' then
    Result := 'system crypto (CNG): none; all operations portable'
  else
    Result := 'system crypto (CNG): ' + LNative + '; all else portable';
end;

{ TNCryptKeyOwner }

constructor TNCryptKeyOwner.Create(const AKeeper: IWindowsNCrypt;
  AHandle: NativeUInt);
begin
  inherited Create;
  FKeeper := AKeeper;
  FHandle := AHandle;
end;

destructor TNCryptKeyOwner.Destroy;
begin
  if FHandle <> 0 then
    FKeeper.FreeKey(FHandle);
  inherited Destroy;
end;

function TNCryptKeyOwner.Handle: NativeUInt;
begin
  Result := FHandle;
end;

{ TPfxKeyOwner }

constructor TPfxKeyOwner.Create(const AKeeper: IWindowsNCrypt; AStore, ACert: Pointer;
  AHandle: NativeUInt; ACallerFree: Boolean);
begin
  inherited Create;
  FKeeper := AKeeper;
  FStore := AStore;
  FCert := ACert;
  FHandle := AHandle;
  FCallerFree := ACallerFree;
end;

destructor TPfxKeyOwner.Destroy;
begin
  FKeeper.FreePfxKey(FStore, FCert, FHandle, FCallerFree);
  inherited Destroy;
end;

function TPfxKeyOwner.Handle: NativeUInt;
begin
  Result := FHandle;
end;

{ TWindowsSigningKey }

constructor TWindowsSigningKey.Create(const AOwner: INCryptKeyOwner;
  const ASchemes: TArray<TSignatureScheme>);
begin
  inherited Create;
  FOwner := AOwner;
  FSchemes := ASchemes;
end;

function TWindowsSigningKey.CapableSchemes: TArray<TSignatureScheme>;
begin
  Result := FSchemes;
end;

function TWindowsSigningKey.WithPreferredSchemes(
  const ASchemes: TArray<TSignatureScheme>): ISigningKey;
var
  LNarrowed: TArray<TSignatureScheme>;
  LPref, LCapable: TSignatureScheme;
  LCount: Int32;
begin
  if System.Length(ASchemes) = 0 then
    Exit(Self);
  // intersect the requested order with what this key can actually sign
  SetLength(LNarrowed, System.Length(ASchemes));
  LCount := 0;
  for LPref in ASchemes do
    for LCapable in FSchemes do
      if LPref = LCapable then
      begin
        LNarrowed[LCount] := LPref;
        Inc(LCount);
        Break;
      end;
  SetLength(LNarrowed, LCount);
  // the narrowed copy shares the same refcounted key handle
  Result := TWindowsSigningKey.Create(FOwner, LNarrowed);
end;

function TWindowsSigningKey.SigningKeyOwner: INCryptKeyOwner;
begin
  Result := FOwner;
end;

{ TWindowsSignatureBuffer }

procedure TWindowsSignatureBuffer.Update(const AData: TBytes;
  AOffset, ALength: Int32);
var
  LOld: Int32;
begin
  if ALength <= 0 then
    Exit;
  LOld := System.Length(FBuffer);
  SetLength(FBuffer, LOld + ALength);
  Move(AData[AOffset], FBuffer[LOld], ALength);
end;

{ TWindowsSignatureSigner }

constructor TWindowsSignatureSigner.Create(const AKeeper: IWindowsNCrypt;
  const AOwner: INCryptKeyOwner; AScheme: TSignatureScheme;
  const ASchemeName: string);
begin
  inherited Create;
  FKeeper := AKeeper;
  FOwner := AOwner;
  FScheme := AScheme;
  FSchemeName := ASchemeName;
end;

function TWindowsSignatureSigner.AlgorithmName: string;
begin
  Result := FSchemeName;
end;

function TWindowsSignatureSigner.Sign: TBytes;
begin
  Result := FKeeper.SignData(FOwner.Handle, FScheme, FBuffer);
end;

{ TWindowsSignatureVerifier }

constructor TWindowsSignatureVerifier.Create(const AKeeper: IWindowsNCrypt;
  AKeyHandle: Pointer; AScheme: TSignatureScheme; const ASchemeName: string);
begin
  inherited Create;
  FKeeper := AKeeper;
  FKeyHandle := AKeyHandle;
  FScheme := AScheme;
  FSchemeName := ASchemeName;
end;

destructor TWindowsSignatureVerifier.Destroy;
begin
  FKeeper.FreeVerifyKey(FKeyHandle);
  inherited Destroy;
end;

function TWindowsSignatureVerifier.AlgorithmName: string;
begin
  Result := FSchemeName;
end;

function TWindowsSignatureVerifier.Verify(const ASignature: TBytes): Boolean;
begin
  Result := FKeeper.VerifyData(FKeyHandle, FScheme, FBuffer, ASignature);
end;

{ TWindowsNCrypt }

class function TWindowsNCrypt.LoadApi(out AModule: THandle;
  out AApi: TNCryptApi): Boolean;
begin
  Result := False;
  System.FillChar(AApi, SizeOf(AApi), 0);
  AModule := SafeLoadLibrary(NCRYPT_DLL, SEM_FAILCRITICALERRORS);
  if AModule = 0 then
    Exit;
  AApi.OpenStorageProvider := TNCryptOpenStorageProvider(
    TModuleApi.Proc(AModule, 'NCryptOpenStorageProvider'));
  AApi.ImportKey := TNCryptImportKey(TModuleApi.Proc(AModule, 'NCryptImportKey'));
  AApi.GetProperty := TNCryptGetProperty(TModuleApi.Proc(AModule, 'NCryptGetProperty'));
  AApi.SignHash := TNCryptSignHash(TModuleApi.Proc(AModule, 'NCryptSignHash'));
  AApi.FreeObject := TNCryptFreeObject(TModuleApi.Proc(AModule, 'NCryptFreeObject'));
  Result := System.Assigned(AApi.OpenStorageProvider) and
    System.Assigned(AApi.ImportKey) and System.Assigned(AApi.GetProperty) and
    System.Assigned(AApi.SignHash) and System.Assigned(AApi.FreeObject);
  if not Result then
  begin
    FreeLibrary(AModule);
    AModule := 0;
  end;
end;

class function TWindowsNCrypt.HashAlgForScheme(
  AScheme: TSignatureScheme): THashAlgorithm;
begin
  case AScheme of
    TSignatureScheme.RSA_PSS_RSAE_SHA384, TSignatureScheme.RSA_PKCS1_SHA384,
    TSignatureScheme.ECDSA_SECP384R1_SHA384:
      Result := THashAlgorithm.SHA_384;
    TSignatureScheme.RSA_PSS_RSAE_SHA512, TSignatureScheme.RSA_PKCS1_SHA512,
    TSignatureScheme.ECDSA_SECP521R1_SHA512:
      Result := THashAlgorithm.SHA_512;
  else
    Result := THashAlgorithm.SHA_256;
  end;
end;

class function TWindowsNCrypt.HashIdForScheme(
  AScheme: TSignatureScheme): WideString;
begin
  case AScheme of
    TSignatureScheme.RSA_PSS_RSAE_SHA384, TSignatureScheme.RSA_PKCS1_SHA384:
      Result := HASH_ALG_SHA384;
    TSignatureScheme.RSA_PSS_RSAE_SHA512, TSignatureScheme.RSA_PKCS1_SHA512:
      Result := HASH_ALG_SHA512;
  else
    Result := HASH_ALG_SHA256;
  end;
end;

class function TWindowsNCrypt.HashLenForScheme(
  AScheme: TSignatureScheme): ULONG;
begin
  case AScheme of
    TSignatureScheme.RSA_PSS_RSAE_SHA384, TSignatureScheme.RSA_PKCS1_SHA384:
      Result := 48;
    TSignatureScheme.RSA_PSS_RSAE_SHA512, TSignatureScheme.RSA_PKCS1_SHA512:
      Result := 64;
  else
    Result := 32;
  end;
end;

class function TWindowsNCrypt.IsPssScheme(AScheme: TSignatureScheme): Boolean;
begin
  Result := AScheme in [TSignatureScheme.RSA_PSS_RSAE_SHA256,
    TSignatureScheme.RSA_PSS_RSAE_SHA384, TSignatureScheme.RSA_PSS_RSAE_SHA512];
end;

class function TWindowsNCrypt.IsEcdsaScheme(AScheme: TSignatureScheme): Boolean;
begin
  Result := AScheme in [TSignatureScheme.ECDSA_SECP256R1_SHA256,
    TSignatureScheme.ECDSA_SECP384R1_SHA384, TSignatureScheme.ECDSA_SECP521R1_SHA512];
end;

class function TWindowsNCrypt.IsNativeScheme(AScheme: TSignatureScheme): Boolean;
begin
  Result := IsEcdsaScheme(AScheme) or (AScheme in [TSignatureScheme.RSA_PSS_RSAE_SHA256,
    TSignatureScheme.RSA_PSS_RSAE_SHA384, TSignatureScheme.RSA_PSS_RSAE_SHA512,
    TSignatureScheme.RSA_PKCS1_SHA256, TSignatureScheme.RSA_PKCS1_SHA384,
    TSignatureScheme.RSA_PKCS1_SHA512]);
end;

class function TWindowsNCrypt.DerEncodeEcdsa(const ARaw: TBytes): TBytes;
var
  LHalf: Int32;
  LR, LS, LBody: TBytes;
begin
  // CNG emits the fixed-width r||s; TLS carries SEQUENCE{ INTEGER r, INTEGER s }
  LHalf := System.Length(ARaw) div 2;
  LR := TDer.IntegerTlv(Copy(ARaw, 0, LHalf));
  LS := TDer.IntegerTlv(Copy(ARaw, LHalf, LHalf));
  SetLength(LBody, System.Length(LR) + System.Length(LS));
  Move(LR[0], LBody[0], System.Length(LR));
  Move(LS[0], LBody[System.Length(LR)], System.Length(LS));
  Result := TDer.Tlv($30, LBody);
end;

function TWindowsNCrypt.KeyFieldSize(AKeyHandle: Pointer): Int32;
var
  LBits, LWritten: ULONG;
begin
  // the raw r||s BCryptVerifySignature expects is 2x the KEY's field width, which in TLS
  // 1.2 can differ from the signature scheme's named curve (e.g. a P-256 key signing with
  // ecdsa_secp384r1_sha384 is valid). BCRYPT_PUBLIC_KEY_LENGTH is the field modulus bit-size.
  LBits := 0;
  LWritten := 0;
  if (not System.Assigned(FBcrypt.GetProperty)) or
    (FBcrypt.GetProperty(AKeyHandle, PWideChar(BCRYPT_PUBLIC_KEY_LENGTH_PROP),
    PByte(@LBits), SizeOf(LBits), LWritten, 0) <> STATUS_SUCCESS) or (LBits = 0) then
    Exit(0);
  Result := Int32((LBits + 7) div 8);
end;

// Decodes a DER SEQUENCE{ INTEGER r, INTEGER s } to the fixed-width r||s BCrypt verifies.
// Strictly bounds-checked and fail-closed: any malformed input returns False.
class function TWindowsNCrypt.TryDerDecodeEcdsa(const ADer: TBytes;
  AFieldSize: Int32; out ARaw: TBytes): Boolean;
var
  LPos, LEnd, LN: Int32;

  // reads one DER INTEGER at AOffset, returns its content left-padded to AFieldSize in
  // AValue, and advances LPos past the whole TLV
  function ReadInt(AOffset: Int32; out AValue: TBytes): Boolean;
  var
    LLenOrig, LLen, LStart: Int32;
  begin
    Result := False;
    if (AOffset + 2 > LEnd) or (ADer[AOffset] <> $02) then
      Exit;
    LLenOrig := ADer[AOffset + 1];
    if (LLenOrig and $80) <> 0 then // long-form length is not expected for r/s
      Exit;
    LStart := AOffset + 2;
    if LStart + LLenOrig > LEnd then
      Exit;
    LLen := LLenOrig;
    // skip a single leading zero sign byte
    if (LLen > 1) and (ADer[LStart] = 0) then
    begin
      Inc(LStart);
      Dec(LLen);
    end;
    if (LLen = 0) or (LLen > AFieldSize) then
      Exit;
    AValue := nil;
    SetLength(AValue, AFieldSize);
    System.FillChar(AValue[0], AFieldSize, 0);
    Move(ADer[LStart], AValue[AFieldSize - LLen], LLen);
    LPos := AOffset + 2 + LLenOrig; // advance past the full TLV
    Result := True;
  end;

var
  LR, LS: TBytes;
  LSeqLen: Int32;
begin
  ARaw := nil;
  LN := System.Length(ADer);
  if (LN < 2) or (ADer[0] <> $30) then
    Exit(False);
  LSeqLen := ADer[1];
  if (LSeqLen and $80) <> 0 then // one long-form length byte (0x81) for larger curves
  begin
    if (LSeqLen <> $81) or (LN < 3) then
      Exit(False);
    LSeqLen := ADer[2];
    LPos := 3;
  end
  else
    LPos := 2;
  LEnd := LPos + LSeqLen;
  if LEnd > LN then
    Exit(False);
  if not ReadInt(LPos, LR) then
    Exit(False);
  if not ReadInt(LPos, LS) then
    Exit(False);
  if LPos <> LEnd then
    Exit(False);
  ARaw := nil;
  SetLength(ARaw, 2 * AFieldSize);
  Move(LR[0], ARaw[0], AFieldSize);
  Move(LS[0], ARaw[AFieldSize], AFieldSize);
  Result := True;
end;

class function TWindowsNCrypt.Sec1CurveOid(const ASec1: TBytes;
  out ACurveOid: TBytes): Boolean;
var
  LTag: Byte;
  LSeqOfs, LSeqLen, LNext, LOfs, LCofs, LClen, LEnd: Int32;
begin
  ACurveOid := nil;
  Result := False;
  if (not TDer.ReadTlv(ASec1, 0, LTag, LSeqOfs, LSeqLen, LNext)) or (LTag <> $30) then
    Exit;
  LEnd := LSeqOfs + LSeqLen;
  LOfs := LSeqOfs;
  while LOfs < LEnd do
  begin
    if not TDer.ReadTlv(ASec1, LOfs, LTag, LCofs, LClen, LNext) then
      Exit;
    // [0] parameters: its content is the named-curve OID TLV, copied verbatim
    if LTag = $A0 then
    begin
      ACurveOid := System.Copy(ASec1, LCofs, LClen);
      Exit(True);
    end;
    LOfs := LNext;
  end;
end;

class function TWindowsNCrypt.WrapPkcs8IfNeeded(const ADer: TBytes): TBytes;
var
  LTag, LTag1, LTag2: Byte;
  LSeqOfs, LSeqLen, LNext, LC1ofs, LC1len, LN1, LC2ofs, LC2len, LN2: Int32;
  LCurveOid, LAlgId, LContent: TBytes;
begin
  // best-effort: any parse mismatch leaves the blob unchanged for the KSP / portable facet
  Result := ADer;
  if (not TDer.ReadTlv(ADer, 0, LTag, LSeqOfs, LSeqLen, LNext)) or (LTag <> $30) then
    Exit;
  // 1st element INTEGER = a version-prefixed body (PKCS#1 / SEC1 / plain PKCS#8); an
  // EncryptedPrivateKeyInfo starts with a SEQUENCE (AlgId) and is left alone
  if (not TDer.ReadTlv(ADer, LSeqOfs, LTag1, LC1ofs, LC1len, LN1)) or (LTag1 <> $02) then
    Exit;
  if not TDer.ReadTlv(ADer, LN1, LTag2, LC2ofs, LC2len, LN2) then
    Exit;
  case LTag2 of
    $02: // 2nd element INTEGER -> PKCS#1 RSAPrivateKey (modulus): wrap with rsaEncryption
      begin
        LContent := TArrayUtilities.Concat([TBytes.Create($02, $01, $00),
          TBytes.Create($30, $0D, $06, $09, $2A, $86, $48, $86, $F7, $0D, $01, $01, $01,
          $05, $00), TDer.Tlv($04, ADer)]);
        Result := TDer.Tlv($30, LContent);
      end;
    $04: // 2nd element OCTET STRING -> SEC1 ECPrivateKey: wrap with ecPublicKey + curve OID
      begin
        if not Sec1CurveOid(ADer, LCurveOid) then
          Exit;
        LAlgId := TDer.Tlv($30, TArrayUtilities.Concat(
          [TBytes.Create($06, $07, $2A, $86, $48, $CE, $3D, $02, $01), LCurveOid]));
        LContent := TArrayUtilities.Concat([TBytes.Create($02, $01, $00), LAlgId,
          TDer.Tlv($04, ADer)]);
        Result := TDer.Tlv($30, LContent);
      end;
    // 2nd element SEQUENCE ($30) = plain PKCS#8, or anything else: unchanged
  end;
end;

constructor TWindowsNCrypt.Create(const ACng: IWindowsCng);
begin
  inherited Create;
  FCng := ACng;
  FBcrypt := ACng.BcryptApi;
  FProvider := 0;
  FCrypt32 := 0;
  // ncrypt + the KSP are required for signing; failure means signing stays portable
  if not LoadApi(FModule, FApi) then
    raise ESystemCryptoUnsupportedTlsLibException.CreateRes(@SCngUnavailable);
  if FApi.OpenStorageProvider(FProvider, PWideChar(NCRYPT_KSP_NAME), 0)
    <> STATUS_SUCCESS then
  begin
    FreeLibrary(FModule);
    FModule := 0;
    raise ESystemCryptoUnsupportedTlsLibException.CreateRes(@SCngUnavailable);
  end;
  // verification is a separate, optional capability (crypt32 to import the SPKI +
  // BCryptVerifySignature): if any part is absent, verification falls back to portable
  FCrypt32 := SafeLoadLibrary(CRYPT32_DLL, SEM_FAILCRITICALERRORS);
  if FCrypt32 <> 0 then
  begin
    FCryptApi.DecodeObjectEx := TCryptDecodeObjectEx(
      TModuleApi.Proc(FCrypt32, 'CryptDecodeObjectEx'));
    FCryptApi.ImportPublicKeyInfoEx2 := TCryptImportPublicKeyInfoEx2(
      TModuleApi.Proc(FCrypt32, 'CryptImportPublicKeyInfoEx2'));
    FCryptApi.PFXImportCertStore := TPFXImportCertStore(
      TModuleApi.Proc(FCrypt32, 'PFXImportCertStore'));
    FCryptApi.CertFindCertificateInStore := TCertFindCertificateInStore(
      TModuleApi.Proc(FCrypt32, 'CertFindCertificateInStore'));
    FCryptApi.GetCertContextProperty := TCertGetCertificateContextProperty(
      TModuleApi.Proc(FCrypt32, 'CertGetCertificateContextProperty'));
    FCryptApi.FreeCertificateContext := TCertFreeCertificateContext(
      TModuleApi.Proc(FCrypt32, 'CertFreeCertificateContext'));
    FCryptApi.CloseStore := TCertCloseStore(TModuleApi.Proc(FCrypt32, 'CertCloseStore'));
  end;
  FVerifyReady := (FCrypt32 <> 0) and
    System.Assigned(FCryptApi.DecodeObjectEx) and
    System.Assigned(FCryptApi.ImportPublicKeyInfoEx2) and
    System.Assigned(FBcrypt.VerifySignature) and System.Assigned(FBcrypt.DestroyKey);
  FPfxReady := (FCrypt32 <> 0) and
    System.Assigned(FCryptApi.PFXImportCertStore) and
    System.Assigned(FCryptApi.CertFindCertificateInStore) and
    System.Assigned(FCryptApi.GetCertContextProperty) and
    System.Assigned(FCryptApi.FreeCertificateContext) and
    System.Assigned(FCryptApi.CloseStore);
end;

destructor TWindowsNCrypt.Destroy;
begin
  if (FProvider <> 0) and System.Assigned(FApi.FreeObject) then
    FApi.FreeObject(FProvider);
  if FModule <> 0 then
    FreeLibrary(FModule);
  if FCrypt32 <> 0 then
    FreeLibrary(FCrypt32);
  inherited Destroy;
end;

function TWindowsNCrypt.AlgName(AKey: NativeUInt): string;
var
  LBuf: array [0 .. 63] of WideChar;
  LWritten: ULONG;
begin
  LWritten := 0;
  System.FillChar(LBuf, SizeOf(LBuf), 0);
  if FApi.GetProperty(AKey, PWideChar(NCRYPT_ALG_NAME_PROP), PByte(@LBuf[0]),
    SizeOf(LBuf), LWritten, 0) <> STATUS_SUCCESS then
    Exit('');
  Result := WideString(PWideChar(@LBuf[0]));
end;

function TWindowsNCrypt.KeySchemes(AKey: NativeUInt;
  out ASchemes: TArray<TSignatureScheme>): Boolean;
var
  LName: string;
begin
  // the KSP names an imported key by algorithm and (for EC) curve: "RSA", "ECDH_P256" /
  // "ECDSA_P256", etc. An EC key imports as the ECDH_* named algorithm but signs as ECDSA.
  ASchemes := nil;
  LName := AlgName(AKey);
  if LName = 'RSA' then
    ASchemes := TArray<TSignatureScheme>.Create(TSignatureScheme.RSA_PSS_RSAE_SHA256,
      TSignatureScheme.RSA_PSS_RSAE_SHA384, TSignatureScheme.RSA_PSS_RSAE_SHA512,
      TSignatureScheme.RSA_PKCS1_SHA256, TSignatureScheme.RSA_PKCS1_SHA384,
      TSignatureScheme.RSA_PKCS1_SHA512)
  else if Pos('P256', LName) > 0 then
    ASchemes := TArray<TSignatureScheme>.Create(TSignatureScheme.ECDSA_SECP256R1_SHA256)
  else if Pos('P384', LName) > 0 then
    ASchemes := TArray<TSignatureScheme>.Create(TSignatureScheme.ECDSA_SECP384R1_SHA384)
  else if Pos('P521', LName) > 0 then
    ASchemes := TArray<TSignatureScheme>.Create(TSignatureScheme.ECDSA_SECP521R1_SHA512);
  Result := System.Length(ASchemes) > 0;
end;

function TWindowsNCrypt.TryImportKey(const APkcs8: TBytes; const APassword: string;
  out AKey: NativeUInt; out ASchemes: TArray<TSignatureScheme>): Boolean;
var
  LKey: NativeUInt;
  LPwd: WideString;
  LBuf: TNCryptBuffer;
  LDesc: TNCryptBufferDesc;
  LParam: Pointer;
  LDer: TBytes;
begin
  AKey := 0;
  ASchemes := nil;
  LKey := 0;
  // a raw PKCS#1 / SEC1 key is wrapped into the PKCS#8 the KSP imports; a PKCS#8 (plain or
  // encrypted, as for a non-empty password) passes through unchanged
  LDer := WrapPkcs8IfNeeded(APkcs8);
  // a non-empty password imports an encrypted PKCS#8: the KSP decrypts it from the
  // NCRYPTBUFFER_PKCS_SECRET buffer. LPwd must outlive the ImportKey call (it does - it is
  // this frame's local, pointed at by the buffer)
  LParam := nil;
  if APassword <> '' then
  begin
    LPwd := WideString(APassword);
    LBuf.cbBuffer := (ULONG(System.Length(LPwd)) + 1) * SizeOf(WideChar);
    LBuf.BufferType := NCRYPTBUFFER_PKCS_SECRET;
    LBuf.pvBuffer := PWideChar(LPwd);
    LDesc.ulVersion := NCRYPTBUFFER_VERSION;
    LDesc.cBuffers := 1;
    LDesc.pBuffers := @LBuf;
    LParam := @LDesc;
  end;
  // the KSP parses the PKCS#8 PrivateKeyInfo; a non-PKCS#8 / unsupported-PBE / unsupported key
  // (or a wrong password) simply fails to import and the caller delegates to the portable facet
  if FApi.ImportKey(FProvider, 0, PWideChar(BLOB_PKCS8_PRIVATE), LParam, LKey,
    PByte(LDer), System.Length(LDer), NCRYPT_SILENT_FLAG) <> STATUS_SUCCESS then
    Exit(False);
  if KeySchemes(LKey, ASchemes) then
  begin
    AKey := LKey;
    Result := True;
  end
  else
  begin
    FApi.FreeObject(LKey);
    Result := False;
  end;
end;

function TWindowsNCrypt.HashDigest(AAlgorithm: THashAlgorithm;
  const AData: TBytes): TBytes;
var
  LHash: IHash;
begin
  if not FCng.TryCreateHash(AAlgorithm, LHash) then
    raise ESystemCryptoBackendTlsLibException.CreateRes(@SCngUnavailable);
  LHash.Update(AData, 0, System.Length(AData));
  Result := LHash.DoFinal;
end;

function TWindowsNCrypt.SignRsaDigest(AKey: NativeUInt;
  AScheme: TSignatureScheme; const ADigest: TBytes): TBytes;
var
  LHashId: WideString;
  LPkcs1: TBCryptPkcs1PaddingInfo;
  LPss: TBCryptPssPaddingInfo;
  LPad: Pointer;
  LFlags, LSize, LWritten: ULONG;
begin
  LHashId := HashIdForScheme(AScheme);
  if IsPssScheme(AScheme) then
  begin
    LPss.pszAlgId := PWideChar(LHashId);
    LPss.cbSalt := HashLenForScheme(AScheme); // rsa_pss_rsae_*: salt length = hash length
    LPad := @LPss;
    LFlags := NCRYPT_PAD_PSS_FLAG or NCRYPT_SILENT_FLAG;
  end
  else
  begin
    LPkcs1.pszAlgId := PWideChar(LHashId);
    LPad := @LPkcs1;
    LFlags := NCRYPT_PAD_PKCS1_FLAG or NCRYPT_SILENT_FLAG;
  end;
  LSize := 0;
  TCngError.Check(FApi.SignHash(AKey, LPad, PByte(ADigest),
    System.Length(ADigest), nil, 0, LSize, LFlags));
  SetLength(Result, LSize);
  LWritten := 0;
  TCngError.Check(FApi.SignHash(AKey, LPad, PByte(ADigest),
    System.Length(ADigest), PByte(Result), LSize, LWritten, LFlags));
  SetLength(Result, LWritten);
end;

function TWindowsNCrypt.SignEcdsaDigest(AKey: NativeUInt;
  const ADigest: TBytes): TBytes;
var
  LRaw: TBytes;
  LSize, LWritten: ULONG;
begin
  // ECDSA takes no padding info; CNG returns the fixed-width r||s, DER-encoded below
  LSize := 0;
  TCngError.Check(FApi.SignHash(AKey, nil, PByte(ADigest), System.Length(ADigest),
    nil, 0, LSize, NCRYPT_SILENT_FLAG));
  SetLength(LRaw, LSize);
  LWritten := 0;
  TCngError.Check(FApi.SignHash(AKey, nil, PByte(ADigest), System.Length(ADigest),
    PByte(LRaw), LSize, LWritten, NCRYPT_SILENT_FLAG));
  SetLength(LRaw, LWritten);
  Result := DerEncodeEcdsa(LRaw);
end;

function TWindowsNCrypt.SignData(AKey: NativeUInt; AScheme: TSignatureScheme;
  const AData: TBytes): TBytes;
var
  LDigest: TBytes;
begin
  LDigest := HashDigest(HashAlgForScheme(AScheme), AData);
  if IsEcdsaScheme(AScheme) then
    Result := SignEcdsaDigest(AKey, LDigest)
  else
    Result := SignRsaDigest(AKey, AScheme, LDigest);
end;

procedure TWindowsNCrypt.FreeKey(AKey: NativeUInt);
begin
  if AKey <> 0 then
    FApi.FreeObject(AKey);
end;

function TWindowsNCrypt.CanVerify: Boolean;
begin
  Result := FVerifyReady;
end;

function TWindowsNCrypt.TryImportSpki(const ASpki: TBytes;
  out AKeyHandle: Pointer): Boolean;
var
  LInfo, LKey: Pointer;
  LSize: DWORD;
begin
  AKeyHandle := nil;
  if not FVerifyReady then
    Exit(False);
  // decode the X.509 SubjectPublicKeyInfo (crypt32 allocates the struct), then import it
  // as a BCrypt public key handle
  LInfo := nil;
  LSize := 0;
  if not FCryptApi.DecodeObjectEx(X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO_STRUCT,
    PByte(ASpki), System.Length(ASpki), CRYPT_DECODE_ALLOC_FLAG, nil, @LInfo, LSize) then
    Exit(False);
  try
    LKey := nil;
    if FCryptApi.ImportPublicKeyInfoEx2(X509_ASN_ENCODING, LInfo, 0, nil, LKey) then
    begin
      AKeyHandle := LKey;
      Result := True;
    end
    else
      Result := False;
  finally
    LocalFree(HLOCAL(LInfo));
  end;
end;

function TWindowsNCrypt.VerifyHash(AKeyHandle: Pointer; AScheme: TSignatureScheme;
  const ADigest, ASignature: TBytes): Boolean;
var
  LHashId: WideString;
  LPkcs1: TBCryptPkcs1PaddingInfo;
  LPss: TBCryptPssPaddingInfo;
  LPad: Pointer;
  LFlags: ULONG;
  LSig: TBytes;
  LFieldSize: Int32;
begin
  if IsEcdsaScheme(AScheme) then
  begin
    // BCrypt expects the fixed-width r||s (2x the KEY's field width, from the key not the
    // scheme - TLS 1.2 decouples them), not the DER the signature travels as
    LFieldSize := KeyFieldSize(AKeyHandle);
    if (LFieldSize = 0) or (not TryDerDecodeEcdsa(ASignature, LFieldSize, LSig)) then
      Exit(False);
    LPad := nil;
    LFlags := 0;
  end
  else
  begin
    LHashId := HashIdForScheme(AScheme);
    if IsPssScheme(AScheme) then
    begin
      LPss.pszAlgId := PWideChar(LHashId);
      LPss.cbSalt := HashLenForScheme(AScheme);
      LPad := @LPss;
      LFlags := BCRYPT_PAD_PSS;
    end
    else
    begin
      LPkcs1.pszAlgId := PWideChar(LHashId);
      LPad := @LPkcs1;
      LFlags := BCRYPT_PAD_PKCS1;
    end;
    LSig := ASignature;
  end;
  Result := FBcrypt.VerifySignature(AKeyHandle, LPad, PByte(ADigest),
    System.Length(ADigest), PByte(LSig), System.Length(LSig), LFlags) = STATUS_SUCCESS;
end;

function TWindowsNCrypt.VerifyData(AKeyHandle: Pointer; AScheme: TSignatureScheme;
  const AData, ASignature: TBytes): Boolean;
var
  LDigest: TBytes;
begin
  // fail-closed: a malformed digest/signature or backend fault is a verification failure,
  // never an exception (ISignatureVerifier.Verify contract)
  try
    LDigest := HashDigest(HashAlgForScheme(AScheme), AData);
    Result := VerifyHash(AKeyHandle, AScheme, LDigest, ASignature);
  except
    Result := False;
  end;
end;

procedure TWindowsNCrypt.FreeVerifyKey(AKeyHandle: Pointer);
begin
  if (AKeyHandle <> nil) and System.Assigned(FBcrypt.DestroyKey) then
    FBcrypt.DestroyKey(AKeyHandle);
end;

function TWindowsNCrypt.TryImportPkcs12Key(const APfx: TBytes;
  const APassword: string; out AKey: ISigningKey): Boolean;
var
  LBlob: TCryptDataBlob;
  LPassword: WideString;
  LStore, LCert: Pointer;
  LKey: NativeUInt;
  LSize: DWORD;
  LSchemes: TArray<TSignatureScheme>;
begin
  AKey := nil;
  if not FPfxReady then
    Exit(False);
  LBlob.cbData := System.Length(APfx);
  LBlob.pbData := PByte(APfx);
  LPassword := WideString(APassword);
  // keep the key CNG-backed (PKCS12_ALWAYS_CNG_KSP) and off disk (PKCS12_NO_PERSIST_KEY)
  LStore := FCryptApi.PFXImportCertStore(@LBlob, PWideChar(LPassword),
    PKCS12_NO_PERSIST_KEY or PKCS12_ALWAYS_CNG_KSP);
  if LStore = nil then
    Exit(False);
  // the portable import already guaranteed exactly one key entry, so the first cert with a
  // private key is the identity's leaf; the no-persist CNG handle is on the cert context
  LCert := FCryptApi.CertFindCertificateInStore(LStore, X509_ASN_ENCODING, 0,
    CERT_FIND_HAS_PRIVATE_KEY, nil, nil);
  if LCert = nil then
  begin
    FCryptApi.CloseStore(LStore, 0);
    Exit(False);
  end;
  LKey := 0;
  LSize := SizeOf(LKey);
  if (not FCryptApi.GetCertContextProperty(LCert, CERT_NCRYPT_KEY_HANDLE_PROP_ID,
    @LKey, LSize)) or (LKey = 0) or (not KeySchemes(LKey, LSchemes)) then
  begin
    FreePfxKey(LStore, LCert, 0, False);
    Exit(False);
  end;
  // the handle is owned by the cert context / store, freed when the owner closes them
  AKey := TWindowsSigningKey.Create(TPfxKeyOwner.Create(Self as IWindowsNCrypt,
    LStore, LCert, LKey, False) as INCryptKeyOwner, LSchemes);
  Result := True;
end;

procedure TWindowsNCrypt.FreePfxKey(AStore, ACert: Pointer; AHandle: NativeUInt;
  ACallerFree: Boolean);
begin
  // the PKCS#12 CNG key handle is owned by the cert context (ACallerFree is always False):
  // closing the store releases it, so only the context and store are freed here
  if ACert <> nil then
    FCryptApi.FreeCertificateContext(ACert);
  if AStore <> nil then
    FCryptApi.CloseStore(AStore, 0);
end;

{ TWindowsSigningCrypto }

constructor TWindowsSigningCrypto.Create(const AInner: ISigningCrypto;
  const ANCrypt: IWindowsNCrypt);
begin
  inherited Create;
  FInner := AInner;
  FNCrypt := ANCrypt;
end;

class function TWindowsSigningCrypto.SchemeName(AScheme: TSignatureScheme): string;
begin
  Result := TEnumUtilities.GetName<TSignatureScheme>(AScheme);
end;

function TWindowsSigningCrypto.TryImportPemNative(const AData: TBytes;
  const APassword: string; out AKey: ISigningKey): Boolean;
var
  LBlocks: TArray<TPemBlock>;
  LI: Int32;
  LKey: NativeUInt;
  LSchemes: TArray<TSignatureScheme>;
  LImported: Boolean;
begin
  AKey := nil;
  try
    LBlocks := TPem.ReadBlocks(AData);
  except
    // malformed PEM: let the portable facet re-parse and own the canonical error
    Exit(False);
  end;
  for LI := 0 to System.Length(LBlocks) - 1 do
  begin
    // encrypted PKCS#8 needs the password; plain PKCS#8 and the raw PKCS#1/SEC1 forms
    // ("RSA/EC PRIVATE KEY", wrapped to PKCS#8 inside TryImportKey) import unkeyed
    if LBlocks[LI].PemType = 'ENCRYPTED PRIVATE KEY' then
      LImported := FNCrypt.TryImportKey(LBlocks[LI].Content, APassword, LKey, LSchemes)
    else if (LBlocks[LI].PemType = 'PRIVATE KEY') or
      (LBlocks[LI].PemType = 'RSA PRIVATE KEY') or
      (LBlocks[LI].PemType = 'EC PRIVATE KEY') then
      LImported := FNCrypt.TryImportKey(LBlocks[LI].Content, '', LKey, LSchemes)
    else
      LImported := False;
    if LImported then
    begin
      AKey := TWindowsSigningKey.Create(TNCryptKeyOwner.Create(FNCrypt, LKey)
        as INCryptKeyOwner, LSchemes);
      Exit(True);
    end;
  end;
  Result := False;
end;

function TWindowsSigningCrypto.ImportSigningKey(const AData: TBytes): ISigningKey;
var
  LKey: NativeUInt;
  LSchemes: TArray<TSignatureScheme>;
  LOwner: INCryptKeyOwner;
begin
  // native path is a PKCS#8 key (RSA or NIST-curve ECDSA) - DER imported directly, PEM
  // decoded first; a PKCS#1/SEC1 or Ed25519 key delegates to the portable facet
  if TPem.IsArmored(AData) then
  begin
    if not TryImportPemNative(AData, '', Result) then
      Result := FInner.ImportSigningKey(AData);
  end
  else if FNCrypt.TryImportKey(AData, '', LKey, LSchemes) then
  begin
    LOwner := TNCryptKeyOwner.Create(FNCrypt, LKey);
    Result := TWindowsSigningKey.Create(LOwner, LSchemes);
  end
  else
    Result := FInner.ImportSigningKey(AData);
end;

function TWindowsSigningCrypto.ImportSigningKey(const AData: TBytes;
  const APassword: string): ISigningKey;
var
  LKey: NativeUInt;
  LSchemes: TArray<TSignatureScheme>;
  LOwner: INCryptKeyOwner;
begin
  // native path is an encrypted PKCS#8 (EncryptedPrivateKeyInfo) the KSP decrypts and imports
  // - DER imported directly, PEM decoded first; an unsupported-PBE or otherwise unsupported
  // key (or a wrong password) delegates to the portable facet, which owns the full
  // decrypt/parse range and all error handling
  if TPem.IsArmored(AData) then
  begin
    if not TryImportPemNative(AData, APassword, Result) then
      Result := FInner.ImportSigningKey(AData, APassword);
  end
  else if FNCrypt.TryImportKey(AData, APassword, LKey, LSchemes) then
  begin
    LOwner := TNCryptKeyOwner.Create(FNCrypt, LKey);
    Result := TWindowsSigningKey.Create(LOwner, LSchemes);
  end
  else
    Result := FInner.ImportSigningKey(AData, APassword);
end;

function TWindowsSigningCrypto.ImportPkcs12(const AData: TBytes;
  const APassword: string): TTlsCredential;
var
  LNativeKey: ISigningKey;
begin
  // the portable facet owns the parse: the certificate chain, the single-key-entry rule,
  // and all fail-closed error handling. We then adopt the same key as a native CNG-backed
  // signing key so the identity signs on OS crypto; on any failure the portable key stays.
  Result := FInner.ImportPkcs12(AData, APassword);
  if FNCrypt.TryImportPkcs12Key(AData, APassword, LNativeKey) then
    Result.PrivateKey := LNativeKey;
end;

function TWindowsSigningCrypto.CreateSignatureSigner(AScheme: TSignatureScheme;
  const AKey: ISigningKey): ISignatureSigner;
var
  LNative: IWindowsSigningKey;
begin
  // route to the backend that produced the key handle: native signer for our own handle,
  // else the portable facet that minted it
  if Supports(AKey, IWindowsSigningKey, LNative) then
    Result := TWindowsSignatureSigner.Create(FNCrypt, LNative.SigningKeyOwner,
      AScheme, SchemeName(AScheme))
  else
    Result := FInner.CreateSignatureSigner(AScheme, AKey);
end;

function TWindowsSigningCrypto.CreateSignatureVerifier(AScheme: TSignatureScheme;
  const APublicKeyDer: TBytes): ISignatureVerifier;
var
  LKeyHandle: Pointer;
begin
  // RSA/ECDSA verify natively when the SPKI imports; EdDSA, an unsupported scheme, or a
  // key crypt32 cannot decode falls back to the portable verifier (which owns the error)
  if TWindowsNCrypt.IsNativeScheme(AScheme) and FNCrypt.CanVerify and
    FNCrypt.TryImportSpki(APublicKeyDer, LKeyHandle) then
    Result := TWindowsSignatureVerifier.Create(FNCrypt, LKeyHandle, AScheme,
      SchemeName(AScheme))
  else
    Result := FInner.CreateSignatureVerifier(AScheme, APublicKeyDer);
end;

{ TWindowsSystemCrypto }

class function TWindowsSystemCrypto.Compose(
  const ABase: ICryptoProvider): ICryptoProvider;
var
  LCng: IWindowsCng;
  LNCrypt: IWindowsNCrypt;
  LPrimitives: ICryptoPrimitives;
  LSigning: ISigningCrypto;
  LReport: ICryptoBackendReport;
begin
  try
    LCng := TWindowsCng.Create;
  except
    // bcrypt unusable on this host: keep the portable base
    on ESystemCryptoUnsupportedTlsLibException do
      Exit(ABase);
  end;
  LPrimitives := TWindowsCryptoPrimitives.Create(ABase.Primitives, LCng);
  // signing is a separate capability (ncrypt.dll + the KSP); if it is unavailable the
  // Signing facet stays portable while the native primitives above still apply
  LSigning := nil;
  try
    LNCrypt := TWindowsNCrypt.Create(LCng);
    LSigning := TWindowsSigningCrypto.Create(ABase.Signing, LNCrypt);
  except
    on ESystemCryptoUnsupportedTlsLibException do
      LSigning := nil;
  end;
  LReport := TWindowsBackendReport.Create(LCng, LSigning <> nil);
  Result := TOverlayCryptoProvider.Create(ABase, LPrimitives, LSigning, LReport);
end;

{$ENDIF}

end.
