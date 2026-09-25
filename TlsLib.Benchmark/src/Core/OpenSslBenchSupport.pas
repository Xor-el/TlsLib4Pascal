{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit OpenSslBenchSupport;

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

interface

uses
  SysUtils,
  mormot.core.base,
  mormot.crypt.secure,
  mormot.lib.openssl11,
  TlsBenchmarkData;

type
  /// <summary>
  /// Shared low-level OpenSSL setup for the benchmark peers, driven through mORMot's
  /// binding: loading the libraries, reporting the exact version measured (so a run
  /// records which OpenSSL produced the figures), building a client/server SSL_CTX with
  /// the version, cipher list and supported-groups pinned to match the TlsLib peer, and
  /// shuttling bytes between a pair of memory BIOs.
  /// </summary>
  TOpenSslBench = class sealed(TObject)
  public
    /// <summary>True when the OpenSSL libraries loaded.</summary>
    class function Available: Boolean; static;
    /// <summary>The loaded OpenSSL version string (empty when unavailable).</summary>
    class function VersionString: string; static;
    /// <summary>A client SSL_CTX with the version and (optional) cipher list / groups pinned.
    /// For TLS 1.3 the cipher string is a TLSv1.3 ciphersuites list (TLS_AES_128_GCM_SHA256 ...),
    /// which OpenSSL configures separately from the 1.2 cipher list.</summary>
    class function NewClientCtx(AWireVersion: UInt16;
      const ACipherList, AGroups: string): PSSL_CTX; static;
    /// <summary>A server SSL_CTX as NewClientCtx plus the loaded EC leaf credential.</summary>
    class function NewServerCtx(const ACredential: TTlsBenchmarkCredential;
      AWireVersion: UInt16; const ACipherList, AGroups: string): PSSL_CTX; static;
    /// <summary>Moves everything queued in ASource's memory BIO into ADestination's.</summary>
    class procedure DrainBio(ASource, ADestination: PBIO; var AScratch: TBytes); static;
  end;

implementation

uses
  mormot.core.os;

const
  // OpenSSL's SSL_CTRL_SET_GROUPS_LIST (ssl.h); mORMot exposes no typed groups setter, so
  // the supported-groups list is pinned through the generic ctrl to match the TlsLib peer
  SSL_CTRL_SET_GROUPS_LIST = 92;
  // OpenSSL_version() selector for the human-readable version string (OPENSSL_VERSION)
  OPENSSL_VERSION_STRING = 0;

type
  TSslCtxSetCipherSuites = function(ACtx: PSSL_CTX; AStr: PUtf8Char): Int32; cdecl;

var
  GSetCipherSuites: TSslCtxSetCipherSuites = nil;

// the binding exposes no SSL_CTX_set_ciphersuites, so resolve it from whichever libssl it
// already loaded (the library names it tries, newest first)
function SetCipherSuites: TSslCtxSetCipherSuites;
const
  CLibraries: array [0 .. 2] of TFileName = (LIB_SSL4, LIB_SSL3, LIB_SSL1);
var
  LIdx: Int32;
  LLib: TLibHandle;
begin
  if not Assigned(GSetCipherSuites) then
    for LIdx := System.Low(CLibraries) to System.High(CLibraries) do
    begin
      LLib := LibraryOpen(CLibraries[LIdx]);
      if LLib = 0 then
        Continue;
      GSetCipherSuites := TSslCtxSetCipherSuites(LibraryResolve(LLib, 'SSL_CTX_set_ciphersuites'));
      if Assigned(GSetCipherSuites) then
        Break;
      LibraryClose(LLib);
    end;
  if not Assigned(GSetCipherSuites) then
    raise ETlsBenchmarkError.Create('OpenSSL SSL_CTX_set_ciphersuites could not be resolved');
  Result := GSetCipherSuites;
end;

procedure PinCiphers(ACtx: PSSL_CTX; AWireVersion: UInt16; const ACipherList: string);
var
  LSetSuites: TSslCtxSetCipherSuites;
  LList: RawUtf8;
begin
  if ACipherList = '' then
    Exit;
  LList := RawUtf8(ACipherList);
  if AWireVersion = TLS1_3_VERSION then
  begin
    LSetSuites := SetCipherSuites;
    if LSetSuites(ACtx, PUtf8Char(LList)) <= 0 then
      raise ETlsBenchmarkError.CreateFmt('OpenSSL rejected the ciphersuites "%s"', [ACipherList]);
  end
  else if SSL_CTX_set_cipher_list(ACtx, PUtf8Char(LList)) <= 0 then
    raise ETlsBenchmarkError.CreateFmt('OpenSSL rejected the cipher list "%s"', [ACipherList]);
end;

class function TOpenSslBench.Available: Boolean;
begin
  Result := OpenSslIsAvailable;
end;

class function TOpenSslBench.VersionString: string;
begin
  if OpenSslIsAvailable then
    Result := string(OpenSSL_version(OPENSSL_VERSION_STRING))
  else
    Result := '';
end;

function DerBytesToPem(const ADer: TBytes; AKind: TPemKind): RawByteString;
var
  LDer: RawByteString;
begin
  SetString(LDer, PAnsiChar(@ADer[0]), System.Length(ADer));
  Result := RawByteString(DerToPem(TCertDer(LDer), AKind));
end;

procedure PinGroups(ACtx: PSSL_CTX; const AGroups: string);
var
  LGroups: RawUtf8;
begin
  if AGroups = '' then
    Exit;
  LGroups := RawUtf8(AGroups);
  if SSL_CTX_ctrl(ACtx, SSL_CTRL_SET_GROUPS_LIST, 0, PUtf8Char(LGroups)) <= 0 then
    raise ETlsBenchmarkError.CreateFmt('OpenSSL rejected the groups list "%s"', [AGroups]);
end;

class function TOpenSslBench.NewClientCtx(AWireVersion: UInt16;
  const ACipherList, AGroups: string): PSSL_CTX;
begin
  Result := SSL_CTX_new(TLS_client_method());
  if Result = nil then
    raise ETlsBenchmarkError.Create('OpenSSL could not create a client SSL context');
  SSL_CTX_set_min_proto_version(Result, AWireVersion);
  SSL_CTX_set_max_proto_version(Result, AWireVersion);
  PinGroups(Result, AGroups);
  PinCiphers(Result, AWireVersion, ACipherList);
end;

class function TOpenSslBench.NewServerCtx(const ACredential: TTlsBenchmarkCredential;
  AWireVersion: UInt16; const ACipherList, AGroups: string): PSSL_CTX;
var
  LPem: RawByteString;
  LBio: PBIO;
  LCert: PX509;
  LKey: PEVP_PKEY;
begin
  Result := SSL_CTX_new(TLS_server_method());
  if Result = nil then
    raise ETlsBenchmarkError.Create('OpenSSL could not create a server SSL context');
  SSL_CTX_set_min_proto_version(Result, AWireVersion);
  SSL_CTX_set_max_proto_version(Result, AWireVersion);
  PinGroups(Result, AGroups);
  PinCiphers(Result, AWireVersion, ACipherList);

  LPem := DerBytesToPem(ACredential.LeafCertDer, pemCertificate);
  LBio := BIO_new(BIO_s_mem());
  BIO_write(LBio, PAnsiChar(LPem), System.Length(LPem));
  LCert := PEM_read_bio_X509(LBio, nil, nil, nil);
  BIO_free(LBio);
  if (LCert = nil) or (SSL_CTX_use_certificate(Result, LCert) <> 1) then
    raise ETlsBenchmarkError.Create('OpenSSL rejected the benchmark certificate');

  LPem := DerBytesToPem(ACredential.LeafKeyDer, pemPrivateKey);
  LBio := BIO_new(BIO_s_mem());
  BIO_write(LBio, PAnsiChar(LPem), System.Length(LPem));
  LKey := PEM_read_bio_PrivateKey(LBio, nil, nil, nil);
  BIO_free(LBio);
  if (LKey = nil) or (SSL_CTX_use_PrivateKey(Result, LKey) <> 1) then
    raise ETlsBenchmarkError.Create('OpenSSL rejected the benchmark private key');
end;

class procedure TOpenSslBench.DrainBio(ASource, ADestination: PBIO;
  var AScratch: TBytes);
var
  LGot: Int32;
begin
  repeat
    LGot := BIO_read(ASource, @AScratch[0], System.Length(AScratch));
    if LGot > 0 then
      BIO_write(ADestination, @AScratch[0], LGot);
  until LGot <= 0;
end;

end.
