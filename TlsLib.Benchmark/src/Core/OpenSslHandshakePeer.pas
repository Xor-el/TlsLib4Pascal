{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit OpenSslHandshakePeer;

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

interface

uses
  SysUtils,
  mormot.lib.openssl11,
  OpenSslBenchSupport,
  TlsBenchmarkData;

type
  /// <summary>
  /// The OpenSSL reference side of the handshake benchmark, driven entirely in memory.
  /// Two SSL_CTX (client + server) are built once with the version and supported groups
  /// pinned and the EC credential loaded into the server, and each RunOneHandshake wires a
  /// fresh SSL pair to a pair of memory BIOs and pumps a full handshake to completion,
  /// mirroring the TlsLib peer. The client keeps OpenSSL's default (no peer verification).
  /// </summary>
  TOpenSslHandshakePeer = class sealed(TObject)
  strict private
  var
    FClientCtx: PSSL_CTX;
    FServerCtx: PSSL_CTX;
    FScratch: TBytes;
  public
    /// <summary>True when the OpenSSL libraries loaded.</summary>
    class function IsAvailable: Boolean; static;
    constructor Create(const ACredential: TTlsBenchmarkCredential;
      AWireVersion: UInt16; const AGroups: string);
    destructor Destroy; override;
    /// <summary>One complete client+server handshake; raises on a non-completing exchange.</summary>
    procedure RunOneHandshake;
  end;

implementation

const
  CScratchBuffer = 16384;
  CMaxRounds = 64;
  // pin an ECDHE AEAD for the 1.2 rows matching the leaf's key type (the 1.3 suite set is
  // negotiated from the fixed 1.3 ciphers); the AEAD choice is irrelevant to handshake cost
  CCipherTls12Ecdsa = 'ECDHE-ECDSA-AES128-GCM-SHA256';
  CCipherTls12Rsa = 'ECDHE-RSA-AES128-GCM-SHA256';

class function TOpenSslHandshakePeer.IsAvailable: Boolean;
begin
  Result := TOpenSslBench.Available;
end;

constructor TOpenSslHandshakePeer.Create(const ACredential: TTlsBenchmarkCredential;
  AWireVersion: UInt16; const AGroups: string);
var
  LCipher: string;
begin
  inherited Create;
  if not TOpenSslBench.Available then
    raise ETlsBenchmarkError.Create('OpenSSL libraries are not available');
  SetLength(FScratch, CScratchBuffer);
  if AWireVersion <> TLS1_2_VERSION then
    LCipher := ''
  else if ACredential.IsRsaLeaf then
    LCipher := CCipherTls12Rsa
  else
    LCipher := CCipherTls12Ecdsa;
  FClientCtx := TOpenSslBench.NewClientCtx(AWireVersion, LCipher, AGroups);
  FServerCtx := TOpenSslBench.NewServerCtx(ACredential, AWireVersion, LCipher, AGroups);
end;

destructor TOpenSslHandshakePeer.Destroy;
begin
  if FServerCtx <> nil then
    SSL_CTX_free(FServerCtx);
  if FClientCtx <> nil then
    SSL_CTX_free(FClientCtx);
  inherited Destroy;
end;

procedure TOpenSslHandshakePeer.RunOneHandshake;
var
  LClient, LServer: PSSL;
  LClientRead, LClientWrite, LServerRead, LServerWrite: PBIO;
  LRounds, LRet, LErr: Int32;
  LClientDone, LServerDone: Boolean;

  procedure Step(ASsl: PSSL; AConnect: Boolean; var ADone: Boolean);
  begin
    if AConnect then
      LRet := SSL_connect(ASsl)
    else
      LRet := SSL_accept(ASsl);
    if LRet = 1 then
      ADone := True
    else
    begin
      LErr := SSL_get_error(ASsl, LRet);
      if (LErr <> SSL_ERROR_WANT_READ) and (LErr <> SSL_ERROR_WANT_WRITE) then
        raise ETlsBenchmarkError.CreateFmt('OpenSSL handshake error (%d)', [LErr]);
    end;
  end;

begin
  LClient := SSL_new(FClientCtx);
  LServer := SSL_new(FServerCtx);
  LClientRead := BIO_new(BIO_s_mem());
  LClientWrite := BIO_new(BIO_s_mem());
  LServerRead := BIO_new(BIO_s_mem());
  LServerWrite := BIO_new(BIO_s_mem());
  // SSL_set_bio hands ownership of both BIOs to the SSL, so SSL_free frees them
  SSL_set_bio(LClient, LClientRead, LClientWrite);
  SSL_set_bio(LServer, LServerRead, LServerWrite);

  LClientDone := False;
  LServerDone := False;
  LRounds := 0;
  try
    repeat
      Inc(LRounds);
      if not LClientDone then
        Step(LClient, True, LClientDone);
      TOpenSslBench.DrainBio(LClientWrite, LServerRead, FScratch); // client -> server
      if not LServerDone then
        Step(LServer, False, LServerDone);
      TOpenSslBench.DrainBio(LServerWrite, LClientRead, FScratch); // server -> client
    until (LClientDone and LServerDone) or (LRounds > CMaxRounds);

    if not (LClientDone and LServerDone) then
      raise ETlsBenchmarkError.Create('OpenSSL handshake did not complete');
  finally
    SSL_free(LClient);
    SSL_free(LServer);
  end;
end;

end.
