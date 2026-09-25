{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit OpenSslThroughputPeer;

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
  /// The OpenSSL side of the record-throughput benchmark. One connection of the requested
  /// version (TLS 1.2 or 1.3) is established up front (a single AEAD cipher pinned) over a
  /// pair of memory BIOs, then each SendOnce SSL_writes a fixed payload on the client and
  /// SSL_reads it on the server - the OpenSSL record layer's steady-state seal+open cost,
  /// mirroring the TlsLib peer. AFeedSlice > 0 hands the sealed bytes to the server BIO in
  /// slices of that size, the same delivery pattern the TlsLib peer's sliced mode uses.
  /// </summary>
  TOpenSslThroughputPeer = class sealed(TObject)
  strict private
  var
    FClientCtx, FServerCtx: PSSL_CTX;
    FClient, FServer: PSSL;
    FClientWrite, FServerRead: PBIO;
    FPayload, FRecv, FScratch: TBytes;
    FRecordSize: Int32;
    FFeedSlice: Int32;
    procedure Deliver;
  public
    class function IsAvailable: Boolean; static;
    constructor Create(const ACredential: TTlsBenchmarkCredential; AWireVersion: UInt16;
      const ACipher, AGroups: string; ARecordSize, APayloadBytes, AFeedSlice: Int32);
    destructor Destroy; override;
    /// <summary>Seal + deliver + open one payload over the established connection.</summary>
    procedure SendOnce;
  end;

implementation

const
  CScratchBuffer = 65536;
  CMaxRounds = 64;

class function TOpenSslThroughputPeer.IsAvailable: Boolean;
begin
  Result := TOpenSslBench.Available;
end;

constructor TOpenSslThroughputPeer.Create(const ACredential: TTlsBenchmarkCredential;
  AWireVersion: UInt16; const ACipher, AGroups: string;
  ARecordSize, APayloadBytes, AFeedSlice: Int32);
var
  LClientRead, LServerWrite: PBIO;
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
        raise ETlsBenchmarkError.CreateFmt('OpenSSL throughput handshake error (%d)', [LErr]);
    end;
  end;

begin
  inherited Create;
  if not TOpenSslBench.Available then
    raise ETlsBenchmarkError.Create('OpenSSL libraries are not available');
  FRecordSize := ARecordSize;
  FFeedSlice := AFeedSlice;
  SetLength(FScratch, CScratchBuffer);
  SetLength(FRecv, CScratchBuffer);
  SetLength(FPayload, APayloadBytes);

  FClientCtx := TOpenSslBench.NewClientCtx(AWireVersion, ACipher, AGroups);
  FServerCtx := TOpenSslBench.NewServerCtx(ACredential, AWireVersion, ACipher, AGroups);

  FClient := SSL_new(FClientCtx);
  FServer := SSL_new(FServerCtx);
  LClientRead := BIO_new(BIO_s_mem());
  FClientWrite := BIO_new(BIO_s_mem());
  FServerRead := BIO_new(BIO_s_mem());
  LServerWrite := BIO_new(BIO_s_mem());
  SSL_set_bio(FClient, LClientRead, FClientWrite);
  SSL_set_bio(FServer, FServerRead, LServerWrite);

  LClientDone := False;
  LServerDone := False;
  LRounds := 0;
  repeat
    Inc(LRounds);
    if not LClientDone then
      Step(FClient, True, LClientDone);
    TOpenSslBench.DrainBio(FClientWrite, FServerRead, FScratch);
    if not LServerDone then
      Step(FServer, False, LServerDone);
    TOpenSslBench.DrainBio(LServerWrite, LClientRead, FScratch);
  until (LClientDone and LServerDone) or (LRounds > CMaxRounds);

  if not (LClientDone and LServerDone) then
    raise ETlsBenchmarkError.Create('OpenSSL throughput handshake did not complete');

  // a TLS 1.3 server queues its NewSessionTicket flight behind the handshake; consume it
  // now so no measured pass carries post-handshake traffic
  TOpenSslBench.DrainBio(LServerWrite, LClientRead, FScratch);
  repeat
    LRet := SSL_read(FClient, @FRecv[0], System.Length(FRecv));
  until LRet <= 0;
end;

destructor TOpenSslThroughputPeer.Destroy;
begin
  // SSL_free frees the BIOs it owns (set via SSL_set_bio)
  if FClient <> nil then
    SSL_free(FClient);
  if FServer <> nil then
    SSL_free(FServer);
  if FServerCtx <> nil then
    SSL_CTX_free(FServerCtx);
  if FClientCtx <> nil then
    SSL_CTX_free(FClientCtx);
  inherited Destroy;
end;

procedure TOpenSslThroughputPeer.Deliver;
var
  LGot, LOffset, LSlice: Int32;
begin
  if FFeedSlice <= 0 then
  begin
    TOpenSslBench.DrainBio(FClientWrite, FServerRead, FScratch);
    Exit;
  end;
  // the sliced delivery mirrors the TlsLib peer; a memory BIO simply concatenates the
  // slices, so this column is the reference for a record layer that a small-read
  // transport does not disturb
  repeat
    LGot := BIO_read(FClientWrite, @FScratch[0], System.Length(FScratch));
    LOffset := 0;
    while LOffset < LGot do
    begin
      LSlice := LGot - LOffset;
      if LSlice > FFeedSlice then
        LSlice := FFeedSlice;
      BIO_write(FServerRead, @FScratch[LOffset], LSlice);
      Inc(LOffset, LSlice);
    end;
  until LGot <= 0;
end;

procedure TOpenSslThroughputPeer.SendOnce;
var
  LOffset, LChunk, LGot: Int32;
begin
  // seal the payload as records of FRecordSize (one SSL_write -> one record), delivering
  // each to the server as it is produced
  LOffset := 0;
  while LOffset < System.Length(FPayload) do
  begin
    LChunk := System.Length(FPayload) - LOffset;
    if LChunk > FRecordSize then
      LChunk := FRecordSize;
    SSL_write(FClient, @FPayload[LOffset], LChunk);
    Inc(LOffset, LChunk);
    Deliver;
  end;
  // open (decrypt) every delivered record; SSL_read drains until WANT_READ (<= 0)
  repeat
    LGot := SSL_read(FServer, @FRecv[0], System.Length(FRecv));
  until LGot <= 0;
end;

end.
