{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlsLibThroughputPeer;

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

interface

uses
  SysUtils,
  TlpICryptoProvider,
  TlpTlsPresets,
  TlpTlsVersion,
  TlpITlsConfigBuilder,
  TlpITlsConfig,
  TlpTlsEngineFactory,
  TlpITlsEngine,
  TlpINegotiation,
  TlpCipherSuiteRegistry,
  TlpNegotiationTypes,
  TlpCryptoAlgorithms,
  TlsBenchmarkData;

type
  /// <summary>
  /// The TlsLib side of the record-throughput benchmark. One hardened TLS 1.2 connection
  /// is established up front with a single AEAD suite pinned, then each SendOnce seals a
  /// fixed application-data payload on the client and opens it on the server over an
  /// in-memory pump - the record layer's steady-state seal+open cost for that suite.
  /// </summary>
  TTlsLibThroughputPeer = class sealed(TObject)
  strict private
  var
    FClient: ITlsEngine;
    FServer: ITlsEngine;
    FPayload: TBytes;
    FScratch: TBytes;
    FRecordSize: Int32;
    function BuildConfigs(const AProvider: ICryptoProvider;
      const ACredential: TTlsBenchmarkCredential; ASuiteCode: UInt16;
      out AClientConfig: ITlsClientConfig; out AServerConfig: ITlsServerConfig): Boolean;
  public
    constructor Create(const AProvider: ICryptoProvider;
      const ACredential: TTlsBenchmarkCredential; ASuiteCode: UInt16;
      ARecordSize, APayloadBytes: Int32);
    /// <summary>Bytes of application data moved per SendOnce (the throughput pass size).</summary>
    function PayloadBytes: Int64;
    /// <summary>Seal + deliver + open one payload over the established connection.</summary>
    procedure SendOnce;
  end;

implementation

const
  // a wide pull buffer keeps the seal->open pump to a few TakeOutgoing/ProcessInput calls
  CScratchBuffer = 65536;

function SingleSuiteRegistry(const AProvider: ICryptoProvider;
  ASuiteCode: UInt16): ICipherSuiteRegistry;
var
  LAll: ICipherSuiteRegistry;
  LSuite: TTlsCipherSuite;
begin
  LAll := TCipherSuiteRegistry.CreateDualVersion(AProvider);
  Result := TCipherSuiteRegistry.Create;
  if LAll.TryGet(ASuiteCode, LSuite) then
    Result.Add(LSuite);
end;

function OfferedGroups(const AProvider: ICryptoProvider;
  const ACredential: TTlsBenchmarkCredential): TArray<UInt16>;
var
  LKind: TCertKeyKind;
  LCurve: UInt16;
begin
  // X25519 for the ECDHE key exchange, plus the ECDSA leaf's curve (RFC 8422 5.4)
  if AProvider.Certificates.KeyKind(ACredential.LeafCertDer, LKind, LCurve)
    and (LKind = TCertKeyKind.Ecdsa) and (LCurve <> TNamedGroupCatalog.X25519) then
    Result := TArray<UInt16>.Create(TNamedGroupCatalog.X25519, LCurve)
  else
    Result := TArray<UInt16>.Create(TNamedGroupCatalog.X25519);
end;

function TTlsLibThroughputPeer.BuildConfigs(const AProvider: ICryptoProvider;
  const ACredential: TTlsBenchmarkCredential; ASuiteCode: UInt16;
  out AClientConfig: ITlsClientConfig; out AServerConfig: ITlsServerConfig): Boolean;
var
  LClientBuilder, LServerBuilder: ITlsConfigBuilder;
  LClient: ITlsClientConfigBuilder;
  LServer: ITlsServerConfigBuilder;
  LGroups: TArray<UInt16>;
begin
  LGroups := OfferedGroups(AProvider, ACredential);

  LClientBuilder := TTlsPresets.Compatible(AProvider);
  LClient := LClientBuilder.Client;
  LClient.WithSupportedVersions(TArray<UInt16>.Create(TlsWireVersionTls12));
  LClient.WithPreferredGroups(LGroups);
  LClient.WithCipherSuites(SingleSuiteRegistry(AProvider, ASuiteCode));
  LClient.WithDangerousInsecureSkipVerify(True);
  LClient.WithTrustAnchors(ACredential.RootCertDer);
  AClientConfig := LClient.Build;

  LServerBuilder := TTlsPresets.Compatible(AProvider);
  LServer := LServerBuilder.Server;
  LServer.WithSupportedVersions(TArray<UInt16>.Create(TlsWireVersionTls12));
  LServer.WithPreferredGroups(LGroups);
  LServer.WithCipherSuites(SingleSuiteRegistry(AProvider, ASuiteCode));
  LServer.WithCredential(ACredential.LeafCertDer, ACredential.LeafKeyDer);
  AServerConfig := LServer.Build;
  Result := True;
end;

constructor TTlsLibThroughputPeer.Create(const AProvider: ICryptoProvider;
  const ACredential: TTlsBenchmarkCredential; ASuiteCode: UInt16;
  ARecordSize, APayloadBytes: Int32);
var
  LClientConfig: ITlsClientConfig;
  LServerConfig: ITlsServerConfig;
  LGot, LRounds: Int32;
  LMoved: Boolean;
begin
  inherited Create;
  FRecordSize := ARecordSize;
  SetLength(FScratch, CScratchBuffer);
  SetLength(FPayload, APayloadBytes);

  BuildConfigs(AProvider, ACredential, ASuiteCode, LClientConfig, LServerConfig);
  FClient := TTlsEngineFactory.CreateClientEngine(LClientConfig, 'localhost');
  FServer := TTlsEngineFactory.CreateServerEngine(LServerConfig);

  // establish the connection once (handshake to completion) before any measured pass
  FClient.StartHandshake;
  LRounds := 0;
  repeat
    Inc(LRounds);
    LMoved := False;
    repeat
      LGot := FClient.TakeOutgoing(FScratch, 0);
      if LGot > 0 then
      begin
        LMoved := True;
        FServer.ProcessInput(FScratch, 0, LGot);
      end;
    until LGot = 0;
    repeat
      LGot := FServer.TakeOutgoing(FScratch, 0);
      if LGot > 0 then
      begin
        LMoved := True;
        FClient.ProcessInput(FScratch, 0, LGot);
      end;
    until LGot = 0;
  until ((not FClient.IsHandshaking) and (not FServer.IsHandshaking))
    or (not LMoved) or (LRounds > 64);

  if FClient.IsHandshaking or FServer.IsHandshaking then
    raise ETlsBenchmarkError.Create('TlsLib throughput handshake did not complete');
end;

function TTlsLibThroughputPeer.PayloadBytes: Int64;
begin
  Result := System.Length(FPayload);
end;

procedure TTlsLibThroughputPeer.SendOnce;
var
  LOffset, LChunk, LGot: Int32;
begin
  // seal the payload as records of FRecordSize (one Write -> one record), delivering each
  // to the server as it is produced so the outgoing buffer stays bounded
  LOffset := 0;
  while LOffset < System.Length(FPayload) do
  begin
    LChunk := System.Length(FPayload) - LOffset;
    if LChunk > FRecordSize then
      LChunk := FRecordSize;
    FClient.Write(FPayload, LOffset, LChunk);
    Inc(LOffset, LChunk);
    repeat
      LGot := FClient.TakeOutgoing(FScratch, 0);
      if LGot > 0 then
        FServer.ProcessInput(FScratch, 0, LGot);
    until LGot = 0;
  end;
  // open (decrypt) every delivered record
  repeat
    LGot := FServer.ReadAppData(FScratch, 0, System.Length(FScratch));
  until LGot = 0;
end;

end.
