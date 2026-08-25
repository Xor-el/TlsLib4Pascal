{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlsLibHandshakePeer;

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

interface

uses
  SysUtils,
  TlpICryptoProvider,
  TlpTlsPresets,
  TlpITlsConfigBuilder,
  TlpITlsConfig,
  TlpTlsEngineFactory,
  TlpITlsEngine,
  TlpCryptoAlgorithms,
  TlsBenchmarkData;

type
  /// <summary>
  /// The TlsLib side of the handshake benchmark. The two frozen configs (client +
  /// server) are built once - the reusable, per-process setup, analogous to an OpenSSL
  /// SSL_CTX - and each RunOneHandshake creates a fresh engine pair and drives a full
  /// 1-RTT handshake to completion over an in-memory pump (no sockets), analogous to
  /// SSL_new + the handshake. Peer-certificate PKIX validation is disabled on the client
  /// (WithDangerousInsecureSkipVerify) so the measurement isolates the handshake proper -
  /// the ECDHE key exchange plus the ECDSA-P256 CertificateVerify - matching the OpenSSL
  /// peer's SSL_VERIFY_NONE. The offered version and ECDHE group are pinned on both ends.
  /// </summary>
  TTlsLibHandshakePeer = class sealed(TObject)
  strict private
  var
    FClientConfig: ITlsClientConfig;
    FServerConfig: ITlsServerConfig;
    FScratch: TBytes;
    /// <summary>The ECDHE group to benchmark, plus the leaf certificate's own curve when it
    /// differs: an ECDSA leaf's curve must appear in supported_groups (RFC 8422 5.4) whatever
    /// the negotiated ECDHE group. ACertGroup is 0 for a non-ECDSA leaf (no such constraint).</summary>
    class function OfferedGroups(AGroupCode, ACertGroup: UInt16): TArray<UInt16>; static;
    /// <summary>Drains everything ASrc has queued into ADst; True if any bytes moved.</summary>
    function Pump(const ASrc, ADst: ITlsEngine): Boolean;
  public
    constructor Create(const AProvider: ICryptoProvider;
      const ACredential: TTlsBenchmarkCredential; AWireVersion, AGroupCode: UInt16);
    /// <summary>One complete client+server handshake; raises on a non-completing exchange.</summary>
    procedure RunOneHandshake;
  end;

implementation

const
  // one TLS record's ciphertext never exceeds ~2^14 + overhead; a 16 KiB pull buffer
  // takes each flight in as few TakeOutgoing calls as the record layer allows
  CPumpBuffer = 16384;
  // a completed 1-RTT handshake never needs anywhere near this many pump rounds; the cap
  // only turns a hung exchange (a misconfiguration) into a raise instead of a spin
  CMaxRounds = 64;

class function TTlsLibHandshakePeer.OfferedGroups(AGroupCode,
  ACertGroup: UInt16): TArray<UInt16>;
begin
  if (ACertGroup = 0) or (ACertGroup = AGroupCode) then
    Result := TArray<UInt16>.Create(AGroupCode)
  else
    Result := TArray<UInt16>.Create(AGroupCode, ACertGroup);
end;

constructor TTlsLibHandshakePeer.Create(const AProvider: ICryptoProvider;
  const ACredential: TTlsBenchmarkCredential; AWireVersion, AGroupCode: UInt16);
var
  LClientBuilder: ITlsConfigBuilder;
  LServerBuilder: ITlsConfigBuilder;
  LClient: ITlsClientConfigBuilder;
  LServer: ITlsServerConfigBuilder;
  LKind: TCertKeyKind;
  LCertCurve, LCertGroup: UInt16;
begin
  inherited Create;
  SetLength(FScratch, CPumpBuffer);

  // the leaf's own curve (RFC 8422 5.4 fallback), read from the certificate so the peer is
  // not tied to one curve; 0 (offer nothing extra) for a non-ECDSA leaf
  LCertGroup := 0;
  if AProvider.Certificates.KeyKind(ACredential.LeafCertDer, LKind, LCertCurve)
    and (LKind = TCertKeyKind.Ecdsa) then
    LCertGroup := LCertCurve;

  // hold the builder in an interface local while configuring: the facets keep only a raw
  // back-reference, so a captured owner is what refcounts and frees it after Build
  LClientBuilder := TTlsPresets.Compatible(AProvider);
  LClient := LClientBuilder.Client;
  LClient.WithSupportedVersions(TArray<UInt16>.Create(AWireVersion));
  LClient.WithPreferredGroups(OfferedGroups(AGroupCode, LCertGroup));
  LClient.WithDangerousInsecureSkipVerify(True);
  LClient.WithTrustAnchors(ACredential.RootCertDer); // a trust source is still required by Build
  FClientConfig := LClient.Build;

  LServerBuilder := TTlsPresets.Compatible(AProvider);
  LServer := LServerBuilder.Server;
  LServer.WithSupportedVersions(TArray<UInt16>.Create(AWireVersion));
  LServer.WithPreferredGroups(OfferedGroups(AGroupCode, LCertGroup)); // AGroupCode first -> negotiated
  LServer.WithCredential(ACredential.LeafCertDer, ACredential.LeafKeyDer);
  FServerConfig := LServer.Build;
end;

function TTlsLibHandshakePeer.Pump(const ASrc, ADst: ITlsEngine): Boolean;
var
  LGot: Int32;
begin
  Result := False;
  repeat
    LGot := ASrc.TakeOutgoing(FScratch, 0);
    if LGot > 0 then
    begin
      Result := True;
      if ADst.ProcessInput(FScratch, 0, LGot) = TTlsOutcome.Fatal then
        raise ETlsBenchmarkError.Create('TlsLib handshake did not complete');
    end;
  until LGot = 0;
end;

procedure TTlsLibHandshakePeer.RunOneHandshake;
var
  LClient, LServer: ITlsEngine;
  LRounds: Int32;
  LMoved: Boolean;
begin
  LClient := TTlsEngineFactory.CreateClientEngine(FClientConfig, 'localhost');
  LServer := TTlsEngineFactory.CreateServerEngine(FServerConfig);
  LClient.StartHandshake;

  LRounds := 0;
  repeat
    Inc(LRounds);
    LMoved := Pump(LClient, LServer);
    LMoved := Pump(LServer, LClient) or LMoved;
  until ((not LClient.IsHandshaking) and (not LServer.IsHandshaking))
    or (not LMoved) or (LRounds > CMaxRounds);

  if LClient.IsHandshaking or LServer.IsHandshaking then
    raise ETlsBenchmarkError.Create('TlsLib handshake did not complete');
end;

end.
