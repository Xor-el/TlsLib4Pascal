{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

{ A real-peer live-revocation cell: it handshakes with revoked.badssl.com and badssl.com to capture
  the chain each presents, then runs the actual driver-edge stack - TSocketHttpFetcher, verifying
  any https responder against OS trust, + TLiveRevocationChecker - against their real, live CRL
  endpoints, and asserts the
  revoked certificate comes back Revoked and the good one Good. The chains are captured at run time,
  so a certificate reissue cannot stale the cell. This is the network-gated counterpart to the
  fake-fetcher unit tests; it needs outbound TLS and HTTP. NOT part of the unit harness. Run returns
  0 on PASS, 1 on FAIL, 2 when a host cannot be reached.

  OCSP is being sunset across the ecosystem, so the cell checks the CRL-only Let's Encrypt certs;
  swap the method for a CA that still serves OCSP to exercise the OCSP path live. }

unit RealPeerRevocationProbeExample;

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

interface

uses
  SysUtils,
  TlpIClock,
  TlpClock,
  TlpIPkixProvider,
  TlpITlsConfig,
  TlpITlsConfigBuilder,
  TlpCertificateVerifierSource,
  TlpITlsTransport,
  TlpINetSocket,
  TlpNetExceptions,
  TlpNetSocket,
  TlpDefaultCryptoProvider,
  TlpDefaultPkixProvider,
  TlpTlsPresets,
  TlpTlsConnection,
  TlpIHttpFetcher,
  TlpSocketHttpFetcher,
  TlpSystemTrustFacade,
  TlpTrustPolicy,
  TlpLiveRevocation;

type
  /// <summary>Runs the live-CRL revocation cell against real endpoints; the thin program
  /// wrappers just Halt on its result.</summary>
  TRealPeerRevocationProbeExample = class sealed(TObject)
  strict private
    const
      FetchBudgetMs = Cardinal(20000);
      NetworkTimeoutMs = Int32(20000);
      HttpsPort = Word(443);
      RevokedHost = 'revoked.badssl.com';
      GoodHost = 'badssl.com';
    class function ClientConfig(const APkix: IPkixProvider): ITlsClientConfig; static;
    /// <summary>A fetcher whose https responders are verified against OS trust.</summary>
    class function Fetcher(const APkix: IPkixProvider): IHttpFetcher; static;
    /// <summary>The chain AHost presents, leaf first. False with AError set when the host cannot
    /// be reached; a failed handshake raises.</summary>
    class function TryCaptureChain(const AConfig: ITlsClientConfig; const AHost: string;
      out AChain: TArray<TBytes>; out AError: string): Boolean; static;
    class function OutcomeName(AOutcome: TLiveRevocationOutcome): string; static;
  public
    class function Run: Integer; static;
  end;

implementation

class function TRealPeerRevocationProbeExample.ClientConfig(
  const APkix: IPkixProvider): ITlsClientConfig;
var
  LBuilder: ITlsClientConfigBuilder;
begin
  LBuilder := TTlsPresets.Compatible(TDefaultCryptoProvider.Shared, APkix).Client;
  LBuilder.WithServerVerification(TServerVerification.DangerousSkip);
  Result := LBuilder.Build;
end;

class function TRealPeerRevocationProbeExample.Fetcher(const APkix: IPkixProvider): IHttpFetcher;
var
  LSettings: TSocketHttpFetcherSettings;
begin
  LSettings := TSocketHttpFetcherSettings.Defaults;
  // the fetcher's own TLS must not defer to live revocation, so it verifies inline
  LSettings.TlsConfig := TTlsPresets.Compatible(TDefaultCryptoProvider.Shared, APkix).Client
    .WithServerVerification(TSystemTrust.ServerVerification(APkix).Build).Build;
  Result := TSocketHttpFetcher.Create(LSettings);
end;

class function TRealPeerRevocationProbeExample.TryCaptureChain(
  const AConfig: ITlsClientConfig; const AHost: string; out AChain: TArray<TBytes>;
  out AError: string): Boolean;
var
  LConnector: ITcpConnector;
  LStream: ITlsTimedTransport;
  LConnection: TTlsConnection;
begin
  AChain := nil;
  AError := '';
  LConnector := TTcpConnector.Create(NetworkTimeoutMs) as ITcpConnector;
  try
    LStream := LConnector.Connect(AHost, HttpsPort);
  except
    on E: ENetConnectError do
    begin
      AError := E.Message;
      Exit(False);
    end;
  end;
  LConnection := TTlsConnection.CreateClient(AConfig, AHost, LStream, nil, 0);
  try
    LConnection.Handshake(NetworkTimeoutMs);
    AChain := TTlsConnection.InfoOf(LConnection).PeerCertificates;
    LConnection.CloseNotifyQuietly;
  finally
    LConnection.Free;
  end;
  Result := True;
end;

class function TRealPeerRevocationProbeExample.OutcomeName(
  AOutcome: TLiveRevocationOutcome): string;
begin
  case AOutcome of
    TLiveRevocationOutcome.Good:
      Result := 'Good';
    TLiveRevocationOutcome.Revoked:
      Result := 'Revoked';
  else
    Result := 'Indeterminate';
  end;
end;

class function TRealPeerRevocationProbeExample.Run: Integer;
var
  LPkix: IPkixProvider;
  LConfig: ITlsClientConfig;
  LFetcher: IHttpFetcher;
  LChecker: TLiveRevocationChecker;
  LRevokedChain, LGoodChain: TArray<TBytes>;
  LRevoked, LGood: TLiveRevocationOutcome;
  LError: string;
begin
  Result := 1;
  LPkix := TDefaultPkixProvider.Create;
  LConfig := ClientConfig(LPkix);
  try
    if not TryCaptureChain(LConfig, RevokedHost, LRevokedChain, LError) then
    begin
      WriteLn('real-peer probe SKIP: ', RevokedHost, ' unreachable (', LError, ')');
      Exit(2);
    end;
    if not TryCaptureChain(LConfig, GoodHost, LGoodChain, LError) then
    begin
      WriteLn('real-peer probe SKIP: ', GoodHost, ' unreachable (', LError, ')');
      Exit(2);
    end;
  except
    on E: Exception do
    begin
      WriteLn('real-peer live-CRL probe FAIL: ', E.Message);
      Exit;
    end;
  end;

  LFetcher := Fetcher(LPkix);
  // hard-fail posture over the live CRL distribution points
  LChecker := TLiveRevocationChecker.Create(LPkix, TSystemClock.Create as ITlsClock,
    TSystemMonotonicClock.Create as ITlsMonotonicClock, LFetcher, TRevocationPosture.Hard, TLiveRevocationMethod.Crl, FetchBudgetMs);
  try
    LRevoked := LChecker.Evaluate(LRevokedChain);
    LGood := LChecker.Evaluate(LGoodChain);

    WriteLn('revoked.badssl.com -> ', OutcomeName(LRevoked), ' (expected Revoked)');
    WriteLn('badssl.com         -> ', OutcomeName(LGood), ' (expected Good)');

    if (LRevoked = TLiveRevocationOutcome.Revoked) and
      (LGood = TLiveRevocationOutcome.Good) then
    begin
      WriteLn('real-peer live-CRL probe PASS');
      Result := 0;
    end
    else
      WriteLn('real-peer live-CRL probe FAIL');
  finally
    LChecker.Free;
  end;
end;

end.
