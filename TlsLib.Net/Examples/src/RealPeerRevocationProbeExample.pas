{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

{ A real-peer live-revocation cell: it runs the actual driver-edge stack - TSocketHttpFetcher
  over the RTL HTTP client + TLiveRevocationChecker - against real, live CRL endpoints, and
  asserts a known-revoked certificate comes back Revoked and a known-good one Good. This is
  the network-gated counterpart to the fake-fetcher unit tests; it needs outbound HTTP and the
  captured certificates are cert-reissue-fragile (refresh the vector via the scratchpad capture
  when badssl.com rotates). NOT part of the unit harness. Run returns 0 on PASS, 1 on FAIL,
  2 when the vector is missing.

  OCSP is being sunset across the ecosystem, so the vector uses CRL-only Let's Encrypt certs;
  swap the method for a CA that still serves OCSP to exercise the OCSP path live. }

unit RealPeerRevocationProbeExample;

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

interface

uses
  SysUtils,
  Classes,
  TlpTrustPolicy,
  TlpLiveRevocation;

type
  /// <summary>Runs the live-CRL revocation cell against real endpoints; the thin program
  /// wrappers just Halt on its result.</summary>
  TRealPeerRevocationProbeExample = class sealed(TObject)
  strict private
    const
      FetchTimeoutMs = Cardinal(20000);
    /// <summary>Walks up from the executable directory to find the shared test vector, so the
    /// example runs from any build/output location - no machine-specific path.</summary>
    class function FindVector: string; static;
    class function LoadField(const AFields: TStringList;
      const AName: string): TBytes; static;
    class function OutcomeName(AOutcome: TLiveRevocationOutcome): string; static;
  public
    class function Run: Integer; static;
  end;

implementation

uses
  TlpDataEncoding,
  TlpIClock,
  TlpClock,
  TlpIPkixProvider,
  TlpDefaultPkixProvider,
  TlpIHttpFetcher,
  TlpSocketHttpFetcher;

{ TRealPeerRevocationProbeExample }

class function TRealPeerRevocationProbeExample.FindVector: string;
var
  LDir, LCandidate: string;
  LI: Int32;
begin
  Result := '';
  LDir := ExtractFileDir(ParamStr(0));
  for LI := 0 to 8 do
  begin
    LCandidate := IncludeTrailingPathDelimiter(LDir) + 'TlsLib.Tests' + PathDelim +
      'Data' + PathDelim + 'Certs' + PathDelim + 'RealPeerRevocation.txt';
    if FileExists(LCandidate) then
      Exit(LCandidate);
    LDir := ExtractFileDir(LDir);
    if LDir = '' then
      Break;
  end;
end;

class function TRealPeerRevocationProbeExample.LoadField(
  const AFields: TStringList; const AName: string): TBytes;
begin
  Result := TDataEncoding.HexDecode(AFields.Values[AName]);
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
  LFetcher: IHttpFetcher;
  LChecker: TLiveRevocationChecker;
  LFields: TStringList;
  LPath: string;
  LRevokedChain, LGoodChain: TArray<TBytes>;
  LRevoked, LGood: TLiveRevocationOutcome;
begin
  LPath := FindVector;
  if LPath = '' then
  begin
    WriteLn('real-peer probe SKIP: RealPeerRevocation.txt not found');
    Exit(2);
  end;

  Result := 1;
  LFields := TStringList.Create;
  LChecker := nil;
  try
    LFields.LoadFromFile(LPath);
    LRevokedChain := TArray<TBytes>.Create(LoadField(LFields, 'revoked_leaf'),
      LoadField(LFields, 'revoked_issuer'));
    LGoodChain := TArray<TBytes>.Create(LoadField(LFields, 'good_leaf'),
      LoadField(LFields, 'good_issuer'));

    LPkix := TDefaultPkixProvider.Create;
    LFetcher := TSocketHttpFetcher.Create;
    // hard-fail posture over the live CRL distribution points
    LChecker := TLiveRevocationChecker.Create(LPkix, TSystemClock.Create as ITlsClock,
      LFetcher, TRevocationPosture.Hard, TLiveRevocationMethod.Crl, FetchTimeoutMs);

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
    LFields.Free;
  end;
end;

end.
