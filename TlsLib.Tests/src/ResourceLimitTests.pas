{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit ResourceLimitTests;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  TlpIClock,
  TlpClock,
  SysUtils,
{$IFDEF FPC}
  fpcunit,
  testregistry,
{$ELSE}
  TestFramework,
{$ENDIF FPC}
  TlpTlsAlert,
  TlpTlsLibExceptions,
  TlpWireVectorMarker,
  TlpIWireWriter,
  TlpWireWriter,
  TlpHandshakeMessage,
  TlpExtensionContext,
  TlpITlsExtension,
  TlpExtensionBlockCodec,
  TlpCoreExtensions,
  TlpICertificateTrust,
  TlpTrustTypes,
  TlpServerName,
  TlpCertificateVerifier,
  TlpCertificateLimits,
  SupportCertificates,
  TlsLibTestBase;

type
  TTestResourceLimit = class(TTlsLibAlgorithmTestCase)
  private
    function ExtensionBlock(const ATypes: TArray<UInt16>): TBytes;
    function ConsumeAlert(const ABlock: TBytes;
      out AAlert: TTlsAlertDescription): Boolean;
    function JunkCert(ALength: Int32): TBytes;
    function VerifyChain(const AChain: TArray<TBytes>; const ALimits: TCertificateChainLimits;
      out AAlert: TTlsAlertDescription): Boolean;
  published
    procedure TestOverLengthHandshakeMessageRejected;
    procedure TestHandshakeReassemblyOverflowRejected;
    procedure TestDuplicateExtensionRejected;
    procedure TestExtensionCountFloodRejected;
    procedure TestCertificateOverPerCertificateCapRejected;
    procedure TestCertificateAtPerCertificateCapAccepted;
    procedure TestChainOverTotalCapRejected;
    procedure TestChainAtTotalCapAccepted;
  end;

implementation

{ TTestResourceLimit }

function TTestResourceLimit.ExtensionBlock(
  const ATypes: TArray<UInt16>): TBytes;
var
  LWriter: IWireWriter;
  LMarker: TWireVectorMarker;
  LType: UInt16;
begin
  LWriter := TWireWriter.Create;
  LMarker := LWriter.OpenVector(2);
  for LType in ATypes do
  begin
    LWriter.WriteUInt16(LType);
    LWriter.WriteUInt16(0); // empty extension_data
  end;
  LWriter.CloseVector(LMarker);
  Result := LWriter.ToBytes;
end;

function TTestResourceLimit.ConsumeAlert(const ABlock: TBytes;
  out AAlert: TTlsAlertDescription): Boolean;
var
  LCodec: IExtensionBlockCodec;
  LContext: TExtensionContext;
begin
  Result := False;
  AAlert := TTlsAlertDescription.CloseNotify;
  LCodec := TExtensionBlockCodec.Create(TCoreExtensions.CreateDefaultRegistry)
    as IExtensionBlockCodec;
  LContext := TExtensionContext.Create;
  try
    try
      LCodec.ConsumeBlock(LContext, TTlsExtensionContextKind.ClientHello, ABlock);
    except
      on E: EDecodeErrorTlsLibException do
      begin
        AAlert := TTlsAlertDescription.DecodeError;
        Result := True;
      end;
      on E: EFatalAlertTlsLibException do
      begin
        AAlert := E.AlertDescription;
        Result := True;
      end;
    end;
  finally
    LContext.Free;
  end;
end;

function TTestResourceLimit.JunkCert(ALength: Int32): TBytes;
begin
  Result := nil;
  SetLength(Result, ALength);
  if ALength > 0 then
    FillChar(Result[0], ALength, $41);
end;

// a real chain under the real root, so only a cap in ALimits can refuse it
function TTestResourceLimit.VerifyChain(const AChain: TArray<TBytes>;
  const ALimits: TCertificateChainLimits; out AAlert: TTlsAlertDescription): Boolean;
var
  LOptions: TCertificateVerifierOptions;
  LVerifier: IServerCertificateVerifier;
  LVerified: TVerifiedChain;
begin
  LOptions.ChainLimits := ALimits;
  LVerifier := TCertificateVerifier.Create(Pkix, TSystemClock.Create as ITlsClock,
    TSupportCertificates.EcP256RootStore, True, LOptions) as IServerCertificateVerifier;
  Result := LVerifier.VerifyServerCertificate(AChain,
    TServerName.DnsName('localhost'), nil, LVerified, AAlert);
end;

procedure TTestResourceLimit.TestOverLengthHandshakeMessageRejected;
var
  LReader: THandshakeMessageReader;
  LMsg: TTlsHandshakeMessage;
  LHeader: TBytes;
  LRaised: Boolean;
begin
  // a handshake header declaring a body above the per-message cap is decode_error
  // before the body is buffered: type 11, uint24 length 0x020000 (> 2^16)
  LReader := THandshakeMessageReader.Create;
  try
    LHeader := DecodeHex('0B020000');
    LReader.Append(LHeader, 0, System.Length(LHeader));
    LRaised := False;
    try
      LReader.NextMessage(LMsg);
    except
      on E: EDecodeErrorTlsLibException do
        LRaised := True;
    end;
    CheckTrue(LRaised, 'an over-length handshake message is rejected');
  finally
    LReader.Free;
  end;
end;

procedure TTestResourceLimit.TestHandshakeReassemblyOverflowRejected;
var
  LReader: THandshakeMessageReader;
  LChunk: TBytes;
  LRaised: Boolean;
  LI: Int32;
begin
  // a flood that never completes a message cannot grow the reassembly buffer without
  // bound: appending past the total cap is decode_error
  LReader := THandshakeMessageReader.Create;
  try
    LReader.MaxTotalLength := 4096;
    LChunk := JunkCert(1024);
    LRaised := False;
    try
      for LI := 0 to 7 do
        LReader.Append(LChunk, 0, System.Length(LChunk));
    except
      on E: EDecodeErrorTlsLibException do
        LRaised := True;
    end;
    CheckTrue(LRaised, 'the reassembly buffer is bounded');
  finally
    LReader.Free;
  end;
end;

procedure TTestResourceLimit.TestDuplicateExtensionRejected;
var
  LAlert: TTlsAlertDescription;
begin
  // two extensions of the same (unknown) type in one block (RFC 9846 4.3): a repeated type is
  // rejected structurally with illegal_parameter
  CheckTrue(ConsumeAlert(ExtensionBlock(TArray<UInt16>.Create($FF00, $FF00)), LAlert),
    'a duplicate extension aborts');
  CheckTrue(LAlert = TTlsAlertDescription.IllegalParameter,
    'a duplicate extension is illegal_parameter');
end;

procedure TTestResourceLimit.TestExtensionCountFloodRejected;
var
  LTypes: TArray<UInt16>;
  LAlert: TTlsAlertDescription;
  LI: Int32;
begin
  // 65 distinct (unknown) extensions exceed the per-block cap
  LTypes := nil;
  SetLength(LTypes, 65);
  for LI := 0 to 64 do
    LTypes[LI] := UInt16($FF00 + LI);
  CheckTrue(ConsumeAlert(ExtensionBlock(LTypes), LAlert),
    'an extension-count flood aborts');
  CheckTrue(LAlert = TTlsAlertDescription.DecodeError,
    'an extension-count flood is decode_error');
end;

procedure TTestResourceLimit.TestCertificateOverPerCertificateCapRejected;
var
  LLeaf: TBytes;
  LLimits: TCertificateChainLimits;
  LAlert: TTlsAlertDescription;
begin
  // only this cap is tightened, so it alone refuses an otherwise valid certificate
  LLeaf := TSupportCertificates.Field('Certs/EcP256Chain.txt', 'leaf_cert');
  LLimits := TCertificateChainLimits.Defaults;
  LLimits.MaxCertificateLength := System.Length(LLeaf) - 1;
  CheckFalse(VerifyChain(TArray<TBytes>.Create(LLeaf), LLimits, LAlert),
    'a certificate one byte over the cap aborts');
  CheckTrue(LAlert = TTlsAlertDescription.BadCertificate,
    'an over-cap certificate is bad_certificate');
end;

procedure TTestResourceLimit.TestCertificateAtPerCertificateCapAccepted;
var
  LLeaf: TBytes;
  LLimits: TCertificateChainLimits;
  LAlert: TTlsAlertDescription;
begin
  // the control for the cap test above: the same leaf at exactly the cap verifies
  LLeaf := TSupportCertificates.Field('Certs/EcP256Chain.txt', 'leaf_cert');
  LLimits := TCertificateChainLimits.Defaults;
  LLimits.MaxCertificateLength := System.Length(LLeaf);
  CheckTrue(VerifyChain(TArray<TBytes>.Create(LLeaf), LLimits, LAlert),
    'a certificate exactly at the cap verifies');
end;

procedure TTestResourceLimit.TestChainOverTotalCapRejected;
var
  LChain: TArray<TBytes>;
  LLimits: TCertificateChainLimits;
  LAlert: TTlsAlertDescription;
begin
  // each certificate is under the per-certificate cap, so only the summed total can refuse it
  LChain := TArray<TBytes>.Create(
    TSupportCertificates.Field('Certs/EcP256Chain.txt', 'leaf_cert'),
    TSupportCertificates.Field('Certs/EcP256Chain.txt', 'root_cert'));
  LLimits := TCertificateChainLimits.Defaults;
  LLimits.MaxTotalChainLength := System.Length(LChain[0]) + System.Length(LChain[1]) - 1;
  CheckFalse(VerifyChain(LChain, LLimits, LAlert), 'a chain one byte over the total cap aborts');
  CheckTrue(LAlert = TTlsAlertDescription.BadCertificate,
    'an over-total chain is bad_certificate');
end;

procedure TTestResourceLimit.TestChainAtTotalCapAccepted;
var
  LChain: TArray<TBytes>;
  LLimits: TCertificateChainLimits;
  LAlert: TTlsAlertDescription;
begin
  LChain := TArray<TBytes>.Create(
    TSupportCertificates.Field('Certs/EcP256Chain.txt', 'leaf_cert'),
    TSupportCertificates.Field('Certs/EcP256Chain.txt', 'root_cert'));
  LLimits := TCertificateChainLimits.Defaults;
  LLimits.MaxTotalChainLength := System.Length(LChain[0]) + System.Length(LChain[1]);
  CheckTrue(VerifyChain(LChain, LLimits, LAlert), 'a chain exactly at the total cap verifies');
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestResourceLimit);
{$ELSE}
  RegisterTest(TTestResourceLimit.Suite);
{$ENDIF FPC}

end.
