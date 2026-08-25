{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit HkdfLabelTests;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  SysUtils,
  Classes,
{$IFDEF FPC}
  fpcunit,
  testregistry,
{$ELSE}
  TestFramework,
{$ENDIF FPC}
  TlpTlsLibExceptions,
  TlpISecretBuffer,
  TlpSecretBuffer,
  TlpICryptoProvider,
  TlpCryptoAlgorithms,
  TlpHkdfLabel,
  TlsLibTestBase;

type
  TTestHkdfLabel = class(TTlsLibAlgorithmTestCase)
  private
    function Hkdf: IHkdf;
  published
    procedure TestHkdfLabelEncoding;
    procedure TestHkdfExpandLabelRfc8448;
    procedure TestDeriveSecretRfc8448;
    procedure TestOverLengthLabelOrContextRaises;
  end;

implementation

{ TTestHkdfLabel }

function TTestHkdfLabel.Hkdf: IHkdf;
begin
  Result := Provider.Primitives.CreateHkdf(THashAlgorithm.SHA_256);
end;

procedure TTestHkdfLabel.TestHkdfLabelEncoding;
var
  LVec: TStringList;
begin
  LVec := LoadVectorFields('Rfc8448/HkdfLabel.txt');
  try
    CheckEqualBytes('key HkdfLabel', DecodeHex(LVec.Values['key_info']),
      THkdfLabel.BuildHkdfLabel('key', nil, 16));
    CheckEqualBytes('iv HkdfLabel', DecodeHex(LVec.Values['iv_info']),
      THkdfLabel.BuildHkdfLabel('iv', nil, 12));
    CheckEqualBytes('finished HkdfLabel', DecodeHex(LVec.Values['finished_info']),
      THkdfLabel.BuildHkdfLabel('finished', nil, 32));
    CheckEqualBytes('derived HkdfLabel', DecodeHex(LVec.Values['derived_info']),
      THkdfLabel.BuildHkdfLabel('derived', DecodeHex(LVec.Values['hash_empty']), 32));
  finally
    LVec.Free;
  end;
end;

procedure TTestHkdfLabel.TestHkdfExpandLabelRfc8448;
var
  LVec: TStringList;
  LHkdf: IHkdf;
  LSecret: ISecretBuffer;
begin
  LVec := LoadVectorFields('Rfc8448/HkdfLabel.txt');
  try
    LHkdf := Hkdf;
    LSecret := TSecretBuffer.From(DecodeHex(LVec.Values['server_hs_traffic']));
    CheckEqualBytes('key expanded', DecodeHex(LVec.Values['key_expanded']),
      THkdfLabel.HkdfExpandLabel(LHkdf, LSecret, 'key', nil, 16).ToBytes);
    CheckEqualBytes('iv expanded', DecodeHex(LVec.Values['iv_expanded']),
      THkdfLabel.HkdfExpandLabel(LHkdf, LSecret, 'iv', nil, 12).ToBytes);
    CheckEqualBytes('finished key', DecodeHex(LVec.Values['finished_key']),
      THkdfLabel.HkdfExpandLabel(LHkdf, LSecret, 'finished', nil, 32).ToBytes);
  finally
    LVec.Free;
  end;
end;

procedure TTestHkdfLabel.TestDeriveSecretRfc8448;
var
  LVec: TStringList;
  LSecret: ISecretBuffer;
begin
  LVec := LoadVectorFields('Rfc8448/HkdfLabel.txt');
  try
    LSecret := TSecretBuffer.From(DecodeHex(LVec.Values['early_secret']));
    CheckEqualBytes('Derive-Secret(early, derived, H(""))',
      DecodeHex(LVec.Values['derived_expanded']),
      THkdfLabel.DeriveSecret(Hkdf, LSecret, 'derived',
      DecodeHex(LVec.Values['hash_empty'])).ToBytes);
  finally
    LVec.Free;
  end;
end;

procedure TTestHkdfLabel.TestOverLengthLabelOrContextRaises;
var
  LBigContext: TBytes;
  LRaised: Boolean;
begin
  // an empty label leaves only the 6-byte "tls13 " prefix, below the 7-byte floor
  LRaised := False;
  try
    THkdfLabel.BuildHkdfLabel('', nil, 16);
  except
    on E: EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'too-short label rejected');

  // "tls13 " + 250 chars = 256 bytes, over the 255 label cap
  LRaised := False;
  try
    THkdfLabel.BuildHkdfLabel(StringOfChar('x', 250), nil, 16);
  except
    on E: EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'too-long label rejected');

  // a 256-byte context exceeds the 255 context cap
  LRaised := False;
  LBigContext := nil;
  SetLength(LBigContext, 256);
  try
    THkdfLabel.BuildHkdfLabel('key', LBigContext, 16);
  except
    on E: EArgumentTlsLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'too-long context rejected');
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestHkdfLabel);
{$ELSE}
  RegisterTest(TTestHkdfLabel.Suite);
{$ENDIF FPC}

end.
