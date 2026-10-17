{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit Pkcs12IdentityTests;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  SysUtils,
{$IFDEF FPC}
  fpcunit,
  testregistry,
{$ELSE}
  TestFramework,
{$ENDIF FPC}
  TlpISigningKey,
  TlpImportedCredential,
  TlpPkcs12Identity,
  MockCryptoProvider,
  TlsLibTestBase;

type
  /// <summary>The shared PKCS#12 credential policy over hand-built store contents: key count,
  /// leaf selection and the issuer-name chain walk. No crypto and no store parsing, so it runs
  /// the same on every platform.</summary>
  TTestPkcs12Identity = class(TTlsLibAlgorithmTestCase)
  strict private
    // A certificate whose DER is 30 AId and whose Subject and Issuer are the one byte each.
    function Cert(AId, ASubject, AIssuer: Byte): TPkcs12Certificate;
    // A key (an opaque double) linked to ALinked and paired with the certificates APairs.
    function KeyOf(ALinked: Int32; const APairs: array of Int32): TPkcs12Key;
    // The hex DER of each chain entry, comma-separated, leaf first.
    function ChainOf(const ACredential: TImportedCredential): string;
    // The class and message Select raises over AContents, empty when it returns.
    function SelectFailure(const AContents: TPkcs12Contents): string;
  published
    procedure TestZeroKeysRaisesNoKeyEntry;
    procedure TestTwoKeysRaisesMultipleKeys;
    procedure TestUnpairedKeyRaisesNoCertForKey;
    procedure TestLinkedPairingCertIsLeaf;
    procedure TestWrongLinkFallsBackToPairingCert;
    procedure TestLeafTieBreakIsDerOrder;
    procedure TestLeafTieBreakIgnoresPairsOrder;
    procedure TestLeafTieBreakIsUnsignedByteOrder;
    procedure TestChainIsLeafFirstByName;
    procedure TestChainStopsAtSelfIssued;
    procedure TestChainDropsSecondRootWithSameName;
    procedure TestChainCycleTerminates;
    procedure TestChainIssuerTieGoesToLowestDer;
    procedure TestUnrelatedCertsDropped;
    procedure TestSelectedCredentialCarriesTheKey;
  end;

implementation

{ TTestPkcs12Identity }

function TTestPkcs12Identity.Cert(AId, ASubject, AIssuer: Byte): TPkcs12Certificate;
begin
  Result.Der := TBytes.Create($30, AId);
  Result.Subject := TBytes.Create(ASubject);
  Result.Issuer := TBytes.Create(AIssuer);
end;

function TTestPkcs12Identity.KeyOf(ALinked: Int32; const APairs: array of Int32): TPkcs12Key;
var
  LI: Int32;
begin
  Result.Key := TMockSigningKey.Create as ISigningKey;
  Result.Linked := ALinked;
  SetLength(Result.Pairs, System.Length(APairs));
  for LI := 0 to System.High(APairs) do
    Result.Pairs[LI] := APairs[LI];
end;

function TTestPkcs12Identity.ChainOf(const ACredential: TImportedCredential): string;
var
  LI: Int32;
begin
  Result := '';
  for LI := 0 to System.High(ACredential.CertificateChain) do
  begin
    if LI > 0 then
      Result := Result + ',';
    Result := Result + EncodeHex(ACredential.CertificateChain[LI]);
  end;
end;

function TTestPkcs12Identity.SelectFailure(const AContents: TPkcs12Contents): string;
begin
  Result := '';
  try
    TPkcs12Identity.Select(AContents);
  except
    on E: Exception do
      Result := E.ClassName + ': ' + E.Message;
  end;
end;

procedure TTestPkcs12Identity.TestZeroKeysRaisesNoKeyEntry;
var
  LContents: TPkcs12Contents;
begin
  LContents.Certificates := TArray<TPkcs12Certificate>.Create(Cert(1, 1, 1));
  CheckEquals('EArgumentTlsLibException: the PKCS#12 blob holds no private-key entry',
    SelectFailure(LContents), 'a store with certificates and no key has no key entry');
end;

procedure TTestPkcs12Identity.TestTwoKeysRaisesMultipleKeys;
var
  LContents: TPkcs12Contents;
  LFailure: string;
begin
  LContents.Certificates := TArray<TPkcs12Certificate>.Create(Cert(1, 1, 1), Cert(2, 2, 2));
  LContents.Keys := TArray<TPkcs12Key>.Create(KeyOf(0, [0]), KeyOf(1, [1]));
  LFailure := SelectFailure(LContents);
  CheckEquals(1, Pos('EArgumentTlsLibException: the PKCS#12 blob holds more than one ' +
    'private-key entry', LFailure), 'two keys are ambiguous for one credential; got: ' + LFailure);
end;

procedure TTestPkcs12Identity.TestUnpairedKeyRaisesNoCertForKey;
var
  LContents: TPkcs12Contents;
begin
  LContents.Certificates := TArray<TPkcs12Certificate>.Create(Cert(1, 1, 1));
  LContents.Keys := TArray<TPkcs12Key>.Create(KeyOf(-1, []));
  CheckEquals('EArgumentTlsLibException: the PKCS#12 blob holds no certificate for its ' +
    'private key', SelectFailure(LContents), 'a key no certificate pairs has no leaf');
end;

procedure TTestPkcs12Identity.TestLinkedPairingCertIsLeaf;
var
  LContents: TPkcs12Contents;
begin
  // the second certificate has the lower DER, so only the link can make the first the leaf
  LContents.Certificates := TArray<TPkcs12Certificate>.Create(Cert(5, 5, 5), Cert(3, 3, 3));
  LContents.Keys := TArray<TPkcs12Key>.Create(KeyOf(0, [0, 1]));
  CheckEquals('3005', ChainOf(TPkcs12Identity.Select(LContents)),
    'the linked certificate is the leaf when it pairs the key');
end;

procedure TTestPkcs12Identity.TestWrongLinkFallsBackToPairingCert;
var
  LContents: TPkcs12Contents;
begin
  // the link points at the CA, which does not pair the key: the pairing certificate is the leaf
  LContents.Certificates := TArray<TPkcs12Certificate>.Create(Cert(1, 9, 9), Cert(7, 1, 9));
  LContents.Keys := TArray<TPkcs12Key>.Create(KeyOf(0, [1]));
  CheckEquals('3007,3001', ChainOf(TPkcs12Identity.Select(LContents)),
    'a link to a certificate that does not pair the key is ignored');
end;

procedure TTestPkcs12Identity.TestLeafTieBreakIsDerOrder;
var
  LContents: TPkcs12Contents;
begin
  // all three pair the key, none linked: lowest DER wins, and a prefix sorts first
  LContents.Certificates := TArray<TPkcs12Certificate>.Create(Cert(5, 1, 1), Cert(3, 2, 2),
    Cert(3, 3, 3));
  LContents.Certificates[2].Der := TBytes.Create($30, 3, 1);
  LContents.Keys := TArray<TPkcs12Key>.Create(KeyOf(-1, [0, 1, 2]));
  CheckEquals('3003', ChainOf(TPkcs12Identity.Select(LContents)),
    'the lowest DER among the pairing certificates is the leaf');
end;

procedure TTestPkcs12Identity.TestLeafTieBreakIgnoresPairsOrder;
var
  LContents: TPkcs12Contents;
begin
  LContents.Certificates := TArray<TPkcs12Certificate>.Create(Cert(5, 1, 1), Cert(3, 2, 2),
    Cert(4, 3, 3));
  LContents.Keys := TArray<TPkcs12Key>.Create(KeyOf(-1, [2, 0, 1]));
  CheckEquals('3003', ChainOf(TPkcs12Identity.Select(LContents)),
    'the leaf does not depend on the order the backend listed the pairing certificates');
end;

procedure TTestPkcs12Identity.TestChainIsLeafFirstByName;
var
  LContents: TPkcs12Contents;
begin
  // enumerated root first, then intermediate, then leaf
  LContents.Certificates := TArray<TPkcs12Certificate>.Create(Cert(1, 3, 3), Cert(2, 2, 3),
    Cert(3, 1, 2));
  LContents.Keys := TArray<TPkcs12Key>.Create(KeyOf(2, [2]));
  CheckEquals('3003,3002,3001', ChainOf(TPkcs12Identity.Select(LContents)),
    'the chain is the leaf then each issuer in turn, not the store order');
end;

procedure TTestPkcs12Identity.TestLeafTieBreakIsUnsignedByteOrder;
var
  LContents: TPkcs12Contents;
begin
  LContents.Certificates := TArray<TPkcs12Certificate>.Create(Cert(1, 1, 1), Cert(2, 2, 2));
  LContents.Certificates[0].Der := TBytes.Create($30, $80);
  LContents.Certificates[1].Der := TBytes.Create($30, $7F);
  LContents.Keys := TArray<TPkcs12Key>.Create(KeyOf(-1, [0, 1]));
  CheckEquals('307F', ChainOf(TPkcs12Identity.Select(LContents)),
    'DER byte order is unsigned, so 7F sorts before 80');
end;

procedure TTestPkcs12Identity.TestChainStopsAtSelfIssued;
var
  LContents: TPkcs12Contents;
begin
  // the self-issued leaf is the whole chain though another certificate has its name and a lower DER
  LContents.Certificates := TArray<TPkcs12Certificate>.Create(Cert(5, 1, 1), Cert(2, 1, 1));
  LContents.Keys := TArray<TPkcs12Key>.Create(KeyOf(0, [0]));
  CheckEquals('3005', ChainOf(TPkcs12Identity.Select(LContents)),
    'the walk does not leave a self-issued certificate');
end;

procedure TTestPkcs12Identity.TestChainDropsSecondRootWithSameName;
var
  LContents: TPkcs12Contents;
begin
  // a second self-issued certificate with the root's name must not extend the chain past the root
  LContents.Certificates := TArray<TPkcs12Certificate>.Create(Cert(1, 1, 2), Cert(4, 2, 2),
    Cert(9, 2, 2));
  LContents.Keys := TArray<TPkcs12Key>.Create(KeyOf(0, [0]));
  CheckEquals('3001,3004', ChainOf(TPkcs12Identity.Select(LContents)),
    'the walk ends at the self-issued certificate');
end;

procedure TTestPkcs12Identity.TestChainCycleTerminates;
var
  LContents: TPkcs12Contents;
begin
  // each names the other as its issuer
  LContents.Certificates := TArray<TPkcs12Certificate>.Create(Cert(1, 1, 2), Cert(2, 2, 1));
  LContents.Keys := TArray<TPkcs12Key>.Create(KeyOf(0, [0]));
  CheckEquals('3001,3002', ChainOf(TPkcs12Identity.Select(LContents)),
    'an issuer cycle ends before a certificate repeats');
end;

procedure TTestPkcs12Identity.TestChainIssuerTieGoesToLowestDer;
var
  LContents: TPkcs12Contents;
begin
  // two self-issued certificates carry the leaf's issuer name
  LContents.Certificates := TArray<TPkcs12Certificate>.Create(Cert(1, 1, 2), Cert(8, 2, 2),
    Cert(3, 2, 2));
  LContents.Keys := TArray<TPkcs12Key>.Create(KeyOf(0, [0]));
  CheckEquals('3001,3003', ChainOf(TPkcs12Identity.Select(LContents)),
    'the lowest DER among the certificates with the issuer name is the issuer');
end;

procedure TTestPkcs12Identity.TestUnrelatedCertsDropped;
var
  LContents: TPkcs12Contents;
begin
  // an unrelated self-issued certificate and a sibling of the leaf under the same root
  LContents.Certificates := TArray<TPkcs12Certificate>.Create(Cert(1, 1, 2), Cert(2, 2, 2),
    Cert(6, 7, 7), Cert(5, 8, 2));
  LContents.Keys := TArray<TPkcs12Key>.Create(KeyOf(0, [0]));
  CheckEquals('3001,3002', ChainOf(TPkcs12Identity.Select(LContents)),
    'certificates off the issuer walk are not in the chain');
end;

procedure TTestPkcs12Identity.TestSelectedCredentialCarriesTheKey;
var
  LContents: TPkcs12Contents;
  LCredential: TImportedCredential;
begin
  LContents.Certificates := TArray<TPkcs12Certificate>.Create(Cert(1, 1, 1));
  LContents.Keys := TArray<TPkcs12Key>.Create(KeyOf(0, [0]));
  LCredential := TPkcs12Identity.Select(LContents);
  CheckTrue(LCredential.PrivateKey = LContents.Keys[0].Key,
    'the credential holds the store''s own key');
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestPkcs12Identity);
{$ELSE}
  RegisterTest(TTestPkcs12Identity.Suite);
{$ENDIF FPC}

end.
