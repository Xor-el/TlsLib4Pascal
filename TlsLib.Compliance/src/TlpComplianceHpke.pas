{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpComplianceHpke;

{$I ..\..\TlsLib\src\Include\TlsLib.inc}

interface

uses
  SysUtils,
  TlpCryptoDomainTypes,
  TlpICryptoProvider,
  TlpISecretBuffer,
  TlpComplianceTypes,
  TlpComplianceExceptions,
  TlpTlsLibExceptions;

type
  /// <summary>
  /// An HPKE decorator for a base whose HPKE is its own and not composed over the primitives the
  /// rules already filter. In both modes it refuses a KEM whose Diffie-Hellman group the rules
  /// leave out and an AEAD the rules do not allow; hashes are not filtered. In strict mode it
  /// refuses everything, because where a foreign HPKE runs cannot be known: suites and KEMs are
  /// unavailable (nil, empty, False) and key generation and import raise
  /// <see cref="EComplianceRefusedTlsLibException" />. It holds only immutable state, so its
  /// thread-safety is the inner facet's.
  /// </summary>
  TComplianceHpke = class sealed(TInterfacedObject, IHpkeCrypto)
  strict private
  var
    FInner: IHpkeCrypto;
    FStrict: Boolean;
    FKeyAgreements: TComplianceKeyAgreementSet;
    FAeads: TComplianceAeadSet;
    function KemGroupAllowed(AKem: UInt16): Boolean;
    function AeadAllowed(AAead: UInt16): Boolean;
    procedure RequireKem(AKem: UInt16);
  public
    /// <param name="AInner">Never nil: the base provider's HPKE facet.</param>
    constructor Create(const AInner: IHpkeCrypto; const ARules: TComplianceRules;
      AEnforcement: TComplianceEnforcement);
    function Suite(AKem, AKdf, AAead: UInt16): IHpkeSuite;
    function ImportRecipientKey(AKem: UInt16;
      const APrivateKey: ISecretBuffer): IHpkeRecipientKey;
    procedure GenerateKeyPair(AKem: UInt16; out APublicKey: TBytes;
      out APrivateKey: ISecretBuffer);
    function ImportPrivateKey(AKem: UInt16; const APkcs8Der: TBytes): ISecretBuffer;
    function SupportedSuites(AKem: UInt16): TArray<THpkeSuiteId>;
    function ValidatePublicKey(AKem: UInt16; const APublicKey: TBytes): Boolean;
    function RandomEncapsulation(AKem: UInt16): TBytes;
  end;

implementation

resourcestring
  SNilInnerHpke = 'the inner HPKE facet must not be nil';
  SHpkeKemRefused = 'the HPKE KEM 0x%.4X is not allowed by the compliance rules';
  SHpkeOutsideModule = 'the HPKE facet is not served by the OS module';

{ TComplianceHpke }

constructor TComplianceHpke.Create(const AInner: IHpkeCrypto; const ARules: TComplianceRules;
  AEnforcement: TComplianceEnforcement);
begin
  inherited Create;
  if AInner = nil then
    raise EArgumentTlsLibException.CreateRes(@SNilInnerHpke);
  FInner := AInner;
  FStrict := AEnforcement = TComplianceEnforcement.Strict;
  FKeyAgreements := TComplianceCatalog.KeyAgreements(ARules);
  FAeads := ARules.Aeads;
end;

function TComplianceHpke.KemGroupAllowed(AKem: UInt16): Boolean;
var
  LAgreement: TKeyAgreementAlgorithm;
begin
  Result := THpkeKem.TryKeyAgreement(AKem, LAgreement) and (LAgreement in FKeyAgreements);
end;

function TComplianceHpke.AeadAllowed(AAead: UInt16): Boolean;
var
  LAead: TAeadAlgorithm;
begin
  Result := THpkeAead.TryAlgorithm(AAead, LAead) and (LAead in FAeads);
end;

procedure TComplianceHpke.RequireKem(AKem: UInt16);
begin
  if FStrict then
    raise EComplianceRefusedTlsLibException.CreateRes(@SHpkeOutsideModule);
  if not KemGroupAllowed(AKem) then
    raise EComplianceRefusedTlsLibException.CreateResFmt(@SHpkeKemRefused, [AKem]);
end;

function TComplianceHpke.Suite(AKem, AKdf, AAead: UInt16): IHpkeSuite;
begin
  if FStrict or not KemGroupAllowed(AKem) or not AeadAllowed(AAead) then
    Result := nil
  else
    Result := FInner.Suite(AKem, AKdf, AAead);
end;

function TComplianceHpke.ImportRecipientKey(AKem: UInt16;
  const APrivateKey: ISecretBuffer): IHpkeRecipientKey;
begin
  RequireKem(AKem);
  Result := FInner.ImportRecipientKey(AKem, APrivateKey);
end;

procedure TComplianceHpke.GenerateKeyPair(AKem: UInt16; out APublicKey: TBytes;
  out APrivateKey: ISecretBuffer);
begin
  RequireKem(AKem);
  FInner.GenerateKeyPair(AKem, APublicKey, APrivateKey);
end;

function TComplianceHpke.ImportPrivateKey(AKem: UInt16;
  const APkcs8Der: TBytes): ISecretBuffer;
begin
  RequireKem(AKem);
  Result := FInner.ImportPrivateKey(AKem, APkcs8Der);
end;

function TComplianceHpke.SupportedSuites(AKem: UInt16): TArray<THpkeSuiteId>;
var
  LSuites: TArray<THpkeSuiteId>;
  LI, LN: Int32;
begin
  Result := nil;
  if FStrict or not KemGroupAllowed(AKem) then
    Exit;
  LSuites := FInner.SupportedSuites(AKem);
  System.SetLength(Result, System.Length(LSuites));
  LN := 0;
  for LI := 0 to System.Length(LSuites) - 1 do
    if AeadAllowed(LSuites[LI].Aead) then
    begin
      Result[LN] := LSuites[LI];
      System.Inc(LN);
    end;
  System.SetLength(Result, LN);
end;

function TComplianceHpke.ValidatePublicKey(AKem: UInt16; const APublicKey: TBytes): Boolean;
begin
  Result := not FStrict and KemGroupAllowed(AKem) and FInner.ValidatePublicKey(AKem, APublicKey);
end;

function TComplianceHpke.RandomEncapsulation(AKem: UInt16): TBytes;
begin
  if FStrict or not KemGroupAllowed(AKem) then
    Result := nil
  else
    Result := FInner.RandomEncapsulation(AKem);
end;

end.
