{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit MockNamedGroups;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  SysUtils,
  TlpISecretBuffer,
  TlpSecretBuffer,
  TlpCryptoDomainTypes,
  TlpINamedGroup,
  TlpIKeyExchangePrivateKey,
  TlpINegotiation,
  TlpCipherSuiteRegistry,
  TlpNegotiationTypes;

type
  /// <summary>A key-exchange key double with no real material.</summary>
  TFixedSecretKey = class sealed(TInterfacedObject, IKeyExchangePrivateKey)
  public
    function Usage: TKeyAgreementUsage;
    function ExportRaw: ISecretBuffer;
  end;

  /// <summary>An X25519-coded group that yields a fixed share and shared secret.</summary>
  TFixedSecretGroup = class sealed(TInterfacedObject, INamedGroup)
  strict private
    FShare: TBytes;
    FShared: TBytes;
  public
    constructor Create(const AShare, AShared: TBytes);
    function Code: UInt16;
    function Name: string;
    function Kind: TNamedGroupKind;
    function Composition: TNamedGroupComposition;
    procedure GenerateKeyPair(out APriv: IKeyExchangePrivateKey; out APubShare: TBytes);
    procedure Encapsulate(const APeerPub: TBytes; out ACiphertext: TBytes;
      out ASharedSecret: ISecretBuffer);
    procedure Decapsulate(const APriv: IKeyExchangePrivateKey; const ACiphertext: TBytes;
      out ASharedSecret: ISecretBuffer);
    function ValidatePeerShare(const AShare: TBytes): Boolean;
  end;

  /// <summary>A cipher-suite registry a host wrote: it holds ASuites as given, with no catalog
  /// check. Never for production use.</summary>
  TFakeSuiteRegistry = class sealed(TInterfacedObject, ICipherSuiteRegistry)
  strict private
  var
    FSuites: TArray<TTlsCipherSuite>;
  public
    constructor Create(const ASuites: TArray<TTlsCipherSuite>);
    /// <summary>Swaps the held records, as a host registry that is not immutable may.</summary>
    procedure Replace(const ASuites: TArray<TTlsCipherSuite>);
    function Items: TArray<TTlsCipherSuite>;
    function Contains(ACode: UInt16): Boolean;
    function TryGet(ACode: UInt16; out ASuite: TTlsCipherSuite): Boolean;
    function ToBuilder: ICipherSuiteRegistryBuilder;
  end;

  /// <summary>A registry that lists the groups of AListed and resolves only AResolved through
  /// TryGet, so every other code resolves to nothing and the two disagree. Never for production
  /// use.</summary>
  TFakeGroupRegistry = class sealed(TInterfacedObject, INamedGroupRegistry)
  strict private
  var
    FListed: INamedGroupRegistry;
    FResolved: INamedGroup;
  public
    constructor Create(const AListed: INamedGroupRegistry; const AResolved: INamedGroup);
    function Items: TArray<INamedGroup>;
    function Contains(ACode: UInt16): Boolean;
    function TryGet(ACode: UInt16; out AGroup: INamedGroup): Boolean;
    function ToBuilder: INamedGroupRegistryBuilder;
  end;

implementation

{ TFixedSecretKey }

function TFixedSecretKey.Usage: TKeyAgreementUsage;
begin
  Result := TKeyAgreementUsage.Ephemeral;
end;

function TFixedSecretKey.ExportRaw: ISecretBuffer;
begin
  Result := TSecretBuffer.Allocate(0);
end;

{ TFixedSecretGroup }

constructor TFixedSecretGroup.Create(const AShare, AShared: TBytes);
begin
  inherited Create;
  FShare := AShare;
  FShared := AShared;
end;

function TFixedSecretGroup.Code: UInt16;
begin
  Result := TNamedGroupCatalog.X25519;
end;

function TFixedSecretGroup.Name: string;
begin
  Result := 'X25519';
end;

function TFixedSecretGroup.Kind: TNamedGroupKind;
begin
  Result := TNamedGroupKind.Ecdhe;
end;

function TFixedSecretGroup.Composition: TNamedGroupComposition;
begin
  Result := TNamedGroupComposition.From(TKeyAgreementAlgorithm.X25519);
end;

procedure TFixedSecretGroup.GenerateKeyPair(out APriv: IKeyExchangePrivateKey;
  out APubShare: TBytes);
begin
  APriv := TFixedSecretKey.Create;
  APubShare := System.Copy(FShare);
end;

procedure TFixedSecretGroup.Encapsulate(const APeerPub: TBytes; out ACiphertext: TBytes;
  out ASharedSecret: ISecretBuffer);
begin
  ACiphertext := System.Copy(FShare);
  ASharedSecret := TSecretBuffer.From(FShared);
end;

procedure TFixedSecretGroup.Decapsulate(const APriv: IKeyExchangePrivateKey;
  const ACiphertext: TBytes; out ASharedSecret: ISecretBuffer);
begin
  ASharedSecret := TSecretBuffer.From(FShared);
end;

function TFixedSecretGroup.ValidatePeerShare(const AShare: TBytes): Boolean;
begin
  Result := True;
end;

{ TFakeSuiteRegistry }

constructor TFakeSuiteRegistry.Create(const ASuites: TArray<TTlsCipherSuite>);
begin
  inherited Create;
  FSuites := ASuites;
end;

procedure TFakeSuiteRegistry.Replace(const ASuites: TArray<TTlsCipherSuite>);
begin
  FSuites := ASuites;
end;

function TFakeSuiteRegistry.Items: TArray<TTlsCipherSuite>;
begin
  Result := FSuites;
end;

function TFakeSuiteRegistry.Contains(ACode: UInt16): Boolean;
var
  LSuite: TTlsCipherSuite;
begin
  Result := TryGet(ACode, LSuite);
end;

function TFakeSuiteRegistry.TryGet(ACode: UInt16; out ASuite: TTlsCipherSuite): Boolean;
var
  LI: Int32;
begin
  for LI := 0 to System.Length(FSuites) - 1 do
    if FSuites[LI].Common.Code = ACode then
    begin
      ASuite := FSuites[LI];
      Exit(True);
    end;
  ASuite := Default(TTlsCipherSuite);
  Result := False;
end;

function TFakeSuiteRegistry.ToBuilder: ICipherSuiteRegistryBuilder;
begin
  Result := TCipherSuiteRegistryBuilder.Create(FSuites) as ICipherSuiteRegistryBuilder;
end;

{ TFakeGroupRegistry }

constructor TFakeGroupRegistry.Create(const AListed: INamedGroupRegistry;
  const AResolved: INamedGroup);
begin
  inherited Create;
  FListed := AListed;
  FResolved := AResolved;
end;

function TFakeGroupRegistry.Items: TArray<INamedGroup>;
begin
  Result := FListed.Items;
end;

function TFakeGroupRegistry.Contains(ACode: UInt16): Boolean;
begin
  Result := FListed.Contains(ACode);
end;

function TFakeGroupRegistry.TryGet(ACode: UInt16; out AGroup: INamedGroup): Boolean;
begin
  Result := ACode = FResolved.Code;
  if Result then
    AGroup := FResolved
  else
    AGroup := nil;
end;

function TFakeGroupRegistry.ToBuilder: INamedGroupRegistryBuilder;
begin
  Result := FListed.ToBuilder;
end;

end.
