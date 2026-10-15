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

end.
