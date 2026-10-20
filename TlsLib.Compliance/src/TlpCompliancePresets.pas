{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpCompliancePresets;

{$I ..\..\TlsLib\src\Include\TlsLib.inc}

interface

uses
  SysUtils,
  TlpCryptoDomainTypes,
  TlpNegotiationTypes,
  TlpTlsVersion,
  TlpComplianceTypes;

type
  TCompliancePreset = record
    Name: string;
    Rules: TComplianceRules;
  end;

  /// <summary>The named rule sets. Both hold trust anchors to the key floors.</summary>
  TCompliancePresets = class sealed(TObject)
  public
    /// <summary>The approved algorithms of the validated OS module, classical key exchange
    /// only; RSA 2048, 3072 or 4096, the sizes the module is tested for.</summary>
    class function Fips140_3: TComplianceRules; static;
    /// <summary>The CNSA 1.0 suite (RFC 9151): AES-256, P-384, SHA-384, RSA 3072 or 4096.</summary>
    class function Cnsa1: TComplianceRules; static;
    /// <summary>The named presets, each inside the ones after it, so the first match is the
    /// tightest.</summary>
    class function Named: TArray<TCompliancePreset>; static;
    /// <summary>Whether ARules fits inside a named preset. AName is that preset's name when the
    /// rules equal it, else 'within' and the name of the tightest preset that holds them.</summary>
    class function TryMatch(const ARules: TComplianceRules; out AName: string): Boolean; static;
  end;

implementation

resourcestring
  SWithinPreset = 'within %s';

{ TCompliancePresets }

class function TCompliancePresets.Fips140_3: TComplianceRules;
begin
  Result := Default(TComplianceRules);
  Result.Versions := TArray<UInt16>.Create(TlsWireVersionTls13, TlsWireVersionTls12);
  Result.CipherSuites := TArray<UInt16>.Create(TCipherSuites13.Aes128GcmSha256,
    TCipherSuites13.Aes256GcmSha384, TCipherSuites12.EcdheEcdsaAes128GcmSha256,
    TCipherSuites12.EcdheEcdsaAes256GcmSha384, TCipherSuites12.EcdheRsaAes128GcmSha256,
    TCipherSuites12.EcdheRsaAes256GcmSha384);
  Result.Aeads := [TAeadAlgorithm.AES_128_GCM, TAeadAlgorithm.AES_256_GCM];
  Result.NamedGroups := TArray<UInt16>.Create(TNamedGroupCatalog.Secp256r1,
    TNamedGroupCatalog.Secp384r1, TNamedGroupCatalog.Secp521r1);
  Result.SignatureSchemes := [TSignatureScheme.ECDSA_SECP256R1_SHA256,
    TSignatureScheme.ECDSA_SECP384R1_SHA384, TSignatureScheme.ECDSA_SECP521R1_SHA512,
    TSignatureScheme.RSA_PSS_RSAE_SHA256, TSignatureScheme.RSA_PSS_RSAE_SHA384,
    TSignatureScheme.RSA_PSS_RSAE_SHA512, TSignatureScheme.RSA_PKCS1_SHA256,
    TSignatureScheme.RSA_PKCS1_SHA384, TSignatureScheme.RSA_PKCS1_SHA512];
  Result.Strength.MinRsaModulusBits := 2048;
  Result.Strength.MaxRsaModulusBits := 4096;
  Result.RsaModulusBits := TArray<UInt32>.Create(2048, 3072, 4096);
  Result.Strength.AllowedEcCurves := TArray<UInt16>.Create(TNamedGroupCatalog.Secp256r1,
    TNamedGroupCatalog.Secp384r1, TNamedGroupCatalog.Secp521r1);
  Result.Strength.AllowEdDsa := False;
  Result.Strength.AnchorKeyFloors := True;
  Result.Strength.AllowedDeprecatedHashes := [];
  Result.Requirements := [Low(TComplianceRequirement) .. High(TComplianceRequirement)];
  Result.Kdf := TKdfRule.AllowComposed;
  Result.ModuleStandard := TModuleStandard.Fips140_3;
end;

class function TCompliancePresets.Cnsa1: TComplianceRules;
begin
  Result := Default(TComplianceRules);
  Result.Versions := TArray<UInt16>.Create(TlsWireVersionTls13, TlsWireVersionTls12);
  Result.CipherSuites := TArray<UInt16>.Create(TCipherSuites13.Aes256GcmSha384,
    TCipherSuites12.EcdheEcdsaAes256GcmSha384, TCipherSuites12.EcdheRsaAes256GcmSha384);
  Result.Aeads := [TAeadAlgorithm.AES_256_GCM];
  Result.NamedGroups := TArray<UInt16>.Create(TNamedGroupCatalog.Secp384r1);
  Result.SignatureSchemes := [TSignatureScheme.ECDSA_SECP384R1_SHA384,
    TSignatureScheme.RSA_PSS_RSAE_SHA384, TSignatureScheme.RSA_PKCS1_SHA384];
  Result.Strength.MinRsaModulusBits := 3072;
  Result.Strength.MaxRsaModulusBits := 4096;
  Result.RsaModulusBits := TArray<UInt32>.Create(3072, 4096);
  Result.Strength.AllowedEcCurves := TArray<UInt16>.Create(TNamedGroupCatalog.Secp384r1);
  Result.Strength.AllowEdDsa := False;
  Result.Strength.AnchorKeyFloors := True;
  Result.Strength.AllowedDeprecatedHashes := [];
  Result.Requirements := [Low(TComplianceRequirement) .. High(TComplianceRequirement)];
  Result.Kdf := TKdfRule.AllowComposed;
  Result.ModuleStandard := TModuleStandard.Fips140_3;
end;

class function TCompliancePresets.Named: TArray<TCompliancePreset>;
begin
  Result := nil;
  SetLength(Result, 2);
  Result[0].Name := 'Cnsa1';
  Result[0].Rules := Cnsa1;
  Result[1].Name := 'Fips140_3';
  Result[1].Rules := Fips140_3;
end;

class function TCompliancePresets.TryMatch(const ARules: TComplianceRules;
  out AName: string): Boolean;
var
  LPresets: TArray<TCompliancePreset>;
  LI: Int32;
begin
  AName := '';
  LPresets := Named;
  for LI := 0 to System.Length(LPresets) - 1 do
    if ARules.IsSubsetOf(LPresets[LI].Rules) then
    begin
      if LPresets[LI].Rules.IsSubsetOf(ARules) then
        AName := LPresets[LI].Name
      else
        AName := Format(SWithinPreset, [LPresets[LI].Name]);
      Exit(True);
    end;
  Result := False;
end;

end.
