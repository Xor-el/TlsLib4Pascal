{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpSignatureSchemeRegistry;

{$I ..\Include\TlsLib.inc}

interface

uses
  SysUtils,
  TlpArrayUtilities,
  TlpCodeKeyedRegistry,
  TlpCryptoDomainTypes,
  TlpINegotiation;

type
  /// <summary>The default signature-scheme registry: an immutable, ordered list.</summary>
  TSignatureSchemeRegistry = class sealed(TCodeKeyedRegistryBase<TSignatureScheme>,
    ISignatureSchemeRegistry)
  public
    constructor Create(const ASchemes: TArray<TSignatureScheme>);
    class function CodeOf(const AScheme: TSignatureScheme): UInt16; static;
    function ToBuilder: ISignatureSchemeRegistryBuilder;

    /// <summary>
    /// The default scheme set in preference order (ECDSA, EdDSA, RSA-PSS, RSA-PKCS1). Provider
    /// capability is confirmed when the signers are wired (the signer sub-seam), so
    /// the default set is the full modern list here.
    /// </summary>
    class function CreateDefault: ISignatureSchemeRegistry; static;

    /// <summary>The default set narrowed to the schemes in AAllowed, in the default preference
    /// order whatever AAllowed's order.</summary>
    class function CreateDefaultRestricted(
      const AAllowed: TArray<TSignatureScheme>): ISignatureSchemeRegistry; static;
  end;

  /// <summary>The signature-scheme registry builder: Add and Prune, then Build a snapshot.</summary>
  TSignatureSchemeRegistryBuilder = class sealed(TCodeKeyedRegistryBuilderBase<TSignatureScheme>,
    ISignatureSchemeRegistryBuilder)
  public
    /// <summary>An empty builder.</summary>
    constructor Create; overload;
    /// <summary>A builder holding ASchemes.</summary>
    constructor Create(const ASchemes: TArray<TSignatureScheme>); overload;
    function Build: ISignatureSchemeRegistry;
  end;

  /// <summary>Projects a signature-scheme registry to its wire codepoints in registry (preference)
  /// order, so a consumer that needs the advertised-scheme list gets it without depending on the
  /// engine factory (the engine's negotiation contexts, an OS delegate's strength policy).</summary>
  TSignatureSchemeCodes = class sealed(TObject)
  public
    class function FromRegistry(const ARegistry: ISignatureSchemeRegistry): TArray<UInt16>; static;
  end;

implementation

constructor TSignatureSchemeRegistry.Create(const ASchemes: TArray<TSignatureScheme>);
begin
  inherited Create(CodeOf, ASchemes);
end;

function TSignatureSchemeRegistry.ToBuilder: ISignatureSchemeRegistryBuilder;
begin
  Result := TSignatureSchemeRegistryBuilder.Create(FItems) as ISignatureSchemeRegistryBuilder;
end;

constructor TSignatureSchemeRegistryBuilder.Create;
begin
  inherited Create(TSignatureSchemeRegistry.CodeOf, nil);
end;

constructor TSignatureSchemeRegistryBuilder.Create(const ASchemes: TArray<TSignatureScheme>);
begin
  inherited Create(TSignatureSchemeRegistry.CodeOf, ASchemes);
end;

function TSignatureSchemeRegistryBuilder.Build: ISignatureSchemeRegistry;
begin
  Result := TSignatureSchemeRegistry.Create(FItems) as ISignatureSchemeRegistry;
end;

class function TSignatureSchemeRegistry.CodeOf(
  const AScheme: TSignatureScheme): UInt16;
begin
  Result := AScheme.ToCode;
end;

class function TSignatureSchemeCodes.FromRegistry(
  const ARegistry: ISignatureSchemeRegistry): TArray<UInt16>;
var
  LSchemes: TArray<TSignatureScheme>;
  LI: Int32;
begin
  Result := nil;
  LSchemes := ARegistry.Items;
  SetLength(Result, System.Length(LSchemes));
  for LI := 0 to System.High(LSchemes) do
    Result[LI] := LSchemes[LI].ToCode;
end;

class function TSignatureSchemeRegistry.CreateDefault: ISignatureSchemeRegistry;
var
  LRegistry: ISignatureSchemeRegistryBuilder;
begin
  LRegistry := TSignatureSchemeRegistryBuilder.Create as ISignatureSchemeRegistryBuilder;
  // preference order: ECDSA, then EdDSA (Ed25519, Ed448), then RSA-PSS, then legacy RSA-PKCS1. PSS is
  // preferred over PKCS1 (and is the only RSA option this library signs or accepts in a 1.3
  // handshake); the pkcs1 schemes are advertised for TLS 1.2 handshake signatures and for pkcs1-signed
  // certificate chains, which RFC 9846 4.3.3 permits ("for backward compatibility with
  // TLS 1.2") even in a 1.3 ClientHello.
  LRegistry.Add(TSignatureScheme.ECDSA_SECP256R1_SHA256);
  LRegistry.Add(TSignatureScheme.ECDSA_SECP384R1_SHA384);
  LRegistry.Add(TSignatureScheme.ECDSA_SECP521R1_SHA512);
  LRegistry.Add(TSignatureScheme.ED25519);
  LRegistry.Add(TSignatureScheme.ED448);
  LRegistry.Add(TSignatureScheme.RSA_PSS_RSAE_SHA256);
  LRegistry.Add(TSignatureScheme.RSA_PSS_RSAE_SHA384);
  LRegistry.Add(TSignatureScheme.RSA_PSS_RSAE_SHA512);
  LRegistry.Add(TSignatureScheme.RSA_PKCS1_SHA256);
  LRegistry.Add(TSignatureScheme.RSA_PKCS1_SHA384);
  LRegistry.Add(TSignatureScheme.RSA_PKCS1_SHA512);
  Result := LRegistry.Build;
end;

class function TSignatureSchemeRegistry.CreateDefaultRestricted(
  const AAllowed: TArray<TSignatureScheme>): ISignatureSchemeRegistry;
var
  LBuilder: ISignatureSchemeRegistryBuilder;
  LScheme: TSignatureScheme;
begin
  LBuilder := TSignatureSchemeRegistryBuilder.Create as ISignatureSchemeRegistryBuilder;
  for LScheme in CreateDefault.Items do
    if TArrayUtilities.Contains<TSignatureScheme>(AAllowed, LScheme) then
      LBuilder.Add(LScheme);
  Result := LBuilder.Build;
end;

end.
