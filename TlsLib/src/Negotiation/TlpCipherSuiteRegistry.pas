{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpCipherSuiteRegistry;

{$I ..\Include\TlsLib.inc}

interface

uses
  SysUtils,
  TlpCodeKeyedRegistry,
  TlpCryptoDomainTypes,
  TlpICryptoProvider,
  TlpNegotiationTypes,
  TlpCipherSuiteCatalog,
  TlpINegotiation;

type
  /// <summary>The default cipher-suite registry: an ordered, prunable suite list.</summary>
  TCipherSuiteRegistry = class sealed(TCodeKeyedRegistry<TTlsCipherSuite>,
    ICipherSuiteRegistry)
  strict private
    class function CodeOf(const ASuite: TTlsCipherSuite): UInt16; static;
    /// <summary>Whether the provider can build both the suite's AEAD and hash, so an
    /// entry is offered only when runnable (or flagged mandatory-to-implement).</summary>
    class function SuiteRunnable(const ACryptoProvider: ICryptoProvider;
      AAead: TAeadAlgorithm; AHash: THashAlgorithm): Boolean; static;
    /// <summary>Adds the catalog suites of AProtocol that the provider can run, AES-GCM ahead of
    /// ChaCha20-Poly1305 when it has hardware AES and the reverse otherwise (a performance
    /// ordering: the software AES-GCM path is constant-time either way), each family in catalog
    /// order.</summary>
    class procedure AddRunnable(const ARegistry: ICipherSuiteRegistry;
      const ACryptoProvider: ICryptoProvider; AProtocol: TSuiteProtocol); static;
  public
    constructor Create;

    /// <summary>
    /// The TLS 1.3 suites the provider can actually run, in preference order.
    /// TLS_AES_128_GCM_SHA256 is mandatory-to-implement and always kept.
    /// </summary>
    class function CreateDefault(const ACryptoProvider: ICryptoProvider)
      : ICipherSuiteRegistry; static;

    /// <summary>
    /// The hardened dual-version set: the TLS 1.3 suites followed by the hardened
    /// TLS 1.2 suites (ECDHE-ECDSA/RSA over AES-GCM and ChaCha20-Poly1305). One
    /// registry holds both; selection is branched on the negotiated version.
    /// </summary>
    class function CreateDualVersion(const ACryptoProvider: ICryptoProvider)
      : ICipherSuiteRegistry; static;
  end;

implementation

constructor TCipherSuiteRegistry.Create;
begin
  inherited Create(CodeOf);
end;

class function TCipherSuiteRegistry.CodeOf(const ASuite: TTlsCipherSuite): UInt16;
begin
  Result := ASuite.Common.Code;
end;

class function TCipherSuiteRegistry.SuiteRunnable(const ACryptoProvider: ICryptoProvider;
  AAead: TAeadAlgorithm; AHash: THashAlgorithm): Boolean;
begin
  Result := True;
  try
    ACryptoProvider.Primitives.CreateAead(AAead);
    ACryptoProvider.Primitives.CreateHash(AHash);
  except
    on E: Exception do
      Result := False;
  end;
end;

class procedure TCipherSuiteRegistry.AddRunnable(const ARegistry: ICipherSuiteRegistry;
  const ACryptoProvider: ICryptoProvider; AProtocol: TSuiteProtocol);
var
  LSuites: TArray<TTlsCipherSuite>;
  LPass, LI: Int32;
  LChaChaPass: Boolean;
begin
  LSuites := TCipherSuiteCatalog.All;
  for LPass := 0 to 1 do
  begin
    // the first pass takes ChaCha20-Poly1305 only without hardware AES; the second the other family
    LChaChaPass := (LPass = 0) = (not ACryptoProvider.Primitives.HasHardwareAes);
    for LI := Low(LSuites) to High(LSuites) do
      if (LSuites[LI].Protocol = AProtocol) and
        ((LSuites[LI].Common.Aead = TAeadAlgorithm.CHACHA20_POLY1305) = LChaChaPass) and
        ((LSuites[LI].Common.Code = TCipherSuites13.Aes128GcmSha256) or
        SuiteRunnable(ACryptoProvider, LSuites[LI].Common.Aead, LSuites[LI].Common.Hash)) then
        ARegistry.Add(LSuites[LI]);
  end;
end;

class function TCipherSuiteRegistry.CreateDefault(const ACryptoProvider: ICryptoProvider)
  : ICipherSuiteRegistry;
begin
  Result := TCipherSuiteRegistry.Create;
  AddRunnable(Result, ACryptoProvider, TSuiteProtocol.Tls13);
end;

class function TCipherSuiteRegistry.CreateDualVersion(
  const ACryptoProvider: ICryptoProvider): ICipherSuiteRegistry;
begin
  Result := CreateDefault(ACryptoProvider);
  AddRunnable(Result, ACryptoProvider, TSuiteProtocol.Tls12);
end;

end.
