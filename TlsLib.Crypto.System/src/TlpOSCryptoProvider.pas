{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpOSCryptoProvider;

{$I ..\..\TlsLib\src\Include\TlsLib.inc}

interface

uses
  TlpICryptoProvider
{$IF DEFINED(TLSLIB_MSWINDOWS)}
  , TlpWindowsSystemCrypto
{$IFEND}
  ;

type
  /// <summary>
  /// Composes a platform's native-accelerated crypto facets over a portable base
  /// provider. Dispatch is compile-time, most-specific OS first; each platform's whole
  /// composition lives in its own unit, so this factory only picks one - a platform
  /// with no native facet returns the base unchanged, so the portable provider is
  /// always the fallback. Only deterministic primitives (key agreement, AEAD, hashes)
  /// and signing are ever replaced - trust, path validation, revocation and alert
  /// behavior stay with the base, whose conformance is authoritative.
  /// </summary>
  TOSCryptoProvider = class sealed(TObject)
  public
    /// <summary>Whether this platform contributes at least one native facet. When
    /// False, <see cref="Compose" /> returns its argument unchanged.</summary>
    class function HasNativeFacets: Boolean; static;
    /// <summary>ABase with this platform's native facets overlaid where it has them,
    /// or ABase unchanged otherwise (including where native support is compiled in but
    /// unavailable at runtime). Never nil. The caller supplies the base provider, so this
    /// factory stays backend-agnostic - it depends only on ICryptoProvider and never on a
    /// concrete provider, keeping the portable provider's construction at the composition
    /// root that already references it.</summary>
    class function Compose(const ABase: ICryptoProvider): ICryptoProvider; static;
  end;

implementation

{ TOSCryptoProvider }

class function TOSCryptoProvider.HasNativeFacets: Boolean;
begin
{$IF DEFINED(TLSLIB_MSWINDOWS)}
  Result := True;
{$ELSE}
  Result := False;
{$IFEND}
end;

class function TOSCryptoProvider.Compose(
  const ABase: ICryptoProvider): ICryptoProvider;
begin
{$IF DEFINED(TLSLIB_MSWINDOWS)}
  Result := TWindowsSystemCrypto.Compose(ABase);
{$ELSE}
  Result := ABase;
{$IFEND}
end;

end.
