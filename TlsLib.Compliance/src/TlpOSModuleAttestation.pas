{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpOSModuleAttestation;

{$I ..\..\TlsLib\src\Include\TlsLib.inc}

interface

uses
  TlpIModuleAttestation
{$IF DEFINED(TLSLIB_MSWINDOWS)}
  , TlpWindowsModuleAttestation
{$ELSE}
  , TlpUnattestedModule
{$IFEND}
  ;

type
  /// <summary>
  /// The attestation of the platform's cryptographic module. Dispatch is compile-time; a platform
  /// with no shipped validated-module table attests nothing, so its status is Unknown and a
  /// strict policy refuses it.
  /// </summary>
  TOSModuleAttestation = class sealed(TObject)
  public
    /// <summary>The attestation of this platform's module; never nil.</summary>
    class function Current: IModuleAttestation; static;
    /// <summary>Whether AAttestation is one of the library's platform classes. Judged by class,
    /// as any host class can implement the interface and claim a validated module.</summary>
    class function IsPlatform(const AAttestation: IModuleAttestation): Boolean; static;
  end;

implementation

{ TOSModuleAttestation }

class function TOSModuleAttestation.Current: IModuleAttestation;
begin
{$IF DEFINED(TLSLIB_MSWINDOWS)}
  Result := TWindowsModuleAttestation.Create as IModuleAttestation;
{$ELSE}
  Result := TUnattestedModule.Create as IModuleAttestation;
{$IFEND}
end;

class function TOSModuleAttestation.IsPlatform(const AAttestation: IModuleAttestation): Boolean;
begin
{$IF DEFINED(TLSLIB_MSWINDOWS)}
  Result := AAttestation is TWindowsModuleAttestation;
{$ELSE}
  Result := AAttestation is TUnattestedModule;
{$IFEND}
end;

end.
