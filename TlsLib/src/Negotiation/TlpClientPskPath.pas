{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpClientPskPath;

{$I ..\Include\TlsLib.inc}

interface

type
  /// <summary>
  /// The rule that decides whether a client can end a handshake in a certificate: a required
  /// pre-shared key ends a version's handshake at the key, so that version never reaches a
  /// certificate. The config builder, the engine factory and any embedder checking a client
  /// config share it.
  /// </summary>
  TClientPskPath = class sealed(TObject)
  public
    /// <summary>Whether a version holding APskCount keys with ARequired set ends its handshake
    /// at the key: a key is configured and the server must select it.</summary>
    class function RequiresPsk(APskCount: Int32; ARequired: Boolean): Boolean; static;
    /// <summary>Whether a client offering TLS 1.3 (AOffers13) and/or TLS 1.2 (AOffers12) can
    /// complete a handshake in a certificate: some offered version does not require its key.
    /// The external keys govern TLS 1.3 and the TLS 1.2 keys govern TLS 1.2.</summary>
    class function HasCertificatePath(AOffers13, AOffers12: Boolean;
      AExternalPskCount: Int32; AExternalPskRequired: Boolean;
      ATls12PskCount: Int32; ATls12PskRequired: Boolean): Boolean; static;
  end;

implementation

class function TClientPskPath.RequiresPsk(APskCount: Int32; ARequired: Boolean): Boolean;
begin
  Result := (APskCount > 0) and ARequired;
end;

class function TClientPskPath.HasCertificatePath(AOffers13, AOffers12: Boolean;
  AExternalPskCount: Int32; AExternalPskRequired: Boolean;
  ATls12PskCount: Int32; ATls12PskRequired: Boolean): Boolean;
begin
  Result := (AOffers13 and not RequiresPsk(AExternalPskCount, AExternalPskRequired)) or
    (AOffers12 and not RequiresPsk(ATls12PskCount, ATls12PskRequired));
end;

end.
