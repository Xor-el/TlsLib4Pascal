{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

/// <summary>
/// Makes the verify and CA writes fcl-web's clients make on the default handler. It deliberately
/// does not use the adapter unit, as fcl-web does not.
/// </summary>
unit FclNetFclWebMimic;

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

interface

uses
  sslsockets;

type
  TFclNetFclWebMimic = class sealed(TObject)
  public
    /// <summary>The default handler with the client's verify switch and CA file written on it.</summary>
    class function NewDefaultHandler(AVerifySSLCertificate: Boolean;
      const ACertCAFileName: string): TSSLSocketHandler; static;
  end;

implementation

class function TFclNetFclWebMimic.NewDefaultHandler(AVerifySSLCertificate: Boolean;
  const ACertCAFileName: string): TSSLSocketHandler;
begin
  Result := TSSLSocketHandler.GetDefaultHandler;
  Result.VerifyPeerCert := AVerifySSLCertificate;
  Result.CertificateData.CertCA.FileName := ACertCAFileName;
end;

end.
