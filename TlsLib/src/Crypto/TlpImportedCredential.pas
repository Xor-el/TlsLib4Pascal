{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpImportedCredential;

{$I ..\Include\TlsLib.inc}

interface

uses
  SysUtils,
  TlpISigningKey;

type
  /// <summary>The crypto-level result of importing an identity (e.g. from PKCS#12): the
  /// certificate chain (leaf first, DER) and the leaf's signing key. This is the provider
  /// boundary's own type - it carries no handshake concerns (OCSP stapling, client-auth mode);
  /// the builder lifts it into a full TTlsCredential.</summary>
  TImportedCredential = record
    CertificateChain: TArray<TBytes>;
    PrivateKey: ISigningKey;
  end;

implementation

end.
