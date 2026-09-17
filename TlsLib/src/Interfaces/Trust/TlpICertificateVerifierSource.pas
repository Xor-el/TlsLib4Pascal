{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpICertificateVerifierSource;

{$I ..\..\Include\TlsLib.inc}

interface

uses
  TlpTrustPolicy,
  TlpICertificateTrust;

type
  /// <summary>
  /// The single way the engine obtains a server-certificate verifier: it asks a
  /// source to build one from the connection's trust context. The built-in PKIX
  /// verifier is the default source; an injected instance and the OS-native
  /// delegate are also just sources (mirrors how a server credential is obtained
  /// through <c>ITlsServerCredentialResolver</c>).
  /// </summary>
  IServerCertificateVerifierSource = interface(IInterface)
    ['{4C7E0B21-9F3A-4D58-8E16-2A7C5D9B0F31}']
    function CreateServerVerifier(const AContext: TServerTrustContext)
      : IServerCertificateVerifier;
  end;

  /// <summary>
  /// The single way an mTLS server obtains a client-certificate verifier: it asks a
  /// source to build one from the connection's client-trust context. The built-in PKIX
  /// verifier is the default source; an injected instance and the OS-native delegate (an
  /// exclusive-root chain engine over the configured client-CA anchors) are also just sources.
  /// </summary>
  IClientCertificateVerifierSource = interface(IInterface)
    ['{9D5A1C82-3E47-4B96-A0F2-7C48D6B1E395}']
    function CreateClientVerifier(const AContext: TClientTrustContext)
      : IClientCertificateVerifier;
  end;

implementation

end.
