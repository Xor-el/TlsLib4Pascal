{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpISystemTrustInstaller;

{$I ..\..\Include\TlsLib.inc}

interface

uses
  TlpIPkixProvider,
  TlpITrustAnchorStore,
  TlpICertificateVerifierSource;

type
  /// <summary>
  /// Supplies the OS system-trust policy for the server certificate: the OS verifier where the
  /// platform has one, else the anchors it can enumerate. Lets a host-neutral composer add system trust
  /// without depending on the system-trust package. System trust never vouches for a client
  /// certificate: a server's client-CA is always caller-supplied.
  /// </summary>
  ISystemTrustInstaller = interface(IInterface)
    ['{C74B4E15-F82E-49C1-993A-EE5DF87BE778}']
    /// <summary>Names what this installer installs: equal for installers that install the same
    /// trust, different otherwise, never empty, and stable for the installer's lifetime. Config
    /// caches key on it, so two installers that install different roots must not share one.</summary>
    function Identity: string;
    /// <summary>The OS server-certificate trust policy. AExtraAnchors (nil for none) are the
    /// host's own roots to trust beside the OS ones; a platform that cannot union them raises
    /// instead of ignoring them.</summary>
    function ServerVerification(const APkix: IPkixProvider;
      const AExtraAnchors: ITrustAnchorStore): IServerVerification;
  end;

implementation

end.
