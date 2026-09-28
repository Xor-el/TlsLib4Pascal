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
  TlpITlsConfigBuilder;

type
  /// <summary>
  /// Installs the OS system-trust source into a client config builder as the server-certificate
  /// trust source: the anchors the platform can enumerate, or the OS delegate where it cannot. Lets
  /// a host-neutral composer add system trust without depending on the system-trust package. System
  /// trust never vouches for a client certificate: a server's client-CA is always caller-supplied.
  /// </summary>
  ISystemTrustInstaller = interface(IInterface)
    ['{F16C2C50-2E66-43E0-BB40-48A4E18994AD}']
    /// <summary>Installs OS server-certificate trust into a client builder.</summary>
    procedure InstallClientTrust(const ABuilder: ITlsClientConfigBuilder;
      const APkix: IPkixProvider);
  end;

implementation

end.
