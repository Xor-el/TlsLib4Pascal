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
  /// Installs the OS system-trust source into a config builder for the role the builder serves:
  /// the anchors the platform can enumerate, or the OS delegate where it cannot. A server
  /// installer authenticates client certificates and never roots them at the public OS store (it
  /// raises where only a delegate exists). Lets a host-neutral composer add system trust without
  /// depending on the system-trust package.
  /// </summary>
  ISystemTrustInstaller = interface(IInterface)
    ['{3F778A08-62D4-417B-9C4B-62467B114B46}']
    /// <summary>Installs OS server-certificate trust into a client builder.</summary>
    procedure InstallClientTrust(const ABuilder: ITlsClientConfigBuilder;
      const APkix: IPkixProvider);
    /// <summary>Installs OS client-certificate (mTLS) trust into a server builder; raises where
    /// the platform exposes only a delegate.</summary>
    procedure InstallClientAuthTrust(const ABuilder: ITlsServerConfigBuilder;
      const APkix: IPkixProvider);
  end;

implementation

end.
