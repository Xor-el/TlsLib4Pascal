{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpITlsResumptionPartition;

{$I ..\..\Include\TlsLib.inc}

interface

uses
  SysUtils;

type
  /// <summary>
  /// The resumption partition of one client engine: an opaque tag that keeps the tickets it caches
  /// apart from those of other partitions on the same configuration, so services that share one
  /// configuration and cache never resume each other. Reach it with Supports on an engine: only a
  /// client handshake-only engine answers it, since a server has no cache key to partition.
  /// </summary>
  ITlsResumptionPartition = interface(IInterface)
    ['{2DA0A9CC-0AFA-40AC-B300-8567D3D38821}']
    /// <summary>Stores the tickets this connection receives from now on under APartition, at most
    /// 32 bytes (empty is the unpartitioned key); a longer one raises EArgumentTlsLibException and
    /// changes nothing. The ticket this engine offers is the one of the partition it was created
    /// with.</summary>
    procedure SetResumptionPartition(const APartition: TBytes);
  end;

  /// <summary>
  /// The handshake's side of <see cref="ITlsResumptionPartition" />, for whoever drives a client
  /// machine: the partition a ticket received now is stored under.
  /// </summary>
  IResumptionPartitionChannel = interface(IInterface)
    ['{6773BB46-6456-4A51-8174-DDC9F6CCD4F2}']
    /// <summary>The partition the host last set, or the one the engine was created with.</summary>
    function Current: TBytes;
  end;

implementation

end.
