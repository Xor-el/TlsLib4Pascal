{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpISecretBuffer;

{$I ..\..\Include\TlsLib.inc}

interface

uses
  SysUtils;

type
  /// <summary>
  /// A handle to a heap-stable region holding key material. The backing memory is
  /// wiped when the buffer is released.
  /// </summary>
  ISecretBuffer = interface(IInterface)
    ['{80E70BAC-E15F-41D6-A2E7-522817A65E9C}']

    /// <summary>The length of the secret in bytes.</summary>
    function Len: Int32;

    /// <summary>
    /// Borrowed pointer to the owned buffer; nil when Len = 0. Valid only while
    /// a reference to this instance is held.
    /// </summary>
    function DataPtr: PByte;

    /// <summary>
    /// A caller-owned copy of the secret as a transient array (typically to feed
    /// a byte-array API). The caller is responsible for wiping it after use.
    /// </summary>
    function ToBytes: TBytes;

    /// <summary>
    /// Constant-time equality with another secret (no early exit), so the
    /// running time does not leak how many leading bytes matched. Different
    /// lengths compare unequal.
    /// </summary>
    function ConstantTimeAreEqual(const AOther: ISecretBuffer): Boolean;
  end;

implementation

end.
