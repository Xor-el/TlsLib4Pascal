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
    ['{7DF4D709-8445-4227-AE82-EC9B9C930B72}']

    /// <summary>The length of the secret in bytes.</summary>
    function Len: Int32;

    /// <summary>
    /// Borrowed pointer to the owned buffer; nil when Len = 0. Valid only while
    /// a reference to this instance is held.
    /// </summary>
    function DataPtr: PByte;

    /// <summary>
    /// Overwrites the owned buffer with ALen bytes read from ASrc. Raises if
    /// ALen exceeds the buffer length.
    /// </summary>
    procedure CopyFrom(ASrc: PByte; ALen: Int32);

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
