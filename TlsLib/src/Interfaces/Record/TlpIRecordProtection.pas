{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpIRecordProtection;

{$I ..\..\Include\TlsLib.inc}

interface

uses
  SysUtils,
  TlpTlsContentType;

type
  /// <summary>
  /// The epoch- and sequence-aware AEAD boundary for the record layer. It owns a
  /// 64-bit record sequence counter, derives a fresh nonce per record so a nonce
  /// never repeats within a key (the hard GCM invariant), and turns a plaintext
  /// fragment into a complete on-the-wire record and back. AEAD-only; a backend
  /// is reached solely through the provider's IAead, never a concrete type.
  /// </summary>
  IRecordProtection = interface(IInterface)
    ['{5D6C9E2A-7F0B-4B8E-9C31-2A4E6F8D0B15}']
    /// <summary>
    /// Seals APlaintext[AOffset .. AOffset + ALength) carrying its (inner)
    /// content type and returns the full record: the 5-byte header followed by
    /// the ciphertext and tag. Advances the sequence number.
    /// </summary>
    function Protect(AContentType: TTlsContentType; const APlaintext: TBytes;
      AOffset, ALength: Int32): TBytes;
    /// <summary>
    /// Authenticates and decrypts the complete record in
    /// ARecord[AOffset .. AOffset + ALength), returning the plaintext and the
    /// recovered content type. An authentication failure raises a fatal
    /// bad_record_mac; advances the sequence number on success.
    /// </summary>
    function Unprotect(const ARecord: TBytes; AOffset, ALength: Int32;
      out AContentType: TTlsContentType): TBytes;
    /// <summary>Non-plaintext bytes the record body adds (tag, inner type, explicit nonce).</summary>
    function Overhead: Int32;
    /// <summary>Content-type bytes carried inside the record plaintext: 1 for TLS 1.3's
    /// TLSInnerPlaintext, 0 for TLS 1.2 and the null epoch. Lets a caller recover the
    /// RFC 8449 TLSInnerPlaintext length from the wire record length.</summary>
    function InnerContentTypeLength: Int32;
    /// <summary>The next sequence number that will be used.</summary>
    function SequenceNumber: UInt64;
    /// <summary>True once the epoch nears its AEAD usage limit (a small lead before the hard
    /// bound), so a key update should be sent before more application data (RFC 8446 5.5).</summary>
    function NeedsKeyUpdate: Boolean;
  end;

  /// <summary>
  /// A test-only seam to force the record sequence counter to a chosen value, so
  /// the usage-limit and wrap invariants can be exercised without sending 2^64
  /// records. Reach it with Supports(protection, IRecordProtectionTestHook, hook);
  /// it is never part of the record-layer contract.
  /// </summary>
  IRecordProtectionTestHook = interface(IInterface)
    ['{9B7A6C41-0E2D-4F53-8AA6-16C0B3D8E2F7}']
    procedure SetSequenceNumber(AValue: UInt64);
  end;

implementation

end.
