{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpITrustAnchorStore;

{$I ..\..\Include\TlsLib.inc}

interface

uses
  SysUtils;

type
  /// <summary>
  /// The set of trusted root certificates (DER), kept behind an interface so the PKIX backend's
  /// certificate types never reach the public surface, together with the certificates its source
  /// explicitly distrusts. A store is immutable: the same store identity always means the same
  /// content, so a consumer may cache work derived from it by identity. Reloading trust means
  /// building a new store. No root is also distrusted (distrust wins), and a root appears once.
  /// The verifier refuses a distrusted leaf, never builds a path through a distrusted
  /// intermediate, and rejects a validated path that still contains one.
  /// </summary>
  ITrustAnchorStore = interface(IInterface)
    ['{81558321-39E8-4452-9063-FBE91D50C6DA}']
    /// <summary>The number of trusted roots.</summary>
    function AnchorCount: Int32;
    /// <summary>The trusted root CA certificates, DER-encoded, as a fresh copy: for one-time
    /// consumers, not the per-handshake path (use IsAnchor there).</summary>
    function RootCertificates: TArray<TBytes>;
    /// <summary>True when ACertificate is byte-for-byte one of the trusted roots.</summary>
    function IsAnchor(const ACertificate: TBytes): Boolean;
    /// <summary>The distrusted certificates, DER-encoded, as a fresh copy.</summary>
    function DistrustedCertificates: TArray<TBytes>;
    /// <summary>True when ACertificate is byte-for-byte one of the distrusted certificates (a
    /// re-issued certificate with the same key is a different certificate).</summary>
    function IsDistrusted(const ACertificate: TBytes): Boolean;
  end;

implementation

end.
