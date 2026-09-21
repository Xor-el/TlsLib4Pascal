{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpExtensionContext;

{$I ..\Include\TlsLib.inc}

interface

uses
  SysUtils,
  TlpArrayUtilities;

type
  /// <summary>
  /// The handshake message an extension block belongs to (RFC 8446 4.2). Only
  /// ClientHello is a request the peer originates unprompted; every other kind is
  /// a response and may carry only extensions the ClientHello offered.
  /// </summary>
  TTlsExtensionContextKind = (
    ClientHello,
    ServerHello,
    HelloRetryRequest,
    EncryptedExtensions,
    Certificate,
    CertificateRequest,
    NewSessionTicket);

  /// <summary>The set of message kinds an extension is permitted to appear in.</summary>
  TTlsExtensionContexts = set of TTlsExtensionContextKind;

  /// <summary>A key_share entry: a named group and its key-exchange bytes.</summary>
  TTlsKeyShareEntry = record
    Group: UInt16;
    KeyExchange: TBytes;
  end;

  /// <summary>
  /// The shared negotiation state the extensions read and write. Each extension
  /// parses its wire form into these fields (inbound) or serializes them (outbound);
  /// the negotiation policy then reads/decides over the same object. MessageContext
  /// is the kind currently being produced or consumed, so an extension can format
  /// itself per message (e.g. the ClientHello version list versus the ServerHello
  /// single selection).
  /// </summary>
  TExtensionContext = class sealed(TObject)
  strict private
  var
    FOfferedTypes: TArray<UInt16>;
  public
    MessageContext: TTlsExtensionContextKind;
    SupportedVersions: TArray<UInt16>;
    SelectedVersion: UInt16;
    SupportedGroups: TArray<UInt16>;
    ClientKeyShares: TArray<TTlsKeyShareEntry>;
    SelectedKeyShare: TTlsKeyShareEntry;
    HelloRetryGroup: UInt16;
    SignatureSchemes: TArray<UInt16>;
    SignatureSchemesCert: TArray<UInt16>;
    /// <summary>certificate_authorities (RFC 8446 4.2.4 / RFC 5246 7.4.4): the DER-encoded
    /// DistinguishedName issuers a server names in its CertificateRequest. Set outbound to
    /// emit them; populated inbound on the client from a received CertificateRequest.</summary>
    CertificateAuthorities: TArray<TBytes>;
    ServerName: string;
    /// <summary>server_name acknowledgement (RFC 6066 3): set true on the server to echo an
    /// empty server_name in the ServerHello (TLS 1.2) or EncryptedExtensions (TLS 1.3) when the
    /// client offered a host_name.</summary>
    ServerNameAck: Boolean;
    AlpnProtocols: TArray<string>;
    SelectedAlpn: string;
    Cookie: TBytes;
    RecordSizeLimit: Int32;
    CertCompressionAlgorithms: TArray<UInt16>;
    /// <summary>extended_master_secret (RFC 7627): set to offer it (ClientHello) or
    /// echo it (ServerHello) outbound, and set true inbound when the peer's empty
    /// extension is present. A TLS 1.2-only signalling flag.</summary>
    ExtendedMasterSecret: Boolean;
    /// <summary>renegotiation_info (RFC 5746): set to signal support (empty on an initial
    /// handshake) and set true inbound when the peer's extension is present. TLS 1.2-only
    /// secure-renegotiation signalling, even though renegotiation itself is never done.</summary>
    RenegotiationInfo: Boolean;
    /// <summary>psk_key_exchange_modes (RFC 8446 4.2.9): the modes the client offers
    /// (0 = psk_ke, 1 = psk_dhe_ke).</summary>
    PskModes: TBytes;
    /// <summary>pre_shared_key (RFC 8446 4.2.11) ClientHello identities, one opaque ticket each.</summary>
    OfferedPskIdentities: TArray<TBytes>;
    /// <summary>The obfuscated_ticket_age accompanying each offered identity.</summary>
    OfferedPskAges: TArray<UInt32>;
    /// <summary>The binder for each offered identity (a zero placeholder until back-patched).</summary>
    OfferedPskBinders: TArray<TBytes>;
    /// <summary>Whether the ServerHello selected a PSK (the pre_shared_key response is present).</summary>
    PskSelected: Boolean;
    /// <summary>The index into the offered identities the server selected.</summary>
    SelectedPskIdentity: UInt16;
    /// <summary>early_data (RFC 8446 4.2.10): present (empty) in the ClientHello offering 0-RTT.</summary>
    EarlyDataOffered: Boolean;
    /// <summary>early_data present (empty) in EncryptedExtensions accepting 0-RTT.</summary>
    EarlyDataAccepted: Boolean;
    /// <summary>early_data max_early_data_size carried in a NewSessionTicket.</summary>
    EarlyDataMaxSize: UInt32;
    /// <summary>session_ticket (RFC 5077): present in the ClientHello to indicate ticket
    /// support, and echoed empty by a 1.2 server that will send a NewSessionTicket. Set
    /// true outbound to emit it and true inbound when the peer's extension is present.</summary>
    SessionTicketOffered: Boolean;
    /// <summary>The session_ticket extension_data: the opaque ticket a client presents to
    /// resume (empty when only indicating support, and always empty on a server echo).</summary>
    SessionTicket: TBytes;
    /// <summary>ec_point_formats (RFC 8422 5.1.2): set true outbound to list support for
    /// the uncompressed point format (a client offering ECC suites, or a 1.2 server that
    /// selected an ECC suite), and set true inbound when the peer's extension is present.</summary>
    EcPointFormatsOffered: Boolean;
    /// <summary>status_request (RFC 6066): set true outbound in the ClientHello to offer
    /// acceptance of a stapled OCSP response, and set true inbound (server side) when the
    /// client's status_request is present.</summary>
    StatusRequestOffered: Boolean;
    /// <summary>status_request response signal: set true by a 1.2 server that will staple
    /// (echoed as an empty status_request in the ServerHello), and set true inbound on the
    /// client when that echo is present so it expects a CertificateStatus message.</summary>
    StatusRequestResponsePending: Boolean;
    /// <summary>encrypted_client_hello (RFC 9849 5): the extension_data to emit for the current
    /// message kind - the outer/inner form in a ClientHello, the 8-byte confirmation in a
    /// HelloRetryRequest, or retry_configs in EncryptedExtensions. Empty to omit the extension.
    /// The ECH machinery builds this body; the extension only frames it.</summary>
    EchExtensionData: TBytes;
    /// <summary>Set true inbound when the peer's encrypted_client_hello was present.</summary>
    EchPresent: Boolean;

    /// <summary>Records that an extension type was offered in the ClientHello.</summary>
    procedure MarkOffered(AExtensionType: UInt16);
    /// <summary>Whether an extension type was offered in the ClientHello.</summary>
    function WasOffered(AExtensionType: UInt16): Boolean;
  end;

implementation

{ TExtensionContext }

procedure TExtensionContext.MarkOffered(AExtensionType: UInt16);
begin
  if WasOffered(AExtensionType) then
    Exit;
  TArrayUtilities.Append<UInt16>(FOfferedTypes, AExtensionType);
end;

function TExtensionContext.WasOffered(AExtensionType: UInt16): Boolean;
begin
  Result := TArrayUtilities.Contains<UInt16>(FOfferedTypes, AExtensionType);
end;

end.
