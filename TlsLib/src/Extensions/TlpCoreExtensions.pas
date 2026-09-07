{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpCoreExtensions;

{$I ..\Include\TlsLib.inc}

interface

uses
  SysUtils,
  TlpWireReader,
  TlpWireVectorMarker,
  TlpIWireWriter,
  TlpWireWriter,
  TlpTlsLibExceptions,
  TlpExtensionContext,
  TlpExtensionBlockCodec,
  TlpITlsExtension;

type
  /// <summary>Extension-type wire codepoints (IANA TLS ExtensionType registry).</summary>
  TExtensionTypes = class sealed(TObject)
  public const
    ServerName = UInt16(0);
    StatusRequest = UInt16(5);
    SupportedGroups = UInt16(10);
    EcPointFormats = UInt16(11);
    SignatureAlgorithms = UInt16(13);
    Alpn = UInt16(16);
    CompressCertificate = UInt16(27);
    RecordSizeLimit = UInt16(28);
    SignatureAlgorithmsCert = UInt16(50);
    CertificateAuthorities = UInt16(47);
    SupportedVersions = UInt16(43);
    Cookie = UInt16(44);
    KeyShare = UInt16(51);
    ExtendedMasterSecret = UInt16(23);
    RenegotiationInfo = UInt16($FF01);
    SessionTicket = UInt16(35);
    PreSharedKey = UInt16(41);
    EarlyData = UInt16(42);
    PskKeyExchangeModes = UInt16(45);
    EncryptedClientHello = UInt16($FE0D);
    EchOuterExtensions = UInt16($FD00);
  end;

  /// <summary>supported_versions (RFC 8446 4.2.1): a version list in the ClientHello, one selection in the ServerHello/HRR.</summary>
  TSupportedVersionsExtension = class sealed(TInterfacedObject, ITlsExtension)
  public
    function ExtensionType: UInt16;
    function ValidContexts: TTlsExtensionContexts;
    function Produce(const AContext: TExtensionContext; out ABody: TBytes): Boolean;
    procedure Consume(const AContext: TExtensionContext; const AExtensionData: TBytes);
  end;

  /// <summary>supported_groups (RFC 8446 4.2.7): the named groups the client accepts.</summary>
  TSupportedGroupsExtension = class sealed(TInterfacedObject, ITlsExtension)
  public
    function ExtensionType: UInt16;
    function ValidContexts: TTlsExtensionContexts;
    function Produce(const AContext: TExtensionContext; out ABody: TBytes): Boolean;
    procedure Consume(const AContext: TExtensionContext; const AExtensionData: TBytes);
  end;

  /// <summary>ec_point_formats (RFC 8422 5.1.2): a client offering ECC cipher suites for
  /// TLS 1.2 lists the point formats it supports (only uncompressed); a 1.2 server that
  /// selected an ECC suite echoes it. Strict peers reject ECDHE without it. Ignored in
  /// TLS 1.3.</summary>
  TEcPointFormatsExtension = class sealed(TInterfacedObject, ITlsExtension)
  public
    function ExtensionType: UInt16;
    function ValidContexts: TTlsExtensionContexts;
    function Produce(const AContext: TExtensionContext; out ABody: TBytes): Boolean;
    procedure Consume(const AContext: TExtensionContext; const AExtensionData: TBytes);
  end;

  /// <summary>signature_algorithms / signature_algorithms_cert (RFC 8446 4.2.3).</summary>
  TSignatureAlgorithmsExtension = class sealed(TInterfacedObject, ITlsExtension)
  strict private
  var
    FIsCertVariant: Boolean;
  public
    constructor Create(AIsCertVariant: Boolean);
    function ExtensionType: UInt16;
    function ValidContexts: TTlsExtensionContexts;
    function Produce(const AContext: TExtensionContext; out ABody: TBytes): Boolean;
    procedure Consume(const AContext: TExtensionContext; const AExtensionData: TBytes);
  end;

  /// <summary>certificate_authorities (RFC 8446 4.2.4): a server may send it in a
  /// CertificateRequest to constrain the acceptable client-certificate issuers. We do not
  /// pin issuers, so it is never produced; on receipt its structure is validated (non-empty
  /// authorities, each a non-empty DistinguishedName, no trailing data) and the content ignored.</summary>
  TCertificateAuthoritiesExtension = class sealed(TInterfacedObject, ITlsExtension)
  public
    function ExtensionType: UInt16;
    function ValidContexts: TTlsExtensionContexts;
    function Produce(const AContext: TExtensionContext; out ABody: TBytes): Boolean;
    procedure Consume(const AContext: TExtensionContext; const AExtensionData: TBytes);
  end;

  /// <summary>extended_master_secret (RFC 7627): an empty flag the client offers in the ClientHello and a 1.2 server echoes in the ServerHello.</summary>
  TExtendedMasterSecretExtension = class sealed(TInterfacedObject, ITlsExtension)
  public
    function ExtensionType: UInt16;
    function ValidContexts: TTlsExtensionContexts;
    function Produce(const AContext: TExtensionContext; out ABody: TBytes): Boolean;
    procedure Consume(const AContext: TExtensionContext; const AExtensionData: TBytes);
  end;

  /// <summary>renegotiation_info (RFC 5746): the initial-handshake secure-renegotiation signal (an empty renegotiated_connection); the client offers it and a 1.2 server echoes it.</summary>
  TRenegotiationInfoExtension = class sealed(TInterfacedObject, ITlsExtension)
  public
    function ExtensionType: UInt16;
    function ValidContexts: TTlsExtensionContexts;
    function Produce(const AContext: TExtensionContext; out ABody: TBytes): Boolean;
    procedure Consume(const AContext: TExtensionContext; const AExtensionData: TBytes);
  end;

  /// <summary>key_share (RFC 8446 4.2.8): offered shares in the ClientHello, the selected share in the ServerHello, the requested group in a HelloRetryRequest.</summary>
  TKeyShareExtension = class sealed(TInterfacedObject, ITlsExtension)
  public
    function ExtensionType: UInt16;
    function ValidContexts: TTlsExtensionContexts;
    function Produce(const AContext: TExtensionContext; out ABody: TBytes): Boolean;
    procedure Consume(const AContext: TExtensionContext; const AExtensionData: TBytes);
  end;

  /// <summary>server_name / SNI (RFC 6066): the host in the ClientHello, an empty acknowledgement in EncryptedExtensions.</summary>
  TServerNameExtension = class sealed(TInterfacedObject, ITlsExtension)
  public
    function ExtensionType: UInt16;
    function ValidContexts: TTlsExtensionContexts;
    function Produce(const AContext: TExtensionContext; out ABody: TBytes): Boolean;
    procedure Consume(const AContext: TExtensionContext; const AExtensionData: TBytes);
  end;

  /// <summary>application_layer_protocol_negotiation / ALPN (RFC 7301).</summary>
  TAlpnExtension = class sealed(TInterfacedObject, ITlsExtension)
  public
    function ExtensionType: UInt16;
    function ValidContexts: TTlsExtensionContexts;
    function Produce(const AContext: TExtensionContext; out ABody: TBytes): Boolean;
    procedure Consume(const AContext: TExtensionContext; const AExtensionData: TBytes);
  end;

  /// <summary>status_request / OCSP stapling (RFC 6066 8): the client offers a
  /// CertificateStatusRequest to signal it accepts a stapled OCSP response; a 1.2 server
  /// echoes it empty in the ServerHello to signal it will send a CertificateStatus message.
  /// The stapled response itself rides the Certificate message, not this extension.</summary>
  TStatusRequestExtension = class sealed(TInterfacedObject, ITlsExtension)
  public
    function ExtensionType: UInt16;
    function ValidContexts: TTlsExtensionContexts;
    function Produce(const AContext: TExtensionContext; out ABody: TBytes): Boolean;
    procedure Consume(const AContext: TExtensionContext; const AExtensionData: TBytes);
  end;

  /// <summary>cookie (RFC 8446 4.2.2): sent by a HelloRetryRequest, echoed by the next ClientHello.</summary>
  TCookieExtension = class sealed(TInterfacedObject, ITlsExtension)
  public
    function ExtensionType: UInt16;
    function ValidContexts: TTlsExtensionContexts;
    function Produce(const AContext: TExtensionContext; out ABody: TBytes): Boolean;
    procedure Consume(const AContext: TExtensionContext; const AExtensionData: TBytes);
  end;

  /// <summary>record_size_limit (RFC 8449): the maximum record plaintext each peer will receive.</summary>
  TRecordSizeLimitExtension = class sealed(TInterfacedObject, ITlsExtension)
  public
    function ExtensionType: UInt16;
    function ValidContexts: TTlsExtensionContexts;
    function Produce(const AContext: TExtensionContext; out ABody: TBytes): Boolean;
    procedure Consume(const AContext: TExtensionContext; const AExtensionData: TBytes);
  end;

  /// <summary>compress_certificate (RFC 8879): the certificate-compression algorithms a peer can decompress.</summary>
  TCompressCertificateExtension = class sealed(TInterfacedObject, ITlsExtension)
  public
    function ExtensionType: UInt16;
    function ValidContexts: TTlsExtensionContexts;
    function Produce(const AContext: TExtensionContext; out ABody: TBytes): Boolean;
    procedure Consume(const AContext: TExtensionContext; const AExtensionData: TBytes);
  end;

  /// <summary>Builds a registry with the core extension set, in ClientHello emission order.</summary>
  TCoreExtensions = class sealed(TObject)
  public
    class function CreateDefaultRegistry: IExtensionRegistry; static;
  end;

implementation

uses
  TlpSessionExtensions;

resourcestring
  SUnknownNameType = 'server_name carries an unknown name_type';
  SEmptyHostName = 'server_name host_name is empty';
  SEmptyAlpnProtocol = 'ALPN carries a zero-length protocol name';
  SEmptyAlpnList = 'ALPN protocol list is empty';
  SDuplicateKeyShare = 'key_share offers two entries for the same group';
  SEmptyKeyExchange = 'key_share carries a zero-length key_exchange (RFC 8446 4.2.8)';
  SBadExtendedMasterSecret = 'extended_master_secret must carry an empty body';
  SBadRenegotiationInfo = 'renegotiation_info must be empty on an initial handshake';
  SBadStatusRequestEcho = 'a server status_request response must carry an empty body';
  SNoUncompressedPointFormat = 'ec_point_formats does not offer the uncompressed format';
  SDuplicateCompressionAlg = 'compress_certificate repeats a certificate-compression algorithm';
  SEmptySignatureAlgorithms = 'signature_algorithms names no scheme (RFC 8446 4.2.3 requires at least one)';
  SEmptyCertificateAuthorities = 'certificate_authorities names no authority (RFC 8446 4.2.4 requires at least one)';
  SEmptyDistinguishedName = 'certificate_authorities carries a zero-length DistinguishedName';

type
  /// <summary>Unit-private wire helpers shared by the uint16-list extensions.</summary>
  TExtensionWire = class sealed(TObject)
  public
    class function DecodeUInt16Vector(const AData: TBytes;
      ALenBytes: Int32): TArray<UInt16>; static;
    class function EncodeUInt16Vector(ALenBytes: Int32;
      const AValues: TArray<UInt16>): TBytes; static;
  end;

{ TExtensionWire }

class function TExtensionWire.DecodeUInt16Vector(const AData: TBytes;
  ALenBytes: Int32): TArray<UInt16>;
var
  LReader, LList: TWireReader;
  LCount: Int32;
begin
  Result := nil;
  LReader := TWireReader.Create(AData);
  LList := LReader.OpenVector(ALenBytes);
  LReader.ExpectEnd;
  LCount := 0;
  while not LList.EndReached do
  begin
    SetLength(Result, LCount + 1);
    Result[LCount] := LList.ReadUInt16;
    Inc(LCount);
  end;
end;

class function TExtensionWire.EncodeUInt16Vector(ALenBytes: Int32;
  const AValues: TArray<UInt16>): TBytes;
var
  LWriter: IWireWriter;
  LMarker: TWireVectorMarker;
  LValue: UInt16;
begin
  Result := nil;
  LWriter := TWireWriter.Create;
  LMarker := LWriter.OpenVector(ALenBytes);
  for LValue in AValues do
    LWriter.WriteUInt16(LValue);
  LWriter.CloseVector(LMarker);
  Result := LWriter.ToBytes;
end;

{ TSupportedVersionsExtension }

function TSupportedVersionsExtension.ExtensionType: UInt16;
begin
  Result := TExtensionTypes.SupportedVersions;
end;

function TSupportedVersionsExtension.ValidContexts: TTlsExtensionContexts;
begin
  Result := [TTlsExtensionContextKind.ClientHello,
    TTlsExtensionContextKind.ServerHello,
    TTlsExtensionContextKind.HelloRetryRequest];
end;

function TSupportedVersionsExtension.Produce(const AContext: TExtensionContext;
  out ABody: TBytes): Boolean;
var
  LWriter: IWireWriter;
begin
  ABody := nil;
  if AContext.MessageContext = TTlsExtensionContextKind.ClientHello then
  begin
    Result := System.Length(AContext.SupportedVersions) > 0;
    if Result then
      ABody := TExtensionWire.EncodeUInt16Vector(1, AContext.SupportedVersions);
  end
  else
  begin
    Result := AContext.SelectedVersion <> 0;
    if Result then
    begin
      LWriter := TWireWriter.Create;
      LWriter.WriteUInt16(AContext.SelectedVersion);
      ABody := LWriter.ToBytes;
    end;
  end;
end;

procedure TSupportedVersionsExtension.Consume(const AContext: TExtensionContext;
  const AExtensionData: TBytes);
var
  LReader: TWireReader;
begin
  if AContext.MessageContext = TTlsExtensionContextKind.ClientHello then
    AContext.SupportedVersions := TExtensionWire.DecodeUInt16Vector(AExtensionData, 1)
  else
  begin
    LReader := TWireReader.Create(AExtensionData);
    AContext.SelectedVersion := LReader.ReadUInt16;
    LReader.ExpectEnd;
  end;
end;

{ TSupportedGroupsExtension }

function TSupportedGroupsExtension.ExtensionType: UInt16;
begin
  Result := TExtensionTypes.SupportedGroups;
end;

function TSupportedGroupsExtension.ValidContexts: TTlsExtensionContexts;
begin
  // a TLS 1.2 server may echo supported_groups in the ServerHello (RFC 8422 5.1.2), and a
  // 1.3 server in EncryptedExtensions; the client tolerates and ignores it either way
  Result := [TTlsExtensionContextKind.ClientHello,
    TTlsExtensionContextKind.ServerHello,
    TTlsExtensionContextKind.EncryptedExtensions];
end;

function TSupportedGroupsExtension.Produce(const AContext: TExtensionContext;
  out ABody: TBytes): Boolean;
begin
  ABody := nil;
  Result := System.Length(AContext.SupportedGroups) > 0;
  if Result then
    ABody := TExtensionWire.EncodeUInt16Vector(2, AContext.SupportedGroups);
end;

procedure TSupportedGroupsExtension.Consume(const AContext: TExtensionContext;
  const AExtensionData: TBytes);
begin
  AContext.SupportedGroups := TExtensionWire.DecodeUInt16Vector(AExtensionData, 2);
end;

{ TSignatureAlgorithmsExtension }

constructor TSignatureAlgorithmsExtension.Create(AIsCertVariant: Boolean);
begin
  inherited Create;
  FIsCertVariant := AIsCertVariant;
end;

function TSignatureAlgorithmsExtension.ExtensionType: UInt16;
begin
  if FIsCertVariant then
    Result := TExtensionTypes.SignatureAlgorithmsCert
  else
    Result := TExtensionTypes.SignatureAlgorithms;
end;

function TSignatureAlgorithmsExtension.ValidContexts: TTlsExtensionContexts;
begin
  Result := [TTlsExtensionContextKind.ClientHello,
    TTlsExtensionContextKind.CertificateRequest];
end;

function TSignatureAlgorithmsExtension.Produce(const AContext: TExtensionContext;
  out ABody: TBytes): Boolean;
var
  LSchemes: TArray<UInt16>;
begin
  ABody := nil;
  if FIsCertVariant then
    LSchemes := AContext.SignatureSchemesCert
  else
    LSchemes := AContext.SignatureSchemes;
  Result := System.Length(LSchemes) > 0;
  if Result then
    ABody := TExtensionWire.EncodeUInt16Vector(2, LSchemes);
end;

procedure TSignatureAlgorithmsExtension.Consume(const AContext: TExtensionContext;
  const AExtensionData: TBytes);
var
  LSchemes: TArray<UInt16>;
begin
  LSchemes := TExtensionWire.DecodeUInt16Vector(AExtensionData, 2);
  // the list must name at least one scheme: RFC 8446 4.2.3 encodes it as <2..2^16-2>, so an
  // empty signature_algorithms (e.g. in a CertificateRequest) is a decode error
  if System.Length(LSchemes) = 0 then
    raise EDecodeErrorTlsLibException.CreateRes(@SEmptySignatureAlgorithms);
  if FIsCertVariant then
    AContext.SignatureSchemesCert := LSchemes
  else
    AContext.SignatureSchemes := LSchemes;
end;

{ TKeyShareExtension }

function TKeyShareExtension.ExtensionType: UInt16;
begin
  Result := TExtensionTypes.KeyShare;
end;

function TKeyShareExtension.ValidContexts: TTlsExtensionContexts;
begin
  Result := [TTlsExtensionContextKind.ClientHello,
    TTlsExtensionContextKind.ServerHello,
    TTlsExtensionContextKind.HelloRetryRequest];
end;

function TKeyShareExtension.Produce(const AContext: TExtensionContext;
  out ABody: TBytes): Boolean;
var
  LWriter: IWireWriter;
  LOuter, LInner: TWireVectorMarker;
  LEntry: TTlsKeyShareEntry;
begin
  ABody := nil;
  LWriter := TWireWriter.Create;
  case AContext.MessageContext of
    TTlsExtensionContextKind.ClientHello:
      begin
        Result := System.Length(AContext.ClientKeyShares) > 0;
        if not Result then
          Exit;
        LOuter := LWriter.OpenVector(2); // client_shares
        for LEntry in AContext.ClientKeyShares do
        begin
          LWriter.WriteUInt16(LEntry.Group);
          LInner := LWriter.OpenVector(2);
          LWriter.WriteBytes(LEntry.KeyExchange);
          LWriter.CloseVector(LInner);
        end;
        LWriter.CloseVector(LOuter);
      end;
    TTlsExtensionContextKind.ServerHello:
      begin
        Result := System.Length(AContext.SelectedKeyShare.KeyExchange) > 0;
        if not Result then
          Exit;
        LWriter.WriteUInt16(AContext.SelectedKeyShare.Group);
        LInner := LWriter.OpenVector(2);
        LWriter.WriteBytes(AContext.SelectedKeyShare.KeyExchange);
        LWriter.CloseVector(LInner);
      end;
  else // HelloRetryRequest: the requested group only
    Result := AContext.HelloRetryGroup <> 0;
    if not Result then
      Exit;
    LWriter.WriteUInt16(AContext.HelloRetryGroup);
  end;
  ABody := LWriter.ToBytes;
end;

procedure TKeyShareExtension.Consume(const AContext: TExtensionContext;
  const AExtensionData: TBytes);
var
  LReader, LShares, LKeyEx: TWireReader;
  LEntry: TTlsKeyShareEntry;
  LCount, LI: Int32;
begin
  LReader := TWireReader.Create(AExtensionData);
  case AContext.MessageContext of
    TTlsExtensionContextKind.ClientHello:
      begin
        AContext.ClientKeyShares := nil;
        LShares := LReader.OpenVector(2);
        LReader.ExpectEnd;
        LCount := 0;
        while not LShares.EndReached do
        begin
          LEntry.Group := LShares.ReadUInt16;
          // a client must not offer two shares for the same group (RFC 8446 4.2.8)
          for LI := 0 to LCount - 1 do
            if AContext.ClientKeyShares[LI].Group = LEntry.Group then
              raise EPeerInputTlsLibException.CreateRes(@SDuplicateKeyShare);
          LKeyEx := LShares.OpenVector(2);
          LEntry.KeyExchange := LKeyEx.ReadBytes(LKeyEx.Remaining);
          // opaque key_exchange<1..2^16-1>: an empty share is a decode_error (RFC 8446 4.2.8)
          if System.Length(LEntry.KeyExchange) = 0 then
            raise EDecodeErrorTlsLibException.CreateRes(@SEmptyKeyExchange);
          SetLength(AContext.ClientKeyShares, LCount + 1);
          AContext.ClientKeyShares[LCount] := LEntry;
          Inc(LCount);
        end;
      end;
    TTlsExtensionContextKind.ServerHello:
      begin
        LEntry.Group := LReader.ReadUInt16;
        LKeyEx := LReader.OpenVector(2);
        LEntry.KeyExchange := LKeyEx.ReadBytes(LKeyEx.Remaining);
        // opaque key_exchange<1..2^16-1>: an empty share is a decode_error (RFC 8446 4.2.8)
        if System.Length(LEntry.KeyExchange) = 0 then
          raise EDecodeErrorTlsLibException.CreateRes(@SEmptyKeyExchange);
        LReader.ExpectEnd;
        AContext.SelectedKeyShare := LEntry;
      end;
  else // HelloRetryRequest
    AContext.HelloRetryGroup := LReader.ReadUInt16;
    LReader.ExpectEnd;
  end;
end;

{ TServerNameExtension }

function TServerNameExtension.ExtensionType: UInt16;
begin
  Result := TExtensionTypes.ServerName;
end;

function TServerNameExtension.ValidContexts: TTlsExtensionContexts;
begin
  // ClientHello carries the host; the server's (empty) acknowledgement rides the ServerHello
  // in TLS 1.2 and the EncryptedExtensions in TLS 1.3 (RFC 6066 3 / RFC 8446 4.2)
  Result := [TTlsExtensionContextKind.ClientHello,
    TTlsExtensionContextKind.ServerHello,
    TTlsExtensionContextKind.EncryptedExtensions];
end;

function TServerNameExtension.Produce(const AContext: TExtensionContext;
  out ABody: TBytes): Boolean;
var
  LWriter: IWireWriter;
  LList, LName: TWireVectorMarker;
begin
  ABody := nil;
  // the server acknowledges a client's host_name with an empty server_name (RFC 6066 3),
  // carried in the ServerHello (TLS 1.2) or EncryptedExtensions (TLS 1.3); ABody stays empty
  if AContext.MessageContext in [TTlsExtensionContextKind.ServerHello,
    TTlsExtensionContextKind.EncryptedExtensions] then
    Exit(AContext.ServerNameAck);
  // the ClientHello carries the host itself
  Result := (AContext.MessageContext = TTlsExtensionContextKind.ClientHello) and
    (AContext.ServerName <> '');
  if not Result then
    Exit;
  LWriter := TWireWriter.Create;
  LList := LWriter.OpenVector(2); // server_name_list
  LWriter.WriteUInt8(0);          // name_type = host_name
  LName := LWriter.OpenVector(2);
  LWriter.WriteBytes(TEncoding.ASCII.GetBytes(AContext.ServerName));
  LWriter.CloseVector(LName);
  LWriter.CloseVector(LList);
  ABody := LWriter.ToBytes;
end;

procedure TServerNameExtension.Consume(const AContext: TExtensionContext;
  const AExtensionData: TBytes);
var
  LReader, LList, LName: TWireReader;
  LNameType: Byte;
  LHost: TBytes;
begin
  // the server's EncryptedExtensions echo is an empty extension - accept and ignore
  if System.Length(AExtensionData) = 0 then
    Exit;
  LReader := TWireReader.Create(AExtensionData);
  LList := LReader.OpenVector(2);
  LReader.ExpectEnd;
  // only host_name is defined; anything else is a decode error (RFC 6066 3)
  LNameType := LList.ReadUInt8;
  if LNameType <> 0 then
    raise EDecodeErrorTlsLibException.CreateRes(@SUnknownNameType);
  LName := LList.OpenVector(2);
  LHost := LName.ReadBytes(LName.Remaining);
  // exactly one host_name, and it may not be empty
  LList.ExpectEnd;
  if System.Length(LHost) = 0 then
    raise EDecodeErrorTlsLibException.CreateRes(@SEmptyHostName);
  AContext.ServerName := TEncoding.ASCII.GetString(LHost);
end;

{ TAlpnExtension }

function TAlpnExtension.ExtensionType: UInt16;
begin
  Result := TExtensionTypes.Alpn;
end;

function TAlpnExtension.ValidContexts: TTlsExtensionContexts;
begin
  // the server's selection rides EncryptedExtensions in 1.3 and the ServerHello in 1.2
  Result := [TTlsExtensionContextKind.ClientHello,
    TTlsExtensionContextKind.ServerHello,
    TTlsExtensionContextKind.EncryptedExtensions];
end;

function TAlpnExtension.Produce(const AContext: TExtensionContext;
  out ABody: TBytes): Boolean;
var
  LWriter: IWireWriter;
  LList, LName: TWireVectorMarker;
  LProtocol: string;
begin
  ABody := nil;
  LWriter := TWireWriter.Create;
  // the server's single selection rides EncryptedExtensions in 1.3 and the ServerHello in 1.2;
  // the ClientHello carries the offered list
  if AContext.MessageContext in [TTlsExtensionContextKind.EncryptedExtensions,
    TTlsExtensionContextKind.ServerHello] then
  begin
    Result := AContext.SelectedAlpn <> '';
    if not Result then
      Exit;
    LList := LWriter.OpenVector(2);
    LName := LWriter.OpenVector(1);
    LWriter.WriteBytes(TEncoding.ASCII.GetBytes(AContext.SelectedAlpn));
    LWriter.CloseVector(LName);
    LWriter.CloseVector(LList);
  end
  else
  begin
    Result := System.Length(AContext.AlpnProtocols) > 0;
    if not Result then
      Exit;
    LList := LWriter.OpenVector(2);
    for LProtocol in AContext.AlpnProtocols do
    begin
      LName := LWriter.OpenVector(1);
      LWriter.WriteBytes(TEncoding.ASCII.GetBytes(LProtocol));
      LWriter.CloseVector(LName);
    end;
    LWriter.CloseVector(LList);
  end;
  ABody := LWriter.ToBytes;
end;

procedure TAlpnExtension.Consume(const AContext: TExtensionContext;
  const AExtensionData: TBytes);
var
  LReader, LList, LName: TWireReader;
  LProtocol: TBytes;
  LCount: Int32;
begin
  LReader := TWireReader.Create(AExtensionData);
  LList := LReader.OpenVector(2);
  LReader.ExpectEnd;
  if (AContext.MessageContext = TTlsExtensionContextKind.EncryptedExtensions) or
    (AContext.MessageContext = TTlsExtensionContextKind.ServerHello) then
  begin
    LName := LList.OpenVector(1);
    LProtocol := LName.ReadBytes(LName.Remaining);
    LList.ExpectEnd;
    // the server's selection is exactly one non-empty protocol (RFC 7301 3.1)
    if System.Length(LProtocol) = 0 then
      raise EDecodeErrorTlsLibException.CreateRes(@SEmptyAlpnProtocol);
    AContext.SelectedAlpn := TEncoding.ASCII.GetString(LProtocol);
  end
  else
  begin
    AContext.AlpnProtocols := nil;
    LCount := 0;
    while not LList.EndReached do
    begin
      LName := LList.OpenVector(1);
      LProtocol := LName.ReadBytes(LName.Remaining);
      if System.Length(LProtocol) = 0 then
        raise EDecodeErrorTlsLibException.CreateRes(@SEmptyAlpnProtocol);
      SetLength(AContext.AlpnProtocols, LCount + 1);
      AContext.AlpnProtocols[LCount] := TEncoding.ASCII.GetString(LProtocol);
      Inc(LCount);
    end;
    // the ProtocolNameList must carry at least one protocol (RFC 7301 3.1)
    if LCount = 0 then
      raise EDecodeErrorTlsLibException.CreateRes(@SEmptyAlpnList);
  end;
end;

{ TEcPointFormatsExtension }

function TEcPointFormatsExtension.ExtensionType: UInt16;
begin
  Result := TExtensionTypes.EcPointFormats;
end;

function TEcPointFormatsExtension.ValidContexts: TTlsExtensionContexts;
begin
  Result := [TTlsExtensionContextKind.ClientHello,
    TTlsExtensionContextKind.ServerHello];
end;

function TEcPointFormatsExtension.Produce(const AContext: TExtensionContext;
  out ABody: TBytes): Boolean;
begin
  // ec_point_formats<1..2^8-1> = a 1-byte-length vector holding only uncompressed(0)
  ABody := nil;
  Result := AContext.EcPointFormatsOffered;
  if Result then
    ABody := TBytes.Create($01, $00);
end;

procedure TEcPointFormatsExtension.Consume(const AContext: TExtensionContext;
  const AExtensionData: TBytes);
var
  LReader, LList: TWireReader;
  LFormats: TBytes;
  LI: Int32;
  LHasUncompressed: Boolean;
begin
  LReader := TWireReader.Create(AExtensionData);
  LList := LReader.OpenVector(1);
  LReader.ExpectEnd;
  LFormats := LList.ReadBytes(LList.Remaining);
  // the peer must offer the uncompressed format
  LHasUncompressed := False;
  for LI := 0 to System.High(LFormats) do
    if LFormats[LI] = 0 then
    begin
      LHasUncompressed := True;
      Break;
    end;
  if not LHasUncompressed then
    raise EDecodeErrorTlsLibException.CreateRes(@SNoUncompressedPointFormat);
  AContext.EcPointFormatsOffered := True;
end;

{ TStatusRequestExtension }

function TStatusRequestExtension.ExtensionType: UInt16;
begin
  Result := TExtensionTypes.StatusRequest;
end;

function TStatusRequestExtension.ValidContexts: TTlsExtensionContexts;
begin
  // the ClientHello offer and the 1.2 ServerHello echo; the 1.3 staple rides the
  // Certificate message, never EncryptedExtensions
  Result := [TTlsExtensionContextKind.ClientHello,
    TTlsExtensionContextKind.ServerHello];
end;

function TStatusRequestExtension.Produce(const AContext: TExtensionContext;
  out ABody: TBytes): Boolean;
var
  LWriter: IWireWriter;
begin
  ABody := nil;
  if AContext.MessageContext = TTlsExtensionContextKind.ServerHello then
  begin
    // a 1.2 server that will staple echoes an empty status_request
    Result := AContext.StatusRequestResponsePending;
    Exit;
  end;
  // ClientHello: CertificateStatusRequest = status_type(ocsp) + empty responder_id_list
  // + empty request_extensions (RFC 6066 8)
  Result := AContext.StatusRequestOffered;
  if not Result then
    Exit;
  LWriter := TWireWriter.Create;
  LWriter.WriteUInt8(1); // CertificateStatusType.ocsp
  LWriter.WriteUInt16(0); // responder_id_list<0..2^16-1>
  LWriter.WriteUInt16(0); // request_extensions<0..2^16-1>
  ABody := LWriter.ToBytes;
end;

procedure TStatusRequestExtension.Consume(const AContext: TExtensionContext;
  const AExtensionData: TBytes);
begin
  if AContext.MessageContext = TTlsExtensionContextKind.ServerHello then
  begin
    // a server response is an empty status_request; the staple follows separately
    if System.Length(AExtensionData) <> 0 then
      raise EDecodeErrorTlsLibException.CreateRes(@SBadStatusRequestEcho);
    AContext.StatusRequestResponsePending := True;
    Exit;
  end;
  // ClientHello: the client accepts a stapled response. The exact request contents
  // do not constrain the server, so acceptance is the whole signal.
  AContext.StatusRequestOffered := True;
end;

{ TCookieExtension }

function TCookieExtension.ExtensionType: UInt16;
begin
  Result := TExtensionTypes.Cookie;
end;

function TCookieExtension.ValidContexts: TTlsExtensionContexts;
begin
  Result := [TTlsExtensionContextKind.ClientHello,
    TTlsExtensionContextKind.HelloRetryRequest];
end;

function TCookieExtension.Produce(const AContext: TExtensionContext;
  out ABody: TBytes): Boolean;
var
  LWriter: IWireWriter;
  LMarker: TWireVectorMarker;
begin
  ABody := nil;
  Result := System.Length(AContext.Cookie) > 0;
  if not Result then
    Exit;
  LWriter := TWireWriter.Create;
  LMarker := LWriter.OpenVector(2);
  LWriter.WriteBytes(AContext.Cookie);
  LWriter.CloseVector(LMarker);
  ABody := LWriter.ToBytes;
end;

procedure TCookieExtension.Consume(const AContext: TExtensionContext;
  const AExtensionData: TBytes);
var
  LReader, LCookie: TWireReader;
begin
  LReader := TWireReader.Create(AExtensionData);
  LCookie := LReader.OpenVector(2);
  LReader.ExpectEnd;
  AContext.Cookie := LCookie.ReadBytes(LCookie.Remaining);
end;

{ TRecordSizeLimitExtension }

function TRecordSizeLimitExtension.ExtensionType: UInt16;
begin
  Result := TExtensionTypes.RecordSizeLimit;
end;

function TRecordSizeLimitExtension.ValidContexts: TTlsExtensionContexts;
begin
  Result := [TTlsExtensionContextKind.ClientHello,
    TTlsExtensionContextKind.EncryptedExtensions];
end;

function TRecordSizeLimitExtension.Produce(const AContext: TExtensionContext;
  out ABody: TBytes): Boolean;
var
  LWriter: IWireWriter;
begin
  ABody := nil;
  Result := AContext.RecordSizeLimit > 0;
  if not Result then
    Exit;
  LWriter := TWireWriter.Create;
  LWriter.WriteUInt16(UInt16(AContext.RecordSizeLimit));
  ABody := LWriter.ToBytes;
end;

procedure TRecordSizeLimitExtension.Consume(const AContext: TExtensionContext;
  const AExtensionData: TBytes);
var
  LReader: TWireReader;
begin
  LReader := TWireReader.Create(AExtensionData);
  AContext.RecordSizeLimit := LReader.ReadUInt16;
  LReader.ExpectEnd;
end;

{ TCompressCertificateExtension }

function TCompressCertificateExtension.ExtensionType: UInt16;
begin
  Result := TExtensionTypes.CompressCertificate;
end;

function TCompressCertificateExtension.ValidContexts: TTlsExtensionContexts;
begin
  Result := [TTlsExtensionContextKind.ClientHello,
    TTlsExtensionContextKind.CertificateRequest];
end;

function TCompressCertificateExtension.Produce(const AContext: TExtensionContext;
  out ABody: TBytes): Boolean;
begin
  ABody := nil;
  Result := System.Length(AContext.CertCompressionAlgorithms) > 0;
  if Result then
    // algorithms<2..2^8-2>: a 1-byte-length vector of uint16 algorithm codes
    ABody := TExtensionWire.EncodeUInt16Vector(1, AContext.CertCompressionAlgorithms);
end;

procedure TCompressCertificateExtension.Consume(const AContext: TExtensionContext;
  const AExtensionData: TBytes);
var
  LAlgorithms: TArray<UInt16>;
  LI, LJ: Int32;
begin
  LAlgorithms := TExtensionWire.DecodeUInt16Vector(AExtensionData, 1);
  // a repeated algorithm makes the advertised list malformed (RFC 8879 3)
  for LI := 0 to High(LAlgorithms) do
    for LJ := LI + 1 to High(LAlgorithms) do
      if LAlgorithms[LI] = LAlgorithms[LJ] then
        raise EDecodeErrorTlsLibException.CreateRes(@SDuplicateCompressionAlg);
  AContext.CertCompressionAlgorithms := LAlgorithms;
end;

{ TCertificateAuthoritiesExtension }

function TCertificateAuthoritiesExtension.ExtensionType: UInt16;
begin
  Result := TExtensionTypes.CertificateAuthorities;
end;

function TCertificateAuthoritiesExtension.ValidContexts: TTlsExtensionContexts;
begin
  Result := [TTlsExtensionContextKind.ClientHello,
    TTlsExtensionContextKind.CertificateRequest];
end;

function TCertificateAuthoritiesExtension.Produce(const AContext: TExtensionContext;
  out ABody: TBytes): Boolean;
var
  LWriter: IWireWriter;
  LList, LDn: TWireVectorMarker;
  LName: TBytes;
begin
  // a server names its acceptable certificate issuers in the CertificateRequest when
  // configured; otherwise the extension is not offered (RFC 8446 4.2.4)
  ABody := nil;
  Result := (AContext.MessageContext = TTlsExtensionContextKind.CertificateRequest) and
    (System.Length(AContext.CertificateAuthorities) > 0);
  if not Result then
    Exit;
  LWriter := TWireWriter.Create;
  LList := LWriter.OpenVector(2); // DistinguishedName authorities<3..2^16-1>
  for LName in AContext.CertificateAuthorities do
  begin
    LDn := LWriter.OpenVector(2); // DistinguishedName opaque<1..2^16-1>
    LWriter.WriteBytes(LName);
    LWriter.CloseVector(LDn);
  end;
  LWriter.CloseVector(LList);
  ABody := LWriter.ToBytes;
end;

procedure TCertificateAuthoritiesExtension.Consume(const AContext: TExtensionContext;
  const AExtensionData: TBytes);
var
  LReader, LList, LDn: TWireReader;
  LNames: TArray<TBytes>;
  LCount: Int32;
begin
  // DistinguishedName authorities<3..2^16-1>, each DistinguishedName opaque<1..2^16-1>
  // (RFC 8446 4.2.4). The parsed issuer names are surfaced on the context.
  LReader := TWireReader.Create(AExtensionData);
  LList := LReader.OpenVector(2);
  LReader.ExpectEnd; // no trailing data after the authorities vector
  LNames := nil;
  LCount := 0;
  while not LList.EndReached do
  begin
    LDn := LList.OpenVector(2);
    if LDn.Remaining = 0 then
      raise EDecodeErrorTlsLibException.CreateRes(@SEmptyDistinguishedName);
    SetLength(LNames, LCount + 1);
    LNames[LCount] := LDn.ReadBytes(LDn.Remaining);
    Inc(LCount);
  end;
  if LCount = 0 then
    raise EDecodeErrorTlsLibException.CreateRes(@SEmptyCertificateAuthorities);
  AContext.CertificateAuthorities := LNames;
end;

{ TExtendedMasterSecretExtension }

function TExtendedMasterSecretExtension.ExtensionType: UInt16;
begin
  Result := TExtensionTypes.ExtendedMasterSecret;
end;

function TExtendedMasterSecretExtension.ValidContexts: TTlsExtensionContexts;
begin
  Result := [TTlsExtensionContextKind.ClientHello,
    TTlsExtensionContextKind.ServerHello];
end;

function TExtendedMasterSecretExtension.Produce(const AContext: TExtensionContext;
  out ABody: TBytes): Boolean;
begin
  // an empty extension: presence is the whole signal (RFC 7627 5.1)
  ABody := nil;
  Result := AContext.ExtendedMasterSecret;
end;

procedure TExtendedMasterSecretExtension.Consume(const AContext: TExtensionContext;
  const AExtensionData: TBytes);
begin
  if System.Length(AExtensionData) <> 0 then
    raise EDecodeErrorTlsLibException.CreateRes(@SBadExtendedMasterSecret);
  AContext.ExtendedMasterSecret := True;
end;

{ TRenegotiationInfoExtension }

function TRenegotiationInfoExtension.ExtensionType: UInt16;
begin
  Result := TExtensionTypes.RenegotiationInfo;
end;

function TRenegotiationInfoExtension.ValidContexts: TTlsExtensionContexts;
begin
  Result := [TTlsExtensionContextKind.ClientHello,
    TTlsExtensionContextKind.ServerHello];
end;

function TRenegotiationInfoExtension.Produce(const AContext: TExtensionContext;
  out ABody: TBytes): Boolean;
begin
  // renegotiated_connection<0..255>: empty on an initial handshake (a single 0x00 length)
  ABody := TBytes.Create($00);
  Result := AContext.RenegotiationInfo;
end;

procedure TRenegotiationInfoExtension.Consume(const AContext: TExtensionContext;
  const AExtensionData: TBytes);
begin
  // the renegotiated_connection must be empty: we never renegotiate (RFC 5746 3.2)
  if (System.Length(AExtensionData) <> 1) or (AExtensionData[0] <> $00) then
    raise EDecodeErrorTlsLibException.CreateRes(@SBadRenegotiationInfo);
  AContext.RenegotiationInfo := True;
end;

{ TCoreExtensions }

class function TCoreExtensions.CreateDefaultRegistry: IExtensionRegistry;
begin
  Result := TExtensionRegistry.Create;
  Result.Add(TServerNameExtension.Create as ITlsExtension);
  Result.Add(TExtendedMasterSecretExtension.Create as ITlsExtension);
  Result.Add(TRenegotiationInfoExtension.Create as ITlsExtension);
  Result.Add(TSupportedGroupsExtension.Create as ITlsExtension);
  Result.Add(TEcPointFormatsExtension.Create as ITlsExtension);
  Result.Add(TSignatureAlgorithmsExtension.Create(False) as ITlsExtension);
  Result.Add(TSignatureAlgorithmsExtension.Create(True) as ITlsExtension);
  Result.Add(TCertificateAuthoritiesExtension.Create as ITlsExtension);
  Result.Add(TAlpnExtension.Create as ITlsExtension);
  Result.Add(TStatusRequestExtension.Create as ITlsExtension);
  Result.Add(TRecordSizeLimitExtension.Create as ITlsExtension);
  Result.Add(TCompressCertificateExtension.Create as ITlsExtension);
  Result.Add(TKeyShareExtension.Create as ITlsExtension);
  // cookie precedes supported_versions so a HelloRetryRequest emits
  // key_share, cookie, supported_versions (RFC 8448 Section 5 order)
  Result.Add(TCookieExtension.Create as ITlsExtension);
  Result.Add(TSupportedVersionsExtension.Create as ITlsExtension);
  // session_ticket (RFC 5077) is a 1.2 mechanism; it precedes the 1.3 PSK extensions
  Result.Add(TSessionTicketExtension.Create as ITlsExtension);
  Result.Add(TPskKeyExchangeModesExtension.Create as ITlsExtension);
  Result.Add(TEarlyDataExtension.Create as ITlsExtension);
  // pre_shared_key MUST be the last ClientHello extension (RFC 8446 4.2.11)
  Result.Add(TPreSharedKeyExtension.Create as ITlsExtension);
end;

end.
