{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpHandshakeEffect;

{$I ..\Include\TlsLib.inc}

interface

uses
  SysUtils,
  TlpTlsAlert,
  TlpTlsVersion,
  TlpCryptoAlgorithms,
  TlpIKeySchedule,
  TlpITlsEngine;

type
  /// <summary>Which record-protection direction a key install targets.</summary>
  TRecordSide = (ReadSide, WriteSide);

  /// <summary>The kind of a handshake effect (an instruction for the driver).</summary>
  THandshakeEffectKind = (
    SendHandshake,        // frame and send a handshake message
    SendChangeCipherSpec, // emit the middlebox-compatibility dummy CCS
    InstallKeys,          // install an epoch's record protection on one side
    SelectAlpn,           // surface the negotiated ALPN protocol
    PeerOcspStaple,       // surface the stapled OCSP response the peer delivered
    SetRecordSizeLimit,   // apply the negotiated record_size_limit to the record layer
    SkipEarlyData,        // enter the 0-RTT reject skip mode on the record layer
    SetEarlyDataLimit,    // cap outbound 0-RTT at the ticket's max_early_data
    RevertWriteToPlaintext, // drop the early-data write epoch back to plaintext (0-RTT + HRR)
    SetEarlyReadEpoch,    // open/close the accepted-0-RTT early-data read window (server)
    RaiseEvent,           // raise an engine event
    AwaitCertificateVerdict, // park the handshake for an out-of-band peer-certificate verdict
    PeerCertificateChain, // surface the validated peer chain for connection info
    RequestedCertificateAuthorities, // surface a CertificateRequest's certificate_authorities
    ConnectionParams,     // surface the negotiated suite/group/resumed for connection info
    HandshakeEstablished, // the handshake completed
    Fail);                // abort with a fatal alert

  /// <summary>
  /// A pure instruction the state machine emits for the driver to carry out. The
  /// states never touch the record layer, key schedule, or event queue directly;
  /// they return these values and the driver applies them.
  /// </summary>
  THandshakeEffect = record
    Kind: THandshakeEffectKind;
    Bytes: TBytes;               // SendHandshake
    Keys: ITrafficKeys;          // InstallKeys
    Side: TRecordSide;           // InstallKeys
    Aead: TAeadAlgorithm;        // InstallKeys (the negotiated suite's AEAD)
    Version: TTlsVersion;        // InstallKeys (which record protection to build)
    Text: string;                // SelectAlpn
    Outbound: Int32;             // SetRecordSizeLimit (max outbound plaintext)
    Inbound: Int32;              // SetRecordSizeLimit (max inbound plaintext)
    Event: TTlsEventKind;        // RaiseEvent
    Chain: TArray<TBytes>;       // AwaitCertificateVerdict (the peer chain, leaf first)
    CipherSuite: UInt16;         // ConnectionParams (the negotiated cipher suite code)
    NamedGroup: UInt16;          // ConnectionParams (0 when none / non-(EC)DHE)
    Resumed: Boolean;            // ConnectionParams (a resumed/abbreviated handshake)
    ServerName: string;          // ConnectionParams (the SNI in play; empty when none)
    Alert: TTlsAlertDescription; // Fail
  end;

  /// <summary>Builds the handshake effect values.</summary>
  THandshakeEffects = class sealed(TObject)
  public
    class function SendHandshake(const ABytes: TBytes): THandshakeEffect; static;
    class function SendChangeCipherSpec: THandshakeEffect; static;
    class function InstallKeys(const AKeys: ITrafficKeys; ASide: TRecordSide;
      AAead: TAeadAlgorithm; const AVersion: TTlsVersion): THandshakeEffect; static;
    class function SelectAlpn(const AProtocol: string): THandshakeEffect; static;
    class function PeerOcspStaple(const AStaple: TBytes): THandshakeEffect; static;
    class function SetRecordSizeLimit(AOutbound, AInbound: Int32): THandshakeEffect; static;
    class function SkipEarlyData(AMaxBytes: Int32): THandshakeEffect; static;
    class function SetEarlyDataLimit(AMaxBytes: Int32): THandshakeEffect; static;
    /// <summary>Reverts the write epoch to plaintext after a HelloRetryRequest rejects offered
    /// 0-RTT: the early-data keys are abandoned and the second ClientHello (and the rest of the
    /// flight) is sent in the clear (RFC 8446 4.2.10).</summary>
    class function RevertWriteToPlaintext: THandshakeEffect; static;
    /// <summary>Opens (AActive) or closes the accepted-0-RTT early-data read window on the record
    /// layer: while open, an application_data record legitimately precedes the handshake
    /// completion (RFC 8446 4.2.10). A server emits it on accepting early data and at
    /// EndOfEarlyData.</summary>
    class function SetEarlyReadEpoch(AActive: Boolean): THandshakeEffect; static;
    class function RaiseEvent(AEvent: TTlsEventKind): THandshakeEffect; static;
    /// <summary>Parks the handshake for an out-of-band peer-certificate verdict: the driver
    /// surfaces AChain and AHostName to the host, which resumes with SetCertificateVerdict.
    /// Emitted only after the built-in trust pipeline has already accepted the chain.</summary>
    class function AwaitCertificateVerdict(const AChain: TArray<TBytes>;
      const AHostName: string): THandshakeEffect; static;
    /// <summary>Surfaces the validated peer certificate chain (leaf first, DER) for
    /// read-only connection info; carries no verdict and never blocks the handshake.</summary>
    class function PeerCertificateChain(
      const AChain: TArray<TBytes>): THandshakeEffect; static;
    /// <summary>Surfaces the DER-encoded DistinguishedName certificate_authorities a peer
    /// named in its CertificateRequest (RFC 8446 4.2.4 / RFC 5246 7.4.4), for read-only
    /// connection info; never blocks the handshake.</summary>
    class function RequestedCertificateAuthorities(
      const AAuthorities: TArray<TBytes>): THandshakeEffect; static;
    /// <summary>Surfaces the negotiated cipher suite, named group (0 when none / non-(EC)DHE),
    /// and whether the handshake was resumed/abbreviated, for read-only connection info.</summary>
    class function ConnectionParams(ACipherSuite, ANamedGroup: UInt16;
      AResumed: Boolean; const AServerName: string): THandshakeEffect; static;
    class function HandshakeEstablished: THandshakeEffect; static;
    class function Fail(AAlert: TTlsAlertDescription): THandshakeEffect; static;
  end;

implementation

{ THandshakeEffects }

class function THandshakeEffects.SendHandshake(
  const ABytes: TBytes): THandshakeEffect;
begin
  Result := Default(THandshakeEffect);
  Result.Kind := THandshakeEffectKind.SendHandshake;
  Result.Bytes := ABytes;
end;

class function THandshakeEffects.SendChangeCipherSpec: THandshakeEffect;
begin
  Result := Default(THandshakeEffect);
  Result.Kind := THandshakeEffectKind.SendChangeCipherSpec;
end;

class function THandshakeEffects.InstallKeys(const AKeys: ITrafficKeys;
  ASide: TRecordSide; AAead: TAeadAlgorithm;
  const AVersion: TTlsVersion): THandshakeEffect;
begin
  Result := Default(THandshakeEffect);
  Result.Kind := THandshakeEffectKind.InstallKeys;
  Result.Keys := AKeys;
  Result.Side := ASide;
  Result.Aead := AAead;
  Result.Version := AVersion;
end;

class function THandshakeEffects.SelectAlpn(
  const AProtocol: string): THandshakeEffect;
begin
  Result := Default(THandshakeEffect);
  Result.Kind := THandshakeEffectKind.SelectAlpn;
  Result.Text := AProtocol;
end;

class function THandshakeEffects.PeerOcspStaple(
  const AStaple: TBytes): THandshakeEffect;
begin
  Result := Default(THandshakeEffect);
  Result.Kind := THandshakeEffectKind.PeerOcspStaple;
  Result.Bytes := AStaple;
end;

class function THandshakeEffects.SetRecordSizeLimit(
  AOutbound, AInbound: Int32): THandshakeEffect;
begin
  Result := Default(THandshakeEffect);
  Result.Kind := THandshakeEffectKind.SetRecordSizeLimit;
  Result.Outbound := AOutbound;
  Result.Inbound := AInbound;
end;

class function THandshakeEffects.SkipEarlyData(AMaxBytes: Int32): THandshakeEffect;
begin
  Result := Default(THandshakeEffect);
  Result.Kind := THandshakeEffectKind.SkipEarlyData;
  Result.Inbound := AMaxBytes; // the byte budget for undecryptable early records
end;

class function THandshakeEffects.SetEarlyDataLimit(AMaxBytes: Int32): THandshakeEffect;
begin
  Result := Default(THandshakeEffect);
  Result.Kind := THandshakeEffectKind.SetEarlyDataLimit;
  Result.Outbound := AMaxBytes; // the outbound 0-RTT byte budget from the ticket
end;

class function THandshakeEffects.RevertWriteToPlaintext: THandshakeEffect;
begin
  Result := Default(THandshakeEffect);
  Result.Kind := THandshakeEffectKind.RevertWriteToPlaintext;
end;

class function THandshakeEffects.SetEarlyReadEpoch(AActive: Boolean): THandshakeEffect;
begin
  Result := Default(THandshakeEffect);
  Result.Kind := THandshakeEffectKind.SetEarlyReadEpoch;
  Result.Resumed := AActive; // the early-data read window is open (True) or closed (False)
end;

class function THandshakeEffects.RaiseEvent(AEvent: TTlsEventKind): THandshakeEffect;
begin
  Result := Default(THandshakeEffect);
  Result.Kind := THandshakeEffectKind.RaiseEvent;
  Result.Event := AEvent;
end;

class function THandshakeEffects.AwaitCertificateVerdict(
  const AChain: TArray<TBytes>; const AHostName: string): THandshakeEffect;
begin
  Result := Default(THandshakeEffect);
  Result.Kind := THandshakeEffectKind.AwaitCertificateVerdict;
  Result.Chain := AChain;
  Result.Text := AHostName;
end;

class function THandshakeEffects.PeerCertificateChain(
  const AChain: TArray<TBytes>): THandshakeEffect;
begin
  Result := Default(THandshakeEffect);
  Result.Kind := THandshakeEffectKind.PeerCertificateChain;
  Result.Chain := AChain;
end;

class function THandshakeEffects.RequestedCertificateAuthorities(
  const AAuthorities: TArray<TBytes>): THandshakeEffect;
begin
  Result := Default(THandshakeEffect);
  Result.Kind := THandshakeEffectKind.RequestedCertificateAuthorities;
  Result.Chain := AAuthorities;
end;

class function THandshakeEffects.ConnectionParams(ACipherSuite, ANamedGroup: UInt16;
  AResumed: Boolean; const AServerName: string): THandshakeEffect;
begin
  Result := Default(THandshakeEffect);
  Result.Kind := THandshakeEffectKind.ConnectionParams;
  Result.CipherSuite := ACipherSuite;
  Result.NamedGroup := ANamedGroup;
  Result.Resumed := AResumed;
  Result.ServerName := AServerName;
end;

class function THandshakeEffects.HandshakeEstablished: THandshakeEffect;
begin
  Result := Default(THandshakeEffect);
  Result.Kind := THandshakeEffectKind.HandshakeEstablished;
end;

class function THandshakeEffects.Fail(
  AAlert: TTlsAlertDescription): THandshakeEffect;
begin
  Result := Default(THandshakeEffect);
  Result.Kind := THandshakeEffectKind.Fail;
  Result.Alert := AAlert;
end;

end.
