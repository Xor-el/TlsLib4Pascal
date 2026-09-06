{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpEchConfigFromSvcb;

{$IFDEF FPC}
{$MODE DELPHI}
{$H+}
{$ENDIF}

interface

uses
  SysUtils,
  TlpWireReader,
  TlpTlsLibExceptions;

type
  /// <summary>
  /// Extracts the ECHConfigList a zone publishes in an HTTPS/SVCB record (RFC 9460)
  /// from the SvcParams, keyed by the "ech" SvcParamKey (5, RFC 9849). This is a pure
  /// decoder over bytes the application already resolved: no DNS lookup happens here,
  /// so it stays outside the TLS core and imposes no resolver dependency. Hand the
  /// resulting ECHConfigList to the client builder's Encrypted Client Hello policy.
  /// It does not enforce the "mandatory" SvcParam (RFC 9460 sec. 8): whether every
  /// mandatory key is understood is the resolving application's decision, not this decoder's.
  /// </summary>
  TEchConfigFromSvcb = class sealed(TObject)
  strict private
    const
      // the "ech" SvcParamKey (RFC 9849 sec. 4); its SvcParamValue is the ECHConfigList
      SvcParamKeyEch = UInt16(5);
    class function TryReadEch(const ARdata: TBytes;
      out AEchConfigList: TBytes): Boolean; static;
  public
    /// <summary>
    /// Extracts the ECHConfigList from the RDATA of an HTTPS/SVCB resource record
    /// (RFC 9460 sec. 2.2: SvcPriority, TargetName, then SvcParams). Returns True with
    /// the opaque ECHConfigList when the record is in ServiceMode and carries an "ech"
    /// SvcParam; False for AliasMode, a record without one, or malformed RDATA.
    /// </summary>
    class function TryFromServiceBinding(const ARdata: TBytes;
      out AEchConfigList: TBytes): Boolean; static;
    /// <summary>
    /// As <see cref="TryFromServiceBinding" />, but raises EArgumentTlsLibException when
    /// no usable "ech" SvcParam is present.
    /// </summary>
    class function FromServiceBinding(const ARdata: TBytes): TBytes; static;
  end;

resourcestring
  SNoEchSvcParam =
    'the HTTPS/SVCB record carries no "ech" SvcParam';

implementation

{ TEchConfigFromSvcb }

class function TEchConfigFromSvcb.TryReadEch(const ARdata: TBytes;
  out AEchConfigList: TBytes): Boolean;
var
  LReader: TWireReader;
  LLabelLen: Int32;
  LKey, LValueLen, LPrevKey: UInt16;
  LHasPrev, LFound: Boolean;
begin
  Result := False;
  AEchConfigList := nil;
  LReader := TWireReader.Create(ARdata);
  // SvcPriority (2 bytes); 0 is AliasMode, which carries no SvcParams
  if LReader.ReadUInt16 = 0 then
    Exit;
  // TargetName: a sequence of length-prefixed labels ended by a zero-length label. No
  // compression pointers appear in SVCB/HTTPS RDATA (RFC 9460 sec. 2.2)
  repeat
    LLabelLen := LReader.ReadUInt8;
    if LLabelLen > 0 then
      LReader.Skip(LLabelLen);
  until LLabelLen = 0;
  // SvcParams MUST be strictly ascending by SvcParamKey (so no duplicates) and consume the
  // RDATA exactly (RFC 9460 sec. 2.2); a mis-ordered key or a trailing byte is malformed input
  LHasPrev := False;
  LPrevKey := 0;
  LFound := False;
  while not LReader.EndReached do
  begin
    LKey := LReader.ReadUInt16;
    if LHasPrev and (LKey <= LPrevKey) then
      Exit;
    LPrevKey := LKey;
    LHasPrev := True;
    LValueLen := LReader.ReadUInt16;
    if LKey = SvcParamKeyEch then
    begin
      // an empty ech value carries no ECHConfigList (which is itself length-prefixed): treat it
      // as absent rather than a usable-but-empty config, so the caller does not silently fall
      // back to a plaintext ClientHello that leaks the true SNI
      if LValueLen > 0 then
      begin
        AEchConfigList := LReader.ReadBytes(LValueLen);
        LFound := True;
      end;
    end
    else
      LReader.Skip(LValueLen);
  end;
  Result := LFound;
end;

class function TEchConfigFromSvcb.TryFromServiceBinding(const ARdata: TBytes;
  out AEchConfigList: TBytes): Boolean;
begin
  AEchConfigList := nil;
  // the RDATA is untrusted resolver output, so a truncated field (an over-read past the
  // buffer) is a plain "no usable ech", not a fatal error
  try
    Result := TryReadEch(ARdata, AEchConfigList);
  except
    on E: Exception do
    begin
      AEchConfigList := nil;
      Result := False;
    end;
  end;
end;

class function TEchConfigFromSvcb.FromServiceBinding(
  const ARdata: TBytes): TBytes;
begin
  if not TryFromServiceBinding(ARdata, Result) then
    raise EArgumentTlsLibException.CreateRes(@SNoEchSvcParam);
end;

end.
