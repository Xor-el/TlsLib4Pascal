{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpHelloRetryCookie;

{$I ..\Include\TlsLib.inc}

interface

uses
  SysUtils,
  TlpArrayUtilities,
  TlpBinaryPrimitives,
  TlpCryptoDomainTypes,
  TlpICryptoProvider,
  TlpISecretBuffer,
  TlpSecureMemory;

type
  /// <summary>
  /// The HelloRetryRequest cookie (RFC 8446 4.2.2): a self-contained token authenticated by an
  /// HMAC over a per-server-instance secret. The transcript rebuild that follows the second
  /// ClientHello is driven solely by the values a verified cookie carries - Hash(ClientHello1),
  /// the selected cipher suite and group, and the first ClientHello's legacy_session_id - so a
  /// second ClientHello that changes any of them is caught here rather than as a late transcript
  /// mismatch. (The server does keep some per-connection state across the two hellos; the cookie
  /// is what makes the retry itself self-describing.) The wire form is opaque to the client, which
  /// echoes it verbatim. Layout:
  /// cipher_suite(2) || selected_group(2) || sid_len(1) || legacy_session_id || Hash(CH1) || HMAC.
  /// </summary>
  THelloRetryCookie = class sealed(TObject)
  strict private
  const
    MacBytes = Int32(32);
    SuiteBytes = Int32(2);
    GroupBytes = Int32(2);
    SidLenBytes = Int32(1);
    MaxSessionIdLen = Int32(32);
  var
    FCrypto: ICryptoProvider;
    FSecret: ISecretBuffer;
    function Mac(const AContent: TBytes): TBytes;
  public
    /// <summary>The cookie authority keyed by a per-server-instance secret.</summary>
    constructor Create(const ACryptoProvider: ICryptoProvider; const ASecret: ISecretBuffer);
    /// <summary>Mints a cookie binding Hash(ClientHello1), the selected cipher suite and group,
    /// and the first ClientHello's legacy_session_id.</summary>
    function Mint(const ACh1Hash: TBytes; ASuite, ASelectedGroup: UInt16;
      const ASessionId: TBytes): TBytes;
    /// <summary>
    /// Verifies the cookie's HMAC (constant-time) and extracts the bound values.
    /// Returns False for a malformed or unauthenticated cookie; the out-params are
    /// only valid on True.
    /// </summary>
    function TryOpen(const ACookie: TBytes; out ACh1Hash: TBytes;
      out ASuite, ASelectedGroup: UInt16; out ASessionId: TBytes): Boolean;
  end;

implementation

{ THelloRetryCookie }

constructor THelloRetryCookie.Create(const ACryptoProvider: ICryptoProvider;
  const ASecret: ISecretBuffer);
begin
  inherited Create;
  FCrypto := ACryptoProvider;
  FSecret := ASecret;
end;

function THelloRetryCookie.Mac(const AContent: TBytes): TBytes;
var
  LHmac: IHmac;
begin
  LHmac := FCrypto.Primitives.CreateHmac(THashAlgorithm.SHA_256);
  LHmac.Init(FSecret);
  LHmac.Update(AContent, 0, System.Length(AContent));
  Result := LHmac.DoFinal;
end;

function THelloRetryCookie.Mint(const ACh1Hash: TBytes; ASuite, ASelectedGroup: UInt16;
  const ASessionId: TBytes): TBytes;
var
  LContent: TBytes;
begin
  Result := nil;
  // fixed fields first (suite, group, session-id length), then the variable session id, then
  // Hash(CH1) as the trailing block, so TryOpen parses the front and takes the hash as the rest
  LContent := nil;
  SetLength(LContent, SuiteBytes + GroupBytes + SidLenBytes);
  TBinaryPrimitives.WriteUInt16BigEndian(LContent, 0, ASuite);
  TBinaryPrimitives.WriteUInt16BigEndian(LContent, SuiteBytes, ASelectedGroup);
  LContent[SuiteBytes + GroupBytes] := Byte(System.Length(ASessionId));
  LContent := TArrayUtilities.Concat(LContent, ASessionId);
  LContent := TArrayUtilities.Concat(LContent, ACh1Hash);
  Result := TArrayUtilities.Concat(LContent, Mac(LContent));
end;

function THelloRetryCookie.TryOpen(const ACookie: TBytes; out ACh1Hash: TBytes;
  out ASuite, ASelectedGroup: UInt16; out ASessionId: TBytes): Boolean;
var
  LContent, LTag: TBytes;
  LContentLen, LHead, LSidLen, LHashLen, LPos: Int32;
begin
  Result := False;
  ACh1Hash := nil;
  ASuite := 0;
  ASelectedGroup := 0;
  ASessionId := nil;
  LHead := SuiteBytes + GroupBytes + SidLenBytes;
  // at least the fixed header and the MAC
  if System.Length(ACookie) < LHead + MacBytes then
    Exit;
  LContentLen := System.Length(ACookie) - MacBytes;
  LContent := System.Copy(ACookie, 0, LContentLen);
  LTag := System.Copy(ACookie, LContentLen, MacBytes);
  if not TSecureMemory.ConstantTimeAreEqual(LTag, Mac(LContent)) then
    Exit;
  LSidLen := LContent[SuiteBytes + GroupBytes];
  if LSidLen > MaxSessionIdLen then
    Exit;
  // suite + group + sid_len + session id + Hash(CH1); the hash is the remainder and non-empty
  LHashLen := LContentLen - LHead - LSidLen;
  if LHashLen <= 0 then
    Exit;
  ASuite := TBinaryPrimitives.ReadUInt16BigEndian(LContent, 0);
  ASelectedGroup := TBinaryPrimitives.ReadUInt16BigEndian(LContent, SuiteBytes);
  LPos := LHead;
  ASessionId := System.Copy(LContent, LPos, LSidLen);
  Inc(LPos, LSidLen);
  ACh1Hash := System.Copy(LContent, LPos, LHashLen);
  Result := True;
end;

end.
