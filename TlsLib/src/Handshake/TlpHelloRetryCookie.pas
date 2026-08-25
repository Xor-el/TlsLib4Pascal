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
  TlpCryptoAlgorithms,
  TlpICryptoProvider,
  TlpISecretBuffer,
  TlpSecureMemory;

type
  /// <summary>
  /// The stateless HelloRetryRequest cookie (RFC 8446 4.2.2): a self-contained token
  /// that carries Hash(ClientHello1) and the selected group, authenticated by an
  /// HMAC over a per-server-instance secret. The server retains no per-connection
  /// state between the two ClientHellos - it rebuilds the transcript from the values
  /// the verified cookie carries. The wire form is opaque to the client, which echoes
  /// it verbatim. Layout: Hash(CH1) || selected_group(2) || HMAC-SHA256.
  /// </summary>
  THelloRetryCookie = class sealed(TObject)
  strict private
  const
    MacBytes = Int32(32);
    GroupBytes = Int32(2);
  var
    FProvider: ICryptoProvider;
    FSecret: ISecretBuffer;
    function Mac(const AContent: TBytes): TBytes;
  public
    /// <summary>The cookie authority keyed by a per-server-instance secret.</summary>
    constructor Create(const AProvider: ICryptoProvider; const ASecret: ISecretBuffer);
    /// <summary>Mints a cookie binding Hash(ClientHello1) and the selected group.</summary>
    function Mint(const ACh1Hash: TBytes; ASelectedGroup: UInt16): TBytes;
    /// <summary>
    /// Verifies the cookie's HMAC (constant-time) and extracts the bound values.
    /// Returns False for a malformed or unauthenticated cookie; the out-params are
    /// only valid on True.
    /// </summary>
    function TryOpen(const ACookie: TBytes; out ACh1Hash: TBytes;
      out ASelectedGroup: UInt16): Boolean;
  end;

implementation

{ THelloRetryCookie }

constructor THelloRetryCookie.Create(const AProvider: ICryptoProvider;
  const ASecret: ISecretBuffer);
begin
  inherited Create;
  FProvider := AProvider;
  FSecret := ASecret;
end;

function THelloRetryCookie.Mac(const AContent: TBytes): TBytes;
var
  LHmac: IHmac;
begin
  LHmac := FProvider.Primitives.CreateHmac(THashAlgorithm.SHA_256);
  LHmac.Init(FSecret);
  LHmac.Update(AContent, 0, System.Length(AContent));
  Result := LHmac.DoFinal;
end;

function THelloRetryCookie.Mint(const ACh1Hash: TBytes;
  ASelectedGroup: UInt16): TBytes;
var
  LContent, LGroup: TBytes;
begin
  Result := nil;
  LGroup := TBytes.Create(Byte(ASelectedGroup shr 8), Byte(ASelectedGroup and $FF));
  LContent := TArrayUtilities.Concat(ACh1Hash, LGroup);
  Result := TArrayUtilities.Concat(LContent, Mac(LContent));
end;

function THelloRetryCookie.TryOpen(const ACookie: TBytes; out ACh1Hash: TBytes;
  out ASelectedGroup: UInt16): Boolean;
var
  LContent, LTag: TBytes;
  LContentLen: Int32;
begin
  Result := False;
  ACh1Hash := nil;
  ASelectedGroup := 0;
  // a cookie needs at least the group, the MAC, and a non-empty hash
  if System.Length(ACookie) <= GroupBytes + MacBytes then
    Exit;
  LContentLen := System.Length(ACookie) - MacBytes;
  LContent := System.Copy(ACookie, 0, LContentLen);
  LTag := System.Copy(ACookie, LContentLen, MacBytes);
  if not TSecureMemory.ConstantTimeAreEqual(LTag, Mac(LContent)) then
    Exit;
  ASelectedGroup := (UInt16(LContent[LContentLen - GroupBytes]) shl 8) or
    UInt16(LContent[LContentLen - 1]);
  ACh1Hash := System.Copy(LContent, 0, LContentLen - GroupBytes);
  Result := True;
end;

end.
