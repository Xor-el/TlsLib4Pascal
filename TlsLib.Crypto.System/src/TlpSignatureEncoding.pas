{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpSignatureEncoding;

{$I ..\..\TlsLib\src\Include\TlsLib.inc}

interface

uses
  SysUtils,
  TlpCryptoDomainTypes,
  TlpDer;

type
  /// <summary>The signature wire encodings a native signer or verifier converts.</summary>
  TSignatureEncoding = class sealed(TObject)
  public
    /// <summary>The DER Ecdsa-Sig-Value SEQUENCE { r INTEGER, s INTEGER } (RFC 3279 2.2.3) TLS
    /// carries, from a fixed-width r||s.</summary>
    class function DerEncodeEcdsa(const ARaw: TBytes): TBytes; static;
    /// <summary>The fixed-width r||s, AFieldSize bytes each, of a strict DER Ecdsa-Sig-Value.
    /// False for any encoding that is not minimal DER, spans more or less than the input, or has an
    /// r or s that is zero, negative or wider than AFieldSize.</summary>
    class function TryDerDecodeEcdsa(const ADer: TBytes; AFieldSize: Int32;
      out ARaw: TBytes): Boolean; static;
    /// <summary>The DER DigestInfo T of RFC 8017 9.2 for the scheme's hash and ADigest: the Note 1
    /// prefix, NULL parameters included, then the digest. It is the only encoding a PKCS#1 v1.5
    /// signature may carry. Nil for a scheme that is not rsa_pkcs1_* or a digest of the wrong
    /// length.</summary>
    class function Pkcs1DigestInfo(AScheme: TSignatureScheme;
      const ADigest: TBytes): TBytes; static;
  end;

implementation

{ TSignatureEncoding }

class function TSignatureEncoding.DerEncodeEcdsa(const ARaw: TBytes): TBytes;
var
  LHalf: Int32;
  LR, LS, LBody: TBytes;
begin
  LHalf := System.Length(ARaw) div 2;
  LR := TDer.IntegerTlv(Copy(ARaw, 0, LHalf));
  LS := TDer.IntegerTlv(Copy(ARaw, LHalf, LHalf));
  SetLength(LBody, System.Length(LR) + System.Length(LS));
  Move(LR[0], LBody[0], System.Length(LR));
  Move(LS[0], LBody[System.Length(LR)], System.Length(LS));
  Result := TDer.Tlv($30, LBody);
end;

class function TSignatureEncoding.TryDerDecodeEcdsa(const ADer: TBytes;
  AFieldSize: Int32; out ARaw: TBytes): Boolean;
var
  LPos, LEnd, LN: Int32;

  // reads one DER INTEGER at AOffset, returns its content left-padded to AFieldSize in
  // AValue, and advances LPos past the whole TLV
  function ReadInt(AOffset: Int32; out AValue: TBytes): Boolean;
  var
    LLenOrig, LLen, LStart, LI: Int32;
    LAllZero: Boolean;
  begin
    Result := False;
    if (AOffset + 2 > LEnd) or (ADer[AOffset] <> $02) then
      Exit;
    LLenOrig := ADer[AOffset + 1];
    if (LLenOrig and $80) <> 0 then // long-form length is not expected for r/s
      Exit;
    LStart := AOffset + 2;
    if LStart + LLenOrig > LEnd then
      Exit;
    // strict DER INTEGER: a non-empty, non-negative, minimally-encoded value (r, s are positive)
    if LLenOrig = 0 then
      Exit;
    if (ADer[LStart] and $80) <> 0 then // negative (high bit set) is not a valid r/s
      Exit;
    if (LLenOrig > 1) and (ADer[LStart] = 0) and ((ADer[LStart + 1] and $80) = 0) then
      Exit; // a leading 0x00 is legal only to clear the sign bit of the next byte
    LLen := LLenOrig;
    // strip a single leading zero sign byte
    if (LLen > 1) and (ADer[LStart] = 0) then
    begin
      Inc(LStart);
      Dec(LLen);
    end;
    if (LLen = 0) or (LLen > AFieldSize) then
      Exit;
    // r and s must be non-zero
    LAllZero := True;
    for LI := 0 to LLen - 1 do
      if ADer[LStart + LI] <> 0 then
      begin
        LAllZero := False;
        Break;
      end;
    if LAllZero then
      Exit;
    AValue := nil;
    SetLength(AValue, AFieldSize);
    System.FillChar(AValue[0], AFieldSize, 0);
    Move(ADer[LStart], AValue[AFieldSize - LLen], LLen);
    LPos := AOffset + 2 + LLenOrig; // advance past the full TLV
    Result := True;
  end;

var
  LR, LS: TBytes;
  LSeqLen: Int32;
begin
  ARaw := nil;
  LN := System.Length(ADer);
  if (LN < 2) or (ADer[0] <> $30) then
    Exit(False);
  LSeqLen := ADer[1];
  if (LSeqLen and $80) <> 0 then // one long-form length byte (0x81) for larger curves
  begin
    if (LSeqLen <> $81) or (LN < 3) then
      Exit(False);
    LSeqLen := ADer[2];
    // long form must be used only when it is required (content length >= 0x80): a value that
    // fits short form encoded in long form is not DER-minimal
    if LSeqLen < $80 then
      Exit(False);
    LPos := 3;
  end
  else
    LPos := 2;
  LEnd := LPos + LSeqLen;
  // the SEQUENCE must span exactly the input: trailing bytes after it are rejected
  if LEnd <> LN then
    Exit(False);
  if not ReadInt(LPos, LR) then
    Exit(False);
  if not ReadInt(LPos, LS) then
    Exit(False);
  if LPos <> LEnd then
    Exit(False);
  ARaw := nil;
  SetLength(ARaw, 2 * AFieldSize);
  Move(LR[0], ARaw[0], AFieldSize);
  Move(LS[0], ARaw[AFieldSize], AFieldSize);
  Result := True;
end;

class function TSignatureEncoding.Pkcs1DigestInfo(AScheme: TSignatureScheme;
  const ADigest: TBytes): TBytes;
const
  // RFC 8017 9.2 Note 1: 30 len 30 0d 06 09 60 86 48 01 65 03 04 02 <hash> 05 00 04 <hashlen>
  Sha256Prefix: array[0..18] of Byte = ($30, $31, $30, $0D, $06, $09, $60, $86, $48, $01, $65,
    $03, $04, $02, $01, $05, $00, $04, $20);
  Sha384Prefix: array[0..18] of Byte = ($30, $41, $30, $0D, $06, $09, $60, $86, $48, $01, $65,
    $03, $04, $02, $02, $05, $00, $04, $30);
  Sha512Prefix: array[0..18] of Byte = ($30, $51, $30, $0D, $06, $09, $60, $86, $48, $01, $65,
    $03, $04, $02, $03, $05, $00, $04, $40);
var
  LPrefix: PByte;
  LDigestLength: Int32;
begin
  case AScheme of
    TSignatureScheme.RSA_PKCS1_SHA256:
      begin
        LPrefix := @Sha256Prefix[0];
        LDigestLength := 32;
      end;
    TSignatureScheme.RSA_PKCS1_SHA384:
      begin
        LPrefix := @Sha384Prefix[0];
        LDigestLength := 48;
      end;
    TSignatureScheme.RSA_PKCS1_SHA512:
      begin
        LPrefix := @Sha512Prefix[0];
        LDigestLength := 64;
      end;
  else
    // no other scheme is an RSASSA-PKCS1-v1_5 one; the caller reads nil as a failed verification
    Exit(nil);
  end;
  if System.Length(ADigest) <> LDigestLength then
    Exit(nil);
  Result := nil;
  SetLength(Result, System.Length(Sha256Prefix) + System.Length(ADigest));
  Move(LPrefix^, Result[0], System.Length(Sha256Prefix));
  if System.Length(ADigest) > 0 then
    Move(ADigest[0], Result[System.Length(Sha256Prefix)], System.Length(ADigest));
end;

end.
