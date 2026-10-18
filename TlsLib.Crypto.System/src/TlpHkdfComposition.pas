{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpHkdfComposition;

{$I ..\..\TlsLib\src\Include\TlsLib.inc}

interface

uses
  SysUtils,
  TlpCryptoDomainTypes,
  TlpICryptoProvider,
  TlpISecretBuffer,
  TlpSecretBuffer,
  TlpSecureMemory,
  TlpTlsLibExceptions;

resourcestring
  SHkdfExpandTooLong = 'HKDF-Expand output length %d exceeds 255 * HashLen (%d)';
  SHkdfExpandNegative = 'HKDF-Expand output length must not be negative';

type
  /// <summary>
  /// HKDF (RFC 5869) over the HMAC that a primitives facet hands back, for a native facet whose
  /// host serves HMAC but no usable HKDF. A subclass may serve Expand in-module through
  /// <see cref="TryExpandInModule" />; the length checks and the HMAC fallback stay here.
  /// </summary>
  THkdfComposition = class(TInterfacedObject, IHkdf)
  strict private
  var
    FPrimitives: ICryptoPrimitives;
    FAlgorithm: THashAlgorithm;
  strict protected
    property Algorithm: THashAlgorithm read FAlgorithm;
    /// <summary>Expand without the HMAC loop; False falls back to it. Called only for a length
    /// already checked to lie in [1, 255 * HashLen].</summary>
    function TryExpandInModule(const APrk: ISecretBuffer; const AInfo: TBytes;
      ALength: Int32; out AOkm: ISecretBuffer): Boolean; virtual;
  public
    constructor Create(const APrimitives: ICryptoPrimitives; AAlgorithm: THashAlgorithm);
    function Extract(const ASalt, AIkm: ISecretBuffer): ISecretBuffer;
    function Expand(const APrk: ISecretBuffer; const AInfo: TBytes;
      ALength: Int32): ISecretBuffer;
  end;

implementation

resourcestring
  SNilHkdfPrimitives = 'the primitives facet must not be nil';

{ THkdfComposition }

constructor THkdfComposition.Create(const APrimitives: ICryptoPrimitives;
  AAlgorithm: THashAlgorithm);
begin
  inherited Create;
  if APrimitives = nil then
    raise EArgumentTlsLibException.CreateRes(@SNilHkdfPrimitives);
  FPrimitives := APrimitives;
  FAlgorithm := AAlgorithm;
end;

function THkdfComposition.TryExpandInModule(const APrk: ISecretBuffer;
  const AInfo: TBytes; ALength: Int32; out AOkm: ISecretBuffer): Boolean;
begin
  AOkm := nil;
  Result := False;
end;

function THkdfComposition.Extract(const ASalt, AIkm: ISecretBuffer): ISecretBuffer;
var
  LIkm, LPrk: TBytes;
  LMac: IHmac;
begin
  LMac := FPrimitives.CreateHmac(FAlgorithm);
  // the salt is secret material used directly as the HMAC key; a nil or empty salt is HashLen
  // zeros (an allocated secret is zero-filled), so no bare byte copy of the salt is made here
  if (ASalt <> nil) and (ASalt.Len > 0) then
    LMac.Init(ASalt)
  else
    LMac.Init(TSecretBuffer.Allocate(LMac.MacSize));
  LIkm := AIkm.ToBytes;
  try
    LMac.Update(LIkm, 0, System.Length(LIkm));
    LPrk := LMac.DoFinal;
    try
      Result := TSecretBuffer.From(LPrk);
    finally
      TSecureMemory.WipeBytes(LPrk);
    end;
  finally
    TSecureMemory.WipeBytes(LIkm);
  end;
end;

function THkdfComposition.Expand(const APrk: ISecretBuffer; const AInfo: TBytes;
  ALength: Int32): ISecretBuffer;
var
  LMac: IHmac;
  LOkm, LT, LCtr: TBytes;
  LPos, LTake, LHashLen: Int32;
  LCounter: Byte;
begin
  LMac := FPrimitives.CreateHmac(FAlgorithm);
  LHashLen := LMac.MacSize;
  // RFC 5869 2.3: L must not exceed 255 * HashLen, else the block counter would wrap
  if ALength < 0 then
    raise EArgumentTlsLibException.CreateRes(@SHkdfExpandNegative);
  if ALength > 255 * LHashLen then
    raise EArgumentTlsLibException.CreateResFmt(@SHkdfExpandTooLong,
      [ALength, 255 * LHashLen]);
  if ALength = 0 then
    Exit(TSecretBuffer.From(nil));
  if TryExpandInModule(APrk, AInfo, ALength, Result) then
    Exit;
  LOkm := nil;
  SetLength(LOkm, ALength);
  LMac.Init(APrk);
  LT := nil;
  LCtr := nil;
  SetLength(LCtr, 1);
  LPos := 0;
  LCounter := 1;
  try
    while LPos < ALength do
    begin
      // T(i) = HMAC(PRK, T(i-1) || info || i)
      if System.Length(LT) > 0 then
        LMac.Update(LT, 0, System.Length(LT));
      if System.Length(AInfo) > 0 then
        LMac.Update(AInfo, 0, System.Length(AInfo));
      LCtr[0] := LCounter;
      LMac.Update(LCtr, 0, 1);
      TSecureMemory.WipeBytes(LT); // each T(i) is an OKM prefix; wipe before reassigning
      LT := LMac.DoFinal; // DoFinal re-keys a fresh HMAC for the next block
      LTake := System.Length(LT);
      if LPos + LTake > ALength then
        LTake := ALength - LPos;
      System.Move(LT[0], LOkm[LPos], LTake);
      Inc(LPos, LTake);
      Inc(LCounter);
    end;
    Result := TSecretBuffer.From(LOkm);
  finally
    TSecureMemory.WipeBytes(LOkm);
    TSecureMemory.WipeBytes(LT);
  end;
end;

end.
