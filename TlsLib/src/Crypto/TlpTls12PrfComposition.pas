{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpTls12PrfComposition;

{$I ..\Include\TlsLib.inc}

interface

uses
  SysUtils,
  TlpArrayUtilities,
  TlpCryptoDomainTypes,
  TlpICryptoProvider,
  TlpISecretBuffer,
  TlpSecretBuffer,
  TlpSecureMemory;

type
  /// <summary>
  /// The built-in <see cref="ITls12Prf" />: P_hash with the bound hash over the provider's
  /// own HMAC (RFC 5246 5) - PRF(secret, label, seed) = P_hash(secret, label + seed). The
  /// single implementation serves both the portable and the OS-native provider: it uses
  /// whatever HMAC the primitives seam hands back, so on the native overlay it runs on the
  /// OS backend where available.
  /// </summary>
  TTls12PrfComposition = class sealed(TInterfacedObject, ITls12Prf)
  strict private
  var
    FPrimitives: ICryptoPrimitives;
    FHash: THashAlgorithm;
  public
    constructor Create(const APrimitives: ICryptoPrimitives; AHash: THashAlgorithm);
    function Compute(const ASecret: ISecretBuffer; const ALabel: string;
      const ASeed: TBytes; ALength: Int32): ISecretBuffer;
  end;

implementation

{ TTls12PrfComposition }

constructor TTls12PrfComposition.Create(const APrimitives: ICryptoPrimitives;
  AHash: THashAlgorithm);
begin
  inherited Create;
  FPrimitives := APrimitives;
  FHash := AHash;
end;

function TTls12PrfComposition.Compute(const ASecret: ISecretBuffer;
  const ALabel: string; const ASeed: TBytes; ALength: Int32): ISecretBuffer;
var
  LSeed, LA, LBlock, LInput, LNext: TBytes;
  LPos, LCopy: Int32;
  LOut: PByte;

  function HmacOf(const AData: TBytes): TBytes;
  var
    LHmac: IHmac;
  begin
    LHmac := FPrimitives.CreateHmac(FHash);
    LHmac.Init(ASecret);
    LHmac.Update(AData, 0, System.Length(AData));
    Result := LHmac.DoFinal;
  end;

begin
  // the PRF output is key material (master secret, key block), so it lands in a wiped buffer
  // rather than a bare byte array the caller must scrub
  Result := TSecretBuffer.Allocate(ALength);
  LOut := Result.DataPtr;
  LSeed := TArrayUtilities.Concat(TEncoding.ASCII.GetBytes(ALabel), ASeed);
  try
    LA := HmacOf(LSeed); // A(1) = HMAC(secret, seed); computed so LA never aliases the seed
    LPos := 0;
    while LPos < ALength do
    begin
      LInput := TArrayUtilities.Concat(LA, LSeed);
      try
        LBlock := HmacOf(LInput);
      finally
        TSecureMemory.WipeBytes(LInput);
      end;
      try
        LCopy := System.Length(LBlock);
        if LCopy > ALength - LPos then
          LCopy := ALength - LPos;
        Move(LBlock[0], (LOut + LPos)^, LCopy);
        Inc(LPos, LCopy);
      finally
        TSecureMemory.WipeBytes(LBlock);
      end;
      if LPos < ALength then
      begin
        LNext := HmacOf(LA); // A(i+1) = HMAC(secret, A(i))
        TSecureMemory.WipeBytes(LA);
        LA := LNext;
      end;
    end;
  finally
    TSecureMemory.WipeBytes(LA);
    TSecureMemory.WipeBytes(LSeed);
  end;
end;

end.
