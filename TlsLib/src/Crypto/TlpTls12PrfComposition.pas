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
      const ASeed: TBytes; ALength: Int32): TBytes;
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
  const ALabel: string; const ASeed: TBytes; ALength: Int32): TBytes;
var
  LSeed, LA, LBlock: TBytes;
  LPos, LCopy: Int32;

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
  Result := nil;
  SetLength(Result, ALength);
  LSeed := TArrayUtilities.Concat(TEncoding.ASCII.GetBytes(ALabel), ASeed);
  LA := LSeed; // A(0) = seed
  try
    LPos := 0;
    while LPos < ALength do
    begin
      LA := HmacOf(LA); // A(i) = HMAC(secret, A(i-1))
      LBlock := HmacOf(TArrayUtilities.Concat(LA, LSeed));
      try
        LCopy := System.Length(LBlock);
        if LCopy > ALength - LPos then
          LCopy := ALength - LPos;
        Move(LBlock[0], Result[LPos], LCopy);
        Inc(LPos, LCopy);
      finally
        TSecureMemory.WipeBytes(LBlock);
      end;
    end;
  finally
    TSecureMemory.WipeBytes(LA);
    TSecureMemory.WipeBytes(LSeed);
  end;
end;

end.
