{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpRecordProtectionFactory;

{$I ..\Include\TlsLib.inc}

interface

uses
  SysUtils,
  TlpTlsVersion,
  TlpICryptoProvider,
  TlpIKeySchedule,
  TlpIRecordProtection,
  TlpRecordProtection,
  TlpTlsLibExceptions;

type
  /// <summary>
  /// The install-path seam between a key schedule and the record layer: it turns an
  /// epoch's derived (key, iv) into the record protection for the negotiated
  /// version, so a driver installs schedule output without hand-picking the 1.3 or
  /// 1.2 class. The AEAD comes from the provider for the negotiated cipher suite;
  /// for TLS 1.2 the traffic keys' iv is the 4-byte salt (AES-GCM) or the 12-byte write IV
  /// (ChaCha20-Poly1305).
  /// </summary>
  TRecordProtectionFactory = class sealed(TObject)
  public
    class function Build(const AVersion: TTlsVersion; const AKeys: ITrafficKeys;
      const AAead: IAead): IRecordProtection; static;
  end;

implementation

resourcestring
  SUnsupportedProtectionVersion =
    'no record protection is defined for this protocol version';

{ TRecordProtectionFactory }

class function TRecordProtectionFactory.Build(const AVersion: TTlsVersion;
  const AKeys: ITrafficKeys; const AAead: IAead): IRecordProtection;
begin
  if AVersion.Equals(TTlsVersion.Tls13) then
    Result := TTls13RecordProtection.Create(AKeys.Key, AKeys.Iv, AAead)
  else if AVersion.Equals(TTlsVersion.Tls12) then
    Result := TTls12RecordProtection.Create(AKeys.Key, AKeys.Iv, AAead)
  else
    raise EArgumentTlsLibException.CreateRes(@SUnsupportedProtectionVersion);
end;

end.
