{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpResumptionPartition;

{$I ..\Include\TlsLib.inc}

interface

uses
  SysUtils,
  TlpTlsLibExceptions,
  TlpSession,
  TlpITlsResumptionPartition;

type
  /// <summary>
  /// The partition a client engine stores its tickets under, shared by the engine (the host's side)
  /// and the client machine (the handshake's side). Only a client engine holds one.
  /// </summary>
  TResumptionPartition = class sealed(TInterfacedObject, ITlsResumptionPartition,
    IResumptionPartitionChannel)
  strict private
  var
    FCurrent: TBytes;
  public
    /// <summary>A partition starting as AInitial; raises EArgumentTlsLibException when it is
    /// longer than the limit.</summary>
    constructor Create(const AInitial: TBytes);
    procedure SetResumptionPartition(const APartition: TBytes);
    function Current: TBytes;
  end;

implementation

resourcestring
  SResumptionPartitionTooLong = 'the resumption partition exceeds the limit';

{ TResumptionPartition }

constructor TResumptionPartition.Create(const AInitial: TBytes);
begin
  inherited Create;
  SetResumptionPartition(AInitial);
end;

procedure TResumptionPartition.SetResumptionPartition(const APartition: TBytes);
begin
  if System.Length(APartition) > TSessionTicketLimits.MaxResumptionPartitionLength then
    raise EArgumentTlsLibException.CreateRes(@SResumptionPartitionTooLong);
  FCurrent := System.Copy(APartition);
end;

function TResumptionPartition.Current: TBytes;
begin
  Result := System.Copy(FCurrent);
end;

end.
