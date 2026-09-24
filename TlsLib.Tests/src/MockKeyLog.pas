{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit MockKeyLog;

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

interface

uses
  SysUtils,
  TlpIKeyLog;

type
  TKeyLogEntry = record
    Lbl: string;
    ClientRandom: TBytes;
    Secret: TBytes;
  end;

  /// <summary>Captures every key-log call in order (copying the transient secret) for tests.</summary>
  TMockKeyLog = class sealed(TInterfacedObject, IKeyLog)
  strict private
  var
    FEntries: TArray<TKeyLogEntry>;
    procedure Log(const ALabel: string; const AClientRandom, ASecret: TBytes);
    function GetCount: Int32;
    function GetEntry(AIndex: Int32): TKeyLogEntry;
  public
    property Count: Int32 read GetCount;
    property Entries[AIndex: Int32]: TKeyLogEntry read GetEntry; default;
  end;

implementation

{ TMockKeyLog }

procedure TMockKeyLog.Log(const ALabel: string; const AClientRandom, ASecret: TBytes);
var
  LEntry: TKeyLogEntry;
begin
  LEntry.Lbl := ALabel;
  LEntry.ClientRandom := System.Copy(AClientRandom);
  LEntry.Secret := System.Copy(ASecret);
  FEntries := FEntries + [LEntry];
end;

function TMockKeyLog.GetCount: Int32;
begin
  Result := System.Length(FEntries);
end;

function TMockKeyLog.GetEntry(AIndex: Int32): TKeyLogEntry;
begin
  Result := FEntries[AIndex];
end;

end.
