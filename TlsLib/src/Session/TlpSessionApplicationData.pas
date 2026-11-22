{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpSessionApplicationData;

{$I ..\Include\TlsLib.inc}

interface

uses
  SysUtils,
  TlpISessionApplicationData;

type
  /// <summary>
  /// The bytes a client host keeps with its cached sessions, shared by the engine (the host's
  /// side) and the client machine (the handshake's side). Only a client engine holds one.
  /// </summary>
  TSessionApplicationData = class sealed(TInterfacedObject, ITlsSessionApplicationData,
    ISessionApplicationDataChannel)
  strict private
  var
    FCurrent: TBytes;
    FOffered: TBytes;
  public
    procedure SetSessionApplicationData(const AData: TBytes);
    function OfferedSessionApplicationData: TBytes;
    function Current: TBytes;
    procedure PublishOffered(const AData: TBytes);
  end;

implementation

{ TSessionApplicationData }

procedure TSessionApplicationData.SetSessionApplicationData(const AData: TBytes);
begin
  FCurrent := System.Copy(AData);
end;

function TSessionApplicationData.OfferedSessionApplicationData: TBytes;
begin
  Result := System.Copy(FOffered);
end;

function TSessionApplicationData.Current: TBytes;
begin
  Result := System.Copy(FCurrent);
end;

procedure TSessionApplicationData.PublishOffered(const AData: TBytes);
begin
  FOffered := System.Copy(AData);
end;

end.
