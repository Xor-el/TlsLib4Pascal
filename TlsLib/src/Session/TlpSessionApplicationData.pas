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
  TlpTlsLibExceptions,
  TlpISessionApplicationData;

type
  /// <summary>
  /// The bytes a client host keeps with its cached sessions, shared by the engine (the host's
  /// side) and the client machine (the handshake's side). A server's instance refuses to be set.
  /// </summary>
  TSessionApplicationData = class sealed(TInterfacedObject, ITlsSessionApplicationData,
    ISessionApplicationDataChannel)
  strict private
  var
    FIsClient: Boolean;
    FCurrent: TBytes;
    FOffered: TBytes;
  public
    constructor Create(AIsClient: Boolean);
    procedure SetSessionApplicationData(const AData: TBytes);
    function OfferedSessionApplicationData: TBytes;
    function Current: TBytes;
    procedure PublishOffered(const AData: TBytes);
  end;

implementation

resourcestring
  SSessionApplicationDataClientOnly =
    'session application data is attached to the tickets a client receives; a server engine has none';

{ TSessionApplicationData }

constructor TSessionApplicationData.Create(AIsClient: Boolean);
begin
  inherited Create;
  FIsClient := AIsClient;
end;

procedure TSessionApplicationData.SetSessionApplicationData(const AData: TBytes);
begin
  if not FIsClient then
    raise EInvalidOperationTlsLibException.CreateRes(@SSessionApplicationDataClientOnly);
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
