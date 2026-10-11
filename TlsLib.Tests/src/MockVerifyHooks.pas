{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit MockVerifyHooks;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  SysUtils,
  TlpTlsAlert,
  TlpTrustPolicy;

type
  /// <summary>An augment-only verify callback double: answers with a fixed verdict and counts how
  /// often it ran. A test creates its own, so no count survives into another test or run.</summary>
  TVerifyCallbackSpy = class(TObject)
  strict private
    FAccept: Boolean;
    FCalls: Int32;
  public
    constructor Create(AAccept: Boolean);
    function Callback(const AChain: TArray<TBytes>; const AHostName: string): Boolean;
    property Calls: Int32 read FCalls;
    function Invoked: Boolean;
  end;

  /// <summary>An async verdict resolver double: accepts a non-empty chain and records the role the
  /// pump attributed to the parked chain, Unknown until it runs.</summary>
  TVerdictResolverSpy = class(TObject)
  strict private
    FPeerRole: TPeerRole;
  public
    constructor Create;
    function Resolve(const ACtx: TCertificateVerdictContext;
      out ARejectAlert: TTlsAlertDescription): Boolean;
    property PeerRole: TPeerRole read FPeerRole;
  end;

implementation

{ TVerifyCallbackSpy }

constructor TVerifyCallbackSpy.Create(AAccept: Boolean);
begin
  inherited Create;
  FAccept := AAccept;
end;

function TVerifyCallbackSpy.Callback(const AChain: TArray<TBytes>;
  const AHostName: string): Boolean;
begin
  System.Inc(FCalls);
  Result := FAccept;
end;

function TVerifyCallbackSpy.Invoked: Boolean;
begin
  Result := FCalls > 0;
end;

{ TVerdictResolverSpy }

constructor TVerdictResolverSpy.Create;
begin
  inherited Create;
  FPeerRole := TPeerRole.Unknown;
end;

function TVerdictResolverSpy.Resolve(const ACtx: TCertificateVerdictContext;
  out ARejectAlert: TTlsAlertDescription): Boolean;
begin
  FPeerRole := ACtx.PeerRole;
  ARejectAlert := TTlsAlertDescription.BadCertificate;
  Result := System.Length(ACtx.Chain) > 0;
end;

end.
