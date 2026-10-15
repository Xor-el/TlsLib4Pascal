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
  TVerifyCallbackSpy = class sealed(TObject)
  strict private
    FAccept: Boolean;
    FCalls: Int32;
    FPresented: TArray<TBytes>;
    FValidated: TArray<TBytes>;
  public
    constructor Create(AAccept: Boolean);
    function Callback(const APresented, AValidated: TArray<TBytes>;
      const AHostName: string): Boolean;
    property Calls: Int32 read FCalls;
    /// <summary>The chain the peer presented, as the last call saw it.</summary>
    property Presented: TArray<TBytes> read FPresented;
    /// <summary>The validated path, as the last call saw it (nil when none was validated).</summary>
    property Validated: TArray<TBytes> read FValidated;
    function Invoked: Boolean;
  end;

  /// <summary>An async verdict resolver double: accepts a non-empty chain and records the role the
  /// pump attributed to the parked chain, Unknown until it runs.</summary>
  TVerdictResolverSpy = class sealed(TObject)
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

function TVerifyCallbackSpy.Callback(const APresented, AValidated: TArray<TBytes>;
  const AHostName: string): Boolean;
begin
  System.Inc(FCalls);
  FPresented := APresented;
  FValidated := AValidated;
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
