{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpComplianceTicketKeys;

{$I ..\..\TlsLib\src\Include\TlsLib.inc}

interface

uses
  SysUtils,
  TlpEnumUtilities,
  TlpCryptoDomainTypes,
  TlpTlsLibExceptions,
  TlpISecretBuffer,
  TlpIClock,
  TlpISession,
  TlpSessionTicketKeys,
  TlpSessionTicketStrategy,
  TlpTlsConfigBuilder,
  TlpICompliancePolicy,
  TlpIComplianceTicketKeys;

type
  /// <summary>
  /// Rotating session-ticket keys issued by a compliance policy, which mints the inner keys from
  /// its own crypto provider. The policy admits a server holding keys of this class and no other
  /// rotating keys. It keeps no state beyond the inner keys, so it is as thread-safe as they are.
  /// </summary>
  TComplianceTicketKeys = class sealed(TInterfacedObject, ISessionTicketKeyManager,
    IRotatingTicketKeyManager, IComplianceTicketKeys)
  strict private
  var
    FPolicy: ICompliancePolicy;
    FInner: IRotatingTicketKeyManager;
    FLifetimeSeconds: UInt32;
  public
    /// <summary>Raises EArgumentTlsLibException for a nil policy or clock, a zero lifetime, or
    /// rules without AES-256-GCM, which seals the tickets.</summary>
    constructor Create(const APolicy: ICompliancePolicy; const AClock: ITlsClock;
      ALifetimeSeconds: UInt32);
    function CurrentKey(out AKeyName: TBytes; out AKey: ISecretBuffer): Boolean;
    function KeyByName(const AKeyName: TBytes; out AKey: ISecretBuffer): Boolean;
    function KeyNameLength: Int32;
    procedure Rotate;
    function Policy: ICompliancePolicy;
    function LifetimeSeconds: UInt32;
    function FleetScope: TBytes;
  end;

  /// <summary>
  /// A fleet key manager whose keys the host enters, marked as checked by a compliance policy. The
  /// policy admits it and still discloses that the host chose the keys and the fleet scope. Install
  /// only keys that were generated in the approved mode: keys from the non-approved mode must not
  /// be used in the approved mode. It keeps no state beyond the inner keys, so it is as thread-safe
  /// as they are.
  /// </summary>
  TComplianceFleetTicketKeys = class sealed(TInterfacedObject, ISessionTicketKeyManager,
    IFleetTicketKeyManager, IComplianceTicketKeys)
  strict private
  var
    FPolicy: ICompliancePolicy;
    FInner: IFleetTicketKeyManager;
    FFleetScope: TBytes;
  public
    /// <summary>Raises EArgumentTlsLibException for a nil argument, or a scope that is empty or
    /// longer than the longest resumption scope the config builder accepts.</summary>
    constructor Create(const APolicy: ICompliancePolicy; const AInner: IFleetTicketKeyManager;
      const AFleetScope: TBytes);
    function CurrentKey(out AKeyName: TBytes; out AKey: ISecretBuffer): Boolean;
    function KeyByName(const AKeyName: TBytes; out AKey: ISecretBuffer): Boolean;
    function KeyNameLength: Int32;
    procedure InstallKey(const AName: TBytes; const AKey: ISecretBuffer);
    function Policy: ICompliancePolicy;
    function LifetimeSeconds: UInt32;
    function FleetScope: TBytes;
  end;

implementation

resourcestring
  SNilPolicy = 'the compliance policy must not be nil';
  SNilClock = 'the clock must not be nil';
  SNilInner = 'the inner ticket keys must not be nil';
  SLifetimeZero = 'the ticket-key lifetime must not be zero';
  SKeysNeedAes256 = 'the ticket keys seal with %s, which the rules do not allow';
  SFleetScopeInvalid = 'the fleet scope must be 1 to %d bytes';

{ TComplianceTicketKeys }

constructor TComplianceTicketKeys.Create(const APolicy: ICompliancePolicy;
  const AClock: ITlsClock; ALifetimeSeconds: UInt32);
begin
  inherited Create;
  if APolicy = nil then
    raise EArgumentTlsLibException.CreateRes(@SNilPolicy);
  if AClock = nil then
    raise EArgumentTlsLibException.CreateRes(@SNilClock);
  // the inner manager would fall back to its own interval for 0 and leave the lifetime unstated
  if ALifetimeSeconds = 0 then
    raise EArgumentTlsLibException.CreateRes(@SLifetimeZero);
  if not (TSessionTicketStrategies.TicketAead in APolicy.Rules.Aeads) then
    raise EArgumentTlsLibException.CreateResFmt(@SKeysNeedAes256,
      [TEnumUtilities.GetName<TAeadAlgorithm>(TSessionTicketStrategies.TicketAead)]);
  FPolicy := APolicy;
  FLifetimeSeconds := ALifetimeSeconds;
  FInner := TStekTicketKeyManager.CreateDefault(APolicy.Crypto, AClock, ALifetimeSeconds)
    as IRotatingTicketKeyManager;
end;

function TComplianceTicketKeys.CurrentKey(out AKeyName: TBytes;
  out AKey: ISecretBuffer): Boolean;
begin
  Result := FInner.CurrentKey(AKeyName, AKey);
end;

function TComplianceTicketKeys.KeyByName(const AKeyName: TBytes;
  out AKey: ISecretBuffer): Boolean;
begin
  Result := FInner.KeyByName(AKeyName, AKey);
end;

function TComplianceTicketKeys.KeyNameLength: Int32;
begin
  Result := FInner.KeyNameLength;
end;

procedure TComplianceTicketKeys.Rotate;
begin
  FInner.Rotate;
end;

function TComplianceTicketKeys.Policy: ICompliancePolicy;
begin
  Result := FPolicy;
end;

function TComplianceTicketKeys.LifetimeSeconds: UInt32;
begin
  Result := FLifetimeSeconds;
end;

function TComplianceTicketKeys.FleetScope: TBytes;
begin
  Result := nil;
end;

{ TComplianceFleetTicketKeys }

constructor TComplianceFleetTicketKeys.Create(const APolicy: ICompliancePolicy;
  const AInner: IFleetTicketKeyManager; const AFleetScope: TBytes);
begin
  inherited Create;
  if APolicy = nil then
    raise EArgumentTlsLibException.CreateRes(@SNilPolicy);
  if AInner = nil then
    raise EArgumentTlsLibException.CreateRes(@SNilInner);
  if (System.Length(AFleetScope) = 0) or
    (System.Length(AFleetScope) > TTlsConfigBuilder.MaxResumptionScopeLength) then
    raise EArgumentTlsLibException.CreateResFmt(@SFleetScopeInvalid,
      [TTlsConfigBuilder.MaxResumptionScopeLength]);
  FPolicy := APolicy;
  FInner := AInner;
  FFleetScope := System.Copy(AFleetScope);
end;

function TComplianceFleetTicketKeys.CurrentKey(out AKeyName: TBytes;
  out AKey: ISecretBuffer): Boolean;
begin
  Result := FInner.CurrentKey(AKeyName, AKey);
end;

function TComplianceFleetTicketKeys.KeyByName(const AKeyName: TBytes;
  out AKey: ISecretBuffer): Boolean;
begin
  Result := FInner.KeyByName(AKeyName, AKey);
end;

function TComplianceFleetTicketKeys.KeyNameLength: Int32;
begin
  Result := FInner.KeyNameLength;
end;

procedure TComplianceFleetTicketKeys.InstallKey(const AName: TBytes;
  const AKey: ISecretBuffer);
begin
  FInner.InstallKey(AName, AKey);
end;

function TComplianceFleetTicketKeys.Policy: ICompliancePolicy;
begin
  Result := FPolicy;
end;

function TComplianceFleetTicketKeys.LifetimeSeconds: UInt32;
begin
  Result := 0;
end;

function TComplianceFleetTicketKeys.FleetScope: TBytes;
begin
  Result := System.Copy(FFleetScope);
end;

end.
