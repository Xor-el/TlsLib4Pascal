{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpIssuerResolution;

{$I ..\Include\TlsLib.inc}

interface

uses
  SysUtils,
  TlpArrayUtilities,
  TlpTlsAlert,
  TlpPkixDomainTypes,
  TlpIPkixProvider,
  TlpITrustAnchorStore,
  TlpTrustAnchorStore,
  TlpTrustTypes,
  TlpIIssuerLookup,
  TlpCertificateStrengthPolicy,
  TlpChainAlgorithmPolicy;

type
  /// <summary>
  /// Resolves, for one verification, the issuers a peer's chain names from an issuer lookup. Data
  /// in, verdict out: given the presented chain and the operator's intermediates it asks the lookup
  /// for each distinct issuer name once, then for the issuers of the intermediates it found, down
  /// to the path-building depth. Only a certificate the lookup returns under the asked name is
  /// used. A self-signed certificate the lookup offers as an anchor, and whose key meets the
  /// anchor floors, becomes an anchor; every other certificate is chain material only. The result
  /// is the base store with the anchors layered over it, and the intermediates found.
  /// </summary>
  TIssuerResolution = class sealed(TObject)
  strict private
  type
    TWalk = record
      Inspector: ICertificateInspector;
      Policy: TCertificateStrengthPolicy;
      Asked: TArray<TBytes>;
      Pending: TArray<TBytes>;
      Anchors: TArray<TBytes>;
      Found: TArray<TBytes>;
    end;
  strict private
    class function Holds(const AItems: TArray<TBytes>; const AItem: TBytes): Boolean; static;
    /// <summary>Queues AName to be asked unless it has been queued already.</summary>
    class procedure Queue(var AWalk: TWalk; const AName: TBytes); static;
    /// <summary>Queues the issuer name of ACertDer; a certificate that does not parse names none.</summary>
    class procedure QueueIssuerOf(var AWalk: TWalk; const ACertDer: TBytes); static;
    /// <summary>Takes the certificates of ABlobs that carry AName as their subject: an anchor when
    /// AClaimsAnchor and self-signed with a key above the floors, chain material otherwise.</summary>
    class procedure Admit(var AWalk: TWalk; const ABlobs: TArray<TBytes>;
      const AName: TBytes; AClaimsAnchor: Boolean); static;
  public
    /// <summary>AStore is ABase with the anchors found for the issuers of AChain and
    /// AIntermediates layered over it (ABase itself when none was found); AFound the intermediates
    /// found. A lookup that raises or returns unreadable data contributes nothing.</summary>
    class procedure Resolve(const AInspector: ICertificateInspector; const ALookup: IIssuerLookup;
      const APolicy: TCertificateStrengthPolicy; const ABase: ITrustAnchorStore;
      const AChain, AIntermediates: TArray<TBytes>; out AStore: ITrustAnchorStore;
      out AFound: TArray<TBytes>); static;
  end;

implementation

{ TIssuerResolution }

class function TIssuerResolution.Holds(const AItems: TArray<TBytes>;
  const AItem: TBytes): Boolean;
var
  LI: Int32;
begin
  Result := True;
  for LI := 0 to System.High(AItems) do
    if TArrayUtilities.AreEqual(AItems[LI], AItem) then
      Exit;
  Result := False;
end;

class procedure TIssuerResolution.Queue(var AWalk: TWalk; const AName: TBytes);
begin
  if Holds(AWalk.Asked, AName) then
    Exit;
  TArrayUtilities.Append<TBytes>(AWalk.Asked, AName);
  TArrayUtilities.Append<TBytes>(AWalk.Pending, AName);
end;

class procedure TIssuerResolution.QueueIssuerOf(var AWalk: TWalk; const ACertDer: TBytes);
var
  LIssuer: TBytes;
begin
  try
    LIssuer := AWalk.Inspector.Parse(ACertDer).IssuerName;
  except
    on Exception do
      Exit;
  end;
  Queue(AWalk, LIssuer);
end;

class procedure TIssuerResolution.Admit(var AWalk: TWalk; const ABlobs: TArray<TBytes>;
  const AName: TBytes; AClaimsAnchor: Boolean);
var
  LCerts: TArray<TBytes>;
  LCert: IInspectedCertificate;
  LSubject: TBytes;
  LAlert: TTlsAlertDescription;
  LB, LC: Int32;
begin
  for LB := 0 to System.High(ABlobs) do
  begin
    try
      LCerts := AWalk.Inspector.LoadChain(ABlobs[LB]);
    except
      on Exception do
        Continue;
    end;
    for LC := 0 to System.High(LCerts) do
    begin
      try
        LCert := AWalk.Inspector.Parse(LCerts[LC]);
        LSubject := LCert.SubjectName;
      except
        on Exception do
          Continue;
      end;
      // the name only selects which answer a certificate belongs to; trust is decided below
      if AWalk.Inspector.SameName(LSubject, AName) <> TCertAnswer.Yes then
        Continue;
      if AClaimsAnchor and (LCert.IsSelfSigned = TCertAnswer.Yes) then
      begin
        if TChainAlgorithmPolicy.AnchorsMeetKeyFloors(AWalk.Inspector,
          TArray<TBytes>.Create(LCerts[LC]), AWalk.Policy, LAlert) then
          TArrayUtilities.Append<TBytes>(AWalk.Anchors, LCerts[LC]);
      end
      else if not Holds(AWalk.Found, LCerts[LC]) then
      begin
        TArrayUtilities.Append<TBytes>(AWalk.Found, LCerts[LC]);
        QueueIssuerOf(AWalk, LCerts[LC]);
      end;
    end;
  end;
end;

class procedure TIssuerResolution.Resolve(const AInspector: ICertificateInspector;
  const ALookup: IIssuerLookup; const APolicy: TCertificateStrengthPolicy;
  const ABase: ITrustAnchorStore; const AChain, AIntermediates: TArray<TBytes>;
  out AStore: ITrustAnchorStore; out AFound: TArray<TBytes>);
var
  LWalk: TWalk;
  LNames: TArray<TBytes>;
  LAnswer: TLookedUpIssuers;
  LDepth, LI: Int32;
begin
  LWalk := Default(TWalk);
  LWalk.Inspector := AInspector;
  LWalk.Policy := APolicy;
  for LI := 0 to System.High(AChain) do
    QueueIssuerOf(LWalk, AChain[LI]);
  for LI := 0 to System.High(AIntermediates) do
    QueueIssuerOf(LWalk, AIntermediates[LI]);
  // one level per intermediate a built path may hold, plus the level that reaches its anchor
  LDepth := 0;
  while (System.Length(LWalk.Pending) > 0) and (LDepth <= TPathBuildLimits.MaxBuiltPathLength) do
  begin
    LNames := LWalk.Pending;
    LWalk.Pending := nil;
    for LI := 0 to System.High(LNames) do
    begin
      LAnswer := Default(TLookedUpIssuers);
      try
        LAnswer := ALookup.IssuersNamed(LNames[LI]);
      except
        on Exception do
          Continue;
      end;
      Admit(LWalk, LAnswer.Anchors, LNames[LI], True);
      Admit(LWalk, LAnswer.Intermediates, LNames[LI], False);
    end;
    Inc(LDepth);
  end;
  AStore := TTrustAnchorStore.Layered(ABase, LWalk.Anchors);
  AFound := LWalk.Found;
end;

end.
