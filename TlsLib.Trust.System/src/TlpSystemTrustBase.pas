{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpSystemTrustBase;

{$I ..\..\TlsLib\src\Include\TlsLib.inc}

interface

uses
  SysUtils,
  Generics.Collections,
  TlpTlsAlert,
  TlpIClock,
  TlpClock,
  TlpServerName,
  TlpEndpointIdentity,
  TlpTrustPolicy,
  TlpCertificateVerifier,
  TlpIPkixProvider,
  TlpPkixDomainTypes,
  TlpICertificateTrust,
  TlpITrustAnchorStore,
  TlpTrustAnchorStore,
  TlpTrustTypes,
  TlpTlsLibExceptions,
  TlpSystemTrustExceptions;

resourcestring
  SLiveNeedsLiveRevocationVerdict =
    'OS-native live revocation needs the live-revocation verdict enabled (it defers the live ' +
    'check to the out-of-band park); call WithLiveRevocationVerdict, or use cache-only trust';
  SHardNeedsLiveRevocationVerdict =
    'a Hard revocation posture on this platform needs the live-revocation verdict (the OS ' +
    'delegate is cache-only and cannot obtain a live revocation status); call ' +
    'WithLiveRevocationVerdict, or use a softer posture';
  SNoLiveRevocation =
    'this platform has no OS-native live revocation (only Windows and Apple do); keep cache-only ' +
    'trust and compose the portable live-revocation checker for a live check here';
  SEngineCannotTrustOsAndHostRoots =
    'this platform engine cannot trust OS and host roots together';
  SHostRootsNeedRoots =
    'HostRoots needs at least one root certificate (after the OS distrust list is applied)';
  SLiveNeedsKnownRoots =
    'the live revocation resolver cannot tell which roots the configured server verifier source ' +
    'trusts; use the OS verifier source or a trust store, or pass the OS source it wraps';
  SLiveNeedsServerVerification =
    'the live revocation resolver needs a client config that verifies the server certificate; ' +
    'this one has no trust store or OS verifier source (a PSK-only or skip-verify config)';
  SLiveRootsOfSourceDiffers =
    'the roots source passed to the live revocation resolver is not the OS verifier source the ' +
    'client config uses';
  SLiveRootsOfNeedsOsSource =
    'the live revocation resolver reads its roots off the OS verifier source; the roots source ' +
    'passed is not one';
  SEngineCannotTrustHostRootsAlone =
    'this platform engine cannot trust host roots alone (no exclusive server roots)';

type
  /// <summary>
  /// How the OS trust delegate performs revocation. CacheOnly (the default) evaluates against the
  /// OS revocation cache / the handshake staple with no socket, inline on the engine thread.
  /// Live re-runs the OS engine with network fetch enabled, off the engine thread in the async
  /// verdict park (the inline pass then defers an indeterminate revocation so the handshake parks).
  /// An armed live-revocation verdict defers an indeterminate cache-only outcome the same way.
  /// </summary>
  TSystemTrustFetch = (CacheOnly, Live);

  /// <summary>Whether host roots are trusted with the OS roots (OsAndHostRoots) or alone, so
  /// the OS roots never vouch for a chain (HostRoots).</summary>
  TSystemTrustRootScope = (OsAndHostRoots, HostRoots);

  /// <summary>What a platform chain engine can do beyond building and trusting a path. LiveFetch: it
  /// can re-evaluate with network revocation fetch on (the async park's live check). CachedRevocation:
  /// it renders a revocation outcome of its own from its cache and the handshake staple, so the inline
  /// pass decides Hard from that; an engine without it renders none, and the staple is the only inline
  /// revocation source. DnsIdentity: it matches a DNS host itself, so the host is withheld when the
  /// name check is off; the library matches the SAN identity (SAN-only, RFC 9525) regardless, for
  /// both DnsIdentity and chain-only engines. NativeAnchorUnion: one server evaluation trusts
  /// ExtraAnchors with the platform's own roots; without it the delegate retries a no-trust-anchor
  /// failure with the host roots as the exclusive root. ExclusiveServerAnchors: the server evaluation
  /// honours Anchors as its exclusive root, so host roots can be retried there or trusted alone; a
  /// server request with Anchors is refused on an engine without it.</summary>
  TPlatformChainCapability = (LiveFetch, CachedRevocation, DnsIdentity, NativeAnchorUnion,
    ExclusiveServerAnchors);
  TPlatformChainCapabilities = set of TPlatformChainCapability;

  /// <summary>What the engine is asked to do about revocation, already resolved from the posture and
  /// the deferral by the caller: None (Off), BestEffort (Soft, or a Hard whose indeterminate case is
  /// deferred to the park), RequirePositive (Hard decided here, or every live re-check so an
  /// indeterminate surfaces distinctly).</summary>
  TPlatformRevocationCheck = (None, BestEffort, RequirePositive);

  /// <summary>One platform chain evaluation. Chain is the peer chain (leaf first, DER). Anchors is the
  /// exclusive trust root: a client-certificate evaluation, a HostRoots server source, the
  /// live re-check of a client config that trusts its store roots (WebPki), or the retry with the
  /// host roots alone (empty on the other server paths, where the OS roots apply). Intermediates
  /// are the configured extra certificates, offered to path building as untrusted candidates
  /// beside the presented chain. ExtraAnchors are host roots trusted with the OS roots on the server path
  /// (read only by an engine with the NativeAnchorUnion capability; ignored when Anchors is set).
  /// ServerName is the server-path identity (the engine reads AsDns or ToString as its platform
  /// requires; empty on the client path). OcspStaple is consumed as cached revocation data where
  /// the platform can. NetworkAllowed is False inline (no socket) and True only from the
  /// off-engine-thread park. Clock nil means platform time; Android ignores it and validates at device
  /// time. DeadlineMs bounds a network fetch where the platform honours one.</summary>
  TPlatformChainRequest = record
    Chain: TArray<TBytes>;
    Anchors: TArray<TBytes>;
    ExtraAnchors: TArray<TBytes>;
    Intermediates: TArray<TBytes>;
    ServerName: TServerName;
    OcspStaple: TBytes;
    Revocation: TPlatformRevocationCheck;
    NetworkAllowed: Boolean;
    Clock: ITlsClock;
    DeadlineMs: Cardinal;
  end;

  /// <summary>Why a platform evaluation failed: NoTrustAnchor when the only fault is that no trusted
  /// root was reached, Other for any other rejection. None on success, or where an engine does not
  /// classify (treated as Other).</summary>
  TPlatformChainFailure = (None, NoTrustAnchor, Other);

  /// <summary>What the engine reports when the platform built a path: the revocation outcome it
  /// rendered (Indeterminate for an engine without CachedRevocation), the path it built, leaf
  /// first and ending at the trust anchor (the leaf alone where the platform reports no anchor), and
  /// the trust anchors whose signature and hash the strength policy skips; an exempt anchor's key is
  /// checked when the policy sets AnchorKeyFloors. An engine that reports no anchor (a client path) has the
  /// delegate build the path to the configured client-CA anchors itself. On a rejection only
  /// Failure is meaningful.</summary>
  TPlatformChainResult = record
    Outcome: TLiveRevocationOutcome;
    Path: TArray<TBytes>;
    PolicyExempt: TArray<TBytes>;
    Failure: TPlatformChainFailure;
  end;

  /// <summary>
  /// The post-checks every OS trust delegate applies once the OS engine has accepted the peer:
  /// they can only reject a peer or refuse a configuration, never turn an OS rejection into an
  /// acceptance. Centralized so the Windows, Apple and Android delegates decide these the same way:
  /// a definitive stapled Revoked always wins (RFC 6960), the name constraints of the anchor and of
  /// every intermediate are enforced over the OS-built path, the endpoint identity is matched in the
  /// library against the leaf SANs (SAN-only, so no engine's subject-CN fallback is trusted), RFC 7633
  /// must-staple + TLS Feature well-formedness are enforced, and a cache-only delegate cannot satisfy a
  /// Hard posture without the live-revocation verdict.
  /// </summary>
  TDelegatePostChecks = class sealed(TObject)
  public
    /// <summary>True (with AAlert = certificate_unknown) when the OS-built path violates the name
    /// constraints of its anchor or of any intermediate (RFC 5280 6.1.3 (b)(c), 6.1.4 (g)); no
    /// platform is trusted to have seeded the anchor's own constraints (RFC 5937 3). Fail-closed
    /// (internal_error) on a nil provider, an empty path or a provider that raises.</summary>
    class function RejectNameConstraintViolation(const APkix: IPkixProvider;
      const AOsPath: TArray<TBytes>; out AAlert: TTlsAlertDescription): Boolean; static;
    /// <summary>True (with AAlert = certificate_revoked) when the handshake staple is a definitive,
    /// authenticated Revoked over the OS-validated path - honored under every posture. A missing,
    /// Good or indeterminate staple does not fire here (the posture governs those). AOsPath carries
    /// the OS-supplied issuer so a leaf-only peer's staple can be authenticated. A nil clock falls
    /// back to system time (a nil clock would otherwise render every staple indeterminate).</summary>
    class function RejectStapledRevoked(const APkix: IPkixProvider;
      const AClock: ITlsClock; const AOsPath: TArray<TBytes>; const AStaple: TBytes;
      out AAlert: TTlsAlertDescription): Boolean; static;
    /// <summary>The one mapping from a handshake staple over the OS-validated path to a revocation
    /// outcome: Good for a fresh/unbounded good response, Revoked for a definitive revocation, else
    /// Indeterminate. A nil clock means system time (a nil clock would otherwise be indeterminate).</summary>
    class function StapleOutcome(const APkix: IPkixProvider; const AClock: ITlsClock;
      const AOsPath: TArray<TBytes>; const AStaple: TBytes): TLiveRevocationOutcome; static;
    /// <summary>Whether a Live fetch source is unusable without the live-revocation verdict (the
    /// live check runs only in the park that verdict arms).</summary>
    class function LiveNeedsLiveRevocation(AFetch: TSystemTrustFetch;
      ADeferral: TVerdictDeferral): Boolean; static;
    /// <summary>The host to hand the OS name check: the DNS host, or '' for an IP literal (which
    /// the OS must never name-check - the library matches it against iPAddress SANs instead).</summary>
    class function OsHostName(const AHostName: string): string; static;
    /// <summary>True (with AAlert = bad_certificate) when a non-empty AName does not match the leaf's
    /// dNSName / iPAddress SANs (RFC 9525), for an engine that validates the chain but not the host.
    /// An empty name never fires. A nil provider or empty path cannot match and fails closed
    /// (bad_certificate).</summary>
    class function RejectNameMismatch(const AName: TServerName;
      const APkix: IPkixProvider; const AOsPath: TArray<TBytes>;
      out AAlert: TTlsAlertDescription): Boolean; static;
    /// <summary>True (with a fatal alert) when the server leaf's RFC 7633 TLS Feature extension is
    /// malformed (bad_certificate - a hard invariant under every posture, role and occasion), or
    /// when the leaf is must-staple and the client asked to staple on the initial handshake yet no
    /// current Good staple was presented (bad_certificate_status_response, even under Soft/Off: a
    /// must-staple leaf demands stapling). The must-staple arm binds only to a server leaf -
    /// AStatusRequestOffered is never set for a client certificate - but the well-formedness
    /// invariant applies to both. Fail-closed on a nil provider or empty path.</summary>
    class function RejectMustStaple(const APkix: IPkixProvider; const AClock: ITlsClock;
      const AOsPath: TArray<TBytes>; const AStaple: TBytes; AStatusRequestOffered: Boolean;
      AOccasion: TVerificationOccasion; out AAlert: TTlsAlertDescription): Boolean; static;
  end;
  /// <summary>
  /// Deduplicates harvested roots by exact bytes: a filesystem store walking
  /// hashed-symlink directories sees the same certificate under several names.
  /// </summary>
  TSystemRootAccumulator = class sealed(TObject)
  strict private
    FRoots: TList<TBytes>;
    FSeen: TDictionary<TBytes, Boolean>;
  public
    constructor Create;
    destructor Destroy; override;
    procedure Add(const ADer: TBytes);
    function ToArray: TArray<TBytes>;
  end;

  /// <summary>
  /// Abstract platform trust-root SOURCE - it reads the OS trust store, it is not
  /// itself a trust store. Snapshot freezes the harvested roots, and the certificates the platform
  /// distrusts, into an immutable anchor store that the verifier consumes, so the anchors a config validates
  /// against are fixed at build time and never change under it; picking up OS changes
  /// means building a new snapshot. A source is a short-lived helper the caller owns
  /// and frees, and nothing is read until Harvest. Fail-closed: an empty or unreadable
  /// harvest raises rather than yielding an empty anchor set. Subclasses override
  /// HarvestRoots.
  /// </summary>
  TSystemRootSourceBase = class abstract(TObject)
  strict private
    FPkix: IPkixProvider;
  strict protected
    /// <summary>Gather the platform's trusted roots as DER. May return empty; Harvest
    /// turns an empty result into a fail-closed error.</summary>
    function HarvestRoots: TArray<TBytes>; virtual; abstract;
    /// <summary>The certificates the platform explicitly distrusts (raw DER), read in the same
    /// Snapshot as HarvestRoots and possibly collected by that read. Default none.</summary>
    function HarvestDistrusted: TArray<TBytes>; virtual;
    /// <summary>The platform's distrusted certificates (raw DER) read without a harvest, which
    /// ReadDistrusted de-duplicates. Default none.</summary>
    function CollectDistrusted: TArray<TBytes>; virtual;
    /// <summary>Human-readable source label, used in the fail-closed message.</summary>
    function SourceName: string; virtual; abstract;
    /// <summary>The PKIX provider, for subclasses that must parse (e.g. PEM).</summary>
    property Pkix: IPkixProvider read FPkix;
  protected
    /// <summary>Adds ADer to AAccumulator only if the provider confirms it a
    /// well-formed X.509 certificate; the accumulator handles the exact-byte
    /// de-dup for hashed-symlink directories.</summary>
    procedure AddUnique(const AAccumulator: TSystemRootAccumulator;
      const ADer: TBytes);
    /// <summary>Runs a fully-materialised raw DER set through the well-formed + de-dup
    /// accumulator and returns the filtered anchors; the whole-array harvesters share it
    /// (a streaming source calls AddUnique directly instead).</summary>
    function FilterRoots(const ARaw: TArray<TBytes>): TArray<TBytes>;
    /// <summary>ARaw with exact duplicates dropped and nothing else: distrust is matched by exact
    /// bytes, so an entry the provider cannot parse must still be kept.</summary>
    function DistinctDistrusted(const ARaw: TArray<TBytes>): TArray<TBytes>;
  public
    constructor Create(const APkix: IPkixProvider);
    /// <summary>Reads the source now. Fail-closed: an empty or unreadable source
    /// raises ESystemTrustUnavailableTlsLibException; a non-empty result is returned
    /// as harvested.</summary>
    function Harvest: TArray<TBytes>;
    /// <summary>The distrusted certificates alone, read without parsing the roots and de-duplicated
    /// like a snapshot's distrust set.</summary>
    function ReadDistrusted: TArray<TBytes>;
    /// <summary>Harvests now and freezes the result into an immutable anchor store.</summary>
    function Snapshot: ITrustAnchorStore;
  end;

implementation

resourcestring
  SSystemTrustEmpty =
    'the %s trust store could not be read or contained no usable root certificates';
  SNoProvider = 'a PKIX provider is required to read the system trust store';

{ TDelegatePostChecks }

class function TDelegatePostChecks.StapleOutcome(const APkix: IPkixProvider;
  const AClock: ITlsClock; const AOsPath: TArray<TBytes>;
  const AStaple: TBytes): TLiveRevocationOutcome;
var
  LClock: ITlsClock;
begin
  // a nil clock would make every staple indeterminate; the delegates accept a nil clock and mean
  // "system time", so honor that here rather than silently skipping the revocation check
  LClock := AClock;
  if LClock = nil then
    LClock := TSystemClock.Create as ITlsClock;
  case TOcspStaplePolicy.Verdict(APkix, LClock, AOsPath, AStaple) of
    TStapleVerdict.GoodFresh, TStapleVerdict.GoodUnbounded:
      Result := TLiveRevocationOutcome.Good;
    TStapleVerdict.Revoked:
      Result := TLiveRevocationOutcome.Revoked;
  else
    Result := TLiveRevocationOutcome.Indeterminate;
  end;
end;

class function TDelegatePostChecks.RejectStapledRevoked(
  const APkix: IPkixProvider; const AClock: ITlsClock;
  const AOsPath: TArray<TBytes>; const AStaple: TBytes;
  out AAlert: TTlsAlertDescription): Boolean;
begin
  Result := StapleOutcome(APkix, AClock, AOsPath, AStaple) = TLiveRevocationOutcome.Revoked;
  if Result then
    AAlert := TTlsAlertDescription.CertificateRevoked;
end;

class function TDelegatePostChecks.LiveNeedsLiveRevocation(
  AFetch: TSystemTrustFetch; ADeferral: TVerdictDeferral): Boolean;
begin
  Result := (AFetch = TSystemTrustFetch.Live) and
    (ADeferral <> TVerdictDeferral.LiveRevocation);
end;

class function TDelegatePostChecks.RejectNameConstraintViolation(const APkix: IPkixProvider;
  const AOsPath: TArray<TBytes>; out AAlert: TTlsAlertDescription): Boolean;
begin
  if (APkix = nil) or (System.Length(AOsPath) = 0) then
  begin
    AAlert := TTlsAlertDescription.InternalError;
    Exit(True);
  end;
  try
    Result := not APkix.PathValidation.NameConstraintsAdmit(AOsPath);
    if Result then
      AAlert := TTlsAlertDescription.CertificateUnknown;
  except
    // a provider that raises cannot vouch for the path
    on Exception do
    begin
      AAlert := TTlsAlertDescription.InternalError;
      Result := True;
    end;
  end;
end;

class function TDelegatePostChecks.OsHostName(const AHostName: string): string;
var
  LName: TServerName;
begin
  if TServerName.TryParse(AHostName, LName) and LName.IsIp then
    Result := ''
  else
    Result := AHostName;
end;

class function TDelegatePostChecks.RejectNameMismatch(const AName: TServerName;
  const APkix: IPkixProvider; const AOsPath: TArray<TBytes>;
  out AAlert: TTlsAlertDescription): Boolean;
begin
  // an engine that validates the chain but not the host: the full RFC 9525 identity is matched here.
  // an empty name never fires; without a provider to read the SANs, or with no validated leaf, the
  // name cannot be confirmed and fails closed
  if AName.IsEmpty then
    Exit(False);
  if (APkix = nil) or (System.Length(AOsPath) = 0) then
  begin
    AAlert := TTlsAlertDescription.BadCertificate;
    Exit(True);
  end;
  Result := not TEndpointIdentity.Matches(AName,
    APkix.Certificates.DnsNames(AOsPath[0]),
    APkix.Certificates.IpAddresses(AOsPath[0]));
  if Result then
    AAlert := TTlsAlertDescription.BadCertificate;
end;

class function TDelegatePostChecks.RejectMustStaple(const APkix: IPkixProvider;
  const AClock: ITlsClock; const AOsPath: TArray<TBytes>; const AStaple: TBytes;
  AStatusRequestOffered: Boolean; AOccasion: TVerificationOccasion;
  out AAlert: TTlsAlertDescription): Boolean;
var
  LFeatures: TArray<UInt16>;
  LClock: ITlsClock;
  LMustStaple: Boolean;
  LI: Int32;
begin
  if (APkix = nil) or (System.Length(AOsPath) = 0) then
  begin
    AAlert := TTlsAlertDescription.InternalError;
    Exit(True);
  end;
  // the RFC 7633 TLS Feature well-formedness is a hard invariant regardless of posture, role or
  // occasion: a value that is not a SEQUENCE OF INTEGER is fatal (built-in verifier parity)
  if not APkix.Certificates.TlsFeatures(AOsPath[0], LFeatures) then
  begin
    AAlert := TTlsAlertDescription.BadCertificate;
    Exit(True);
  end;
  // must-staple binds only to a server leaf on the initial handshake the client asked to staple
  // (RFC 7633 4.3.3); AStatusRequestOffered is never set for a client certificate or a resumption
  if not (AStatusRequestOffered and
    (AOccasion = TVerificationOccasion.InitialHandshake)) then
    Exit(False);
  LMustStaple := False;
  for LI := 0 to System.High(LFeatures) do
    if LFeatures[LI] = TTlsFeatureCodes.StatusRequest then
    begin
      LMustStaple := True;
      Break;
    end;
  if not LMustStaple then
    Exit(False);
  // a must-staple leaf demands a current Good staple even under Soft/Off and even when a live
  // resolver exists: a live fetch does not satisfy a leaf that demands stapling
  LClock := AClock;
  if LClock = nil then
    LClock := TSystemClock.Create as ITlsClock;
  case TOcspStaplePolicy.Verdict(APkix, LClock, AOsPath, AStaple) of
    TStapleVerdict.GoodFresh, TStapleVerdict.GoodUnbounded:
      Result := False;
  else
    begin
      AAlert := TTlsAlertDescription.BadCertificateStatusResponse;
      Result := True;
    end;
  end;
end;

{ TSystemRootAccumulator }

constructor TSystemRootAccumulator.Create;
begin
  inherited Create;
  FRoots := TList<TBytes>.Create;
  FSeen := TDictionary<TBytes, Boolean>.Create;
end;

destructor TSystemRootAccumulator.Destroy;
begin
  FSeen.Free;
  FRoots.Free;
  inherited Destroy;
end;

procedure TSystemRootAccumulator.Add(const ADer: TBytes);
var
  LCopy: TBytes;
begin
  if FSeen.ContainsKey(ADer) then
    Exit;
  LCopy := Copy(ADer, 0, Length(ADer));
  FSeen.Add(LCopy, True);
  FRoots.Add(LCopy);
end;

function TSystemRootAccumulator.ToArray: TArray<TBytes>;
begin
  Result := FRoots.ToArray;
end;

{ TSystemRootSourceBase }

constructor TSystemRootSourceBase.Create(const APkix: IPkixProvider);
begin
  inherited Create;
  if APkix = nil then
    raise EArgumentTlsLibException.CreateRes(@SNoProvider);
  FPkix := APkix;
end;

procedure TSystemRootSourceBase.AddUnique(const AAccumulator: TSystemRootAccumulator;
  const ADer: TBytes);
begin
  if not FPkix.Certificates.IsWellFormed(ADer) then
    Exit;
  AAccumulator.Add(ADer);
end;

function TSystemRootSourceBase.FilterRoots(const ARaw: TArray<TBytes>): TArray<TBytes>;
var
  LAcc: TSystemRootAccumulator;
  LI: Integer;
begin
  Result := nil;
  LAcc := TSystemRootAccumulator.Create;
  try
    for LI := 0 to Length(ARaw) - 1 do
      AddUnique(LAcc, ARaw[LI]);
    Result := LAcc.ToArray;
  finally
    LAcc.Free;
  end;
end;

function TSystemRootSourceBase.DistinctDistrusted(const ARaw: TArray<TBytes>): TArray<TBytes>;
var
  LAcc: TSystemRootAccumulator;
  LI: Integer;
begin
  Result := nil;
  LAcc := TSystemRootAccumulator.Create;
  try
    for LI := 0 to Length(ARaw) - 1 do
      LAcc.Add(ARaw[LI]);
    Result := LAcc.ToArray;
  finally
    LAcc.Free;
  end;
end;

function TSystemRootSourceBase.Harvest: TArray<TBytes>;
begin
  Result := HarvestRoots;
  if Length(Result) = 0 then
    raise ESystemTrustUnavailableTlsLibException.CreateResFmt(
      @SSystemTrustEmpty, [SourceName]);
end;

function TSystemRootSourceBase.HarvestDistrusted: TArray<TBytes>;
begin
  Result := nil;
end;

function TSystemRootSourceBase.CollectDistrusted: TArray<TBytes>;
begin
  Result := nil;
end;

function TSystemRootSourceBase.ReadDistrusted: TArray<TBytes>;
begin
  Result := DistinctDistrusted(CollectDistrusted);
end;

function TSystemRootSourceBase.Snapshot: ITrustAnchorStore;
var
  LRoots: TArray<TBytes>;
begin
  // a failed harvest raises here, before any store is built; the distrust set is read after the
  // roots so a source that collects it while harvesting has it ready, and is de-duplicated
  LRoots := Harvest;
  Result := TTrustAnchorStore.Create(LRoots,
    DistinctDistrusted(HarvestDistrusted)) as ITrustAnchorStore;
  // a source whose every root is also distrusted would leave no anchor at all: fail closed here
  // rather than hand back a store that only ever answers unknown_ca
  if Result.AnchorCount = 0 then
    raise ESystemTrustUnavailableTlsLibException.CreateResFmt(@SSystemTrustEmpty,
      [SourceName]);
end;

end.
