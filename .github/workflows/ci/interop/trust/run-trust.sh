#!/usr/bin/env bash
# Native-trust cells for the interop harness. Two layers over one per-run generated CA:
#
#   * portable  - our PKIX verifier against a fixed generated root. Needs no OS mutation, so it
#                 runs on every native interop leg and asserts the exact abort alerts.
#   * delegate  - our client verifies the SERVER certificate through the OS trust engine against
#                 the real machine store (Windows crypt32 / Apple SecTrust). Only reachable by
#                 installing the generated root, so it runs on Windows/macOS and brackets the
#                 install: reject (before install) -> install -> accept + reject verdicts ->
#                 uninstall -> reject (after). The pre-install reject proves the store is the
#                 discriminator (a leaked root cannot make it pass); the post-uninstall reject
#                 proves cleanup. The root's CN carries a per-run id so it never collides.
#                 The machine store is only ever mutated on a github-hosted runner or
#                 when TLSLIB_TRUST_ALLOW_STORE_MUTATION=true is set; elsewhere only the reject path runs.
#   * os-anchors - our own verifier over the OS root set and its distrust set (the same installed
#                 root). Inside the bracket a second per-run intermediate is marked OS-distrusted
#                 (Windows Disallowed / macOS Deny): both the delegate and os-anchors must reject a
#                 path through it (os-anchors with bad_certificate), a non-distrusted intermediate
#                 and a twin of the distrusted one still verify. Before the root install, the same
#                 distrust is applied to a path that relied on a --host-root (the run root passed
#                 with the OS roots, or alone with --host-roots-alone), where it must win too in
#                 both the delegate and os-anchors.
#
# The server-cert delegate reject cells whose alert is a per-OS status-map code (hostname, EKU,
# expired) assert only that the handshake aborts with a fatal alert, not the exact code: the two OS
# engines render those differently and pinning them per OS is out of scope here. The revocation cells
# DO assert the exact certificate_revoked(44) - both OS engines render a definitive Revoked
# identically - as do the library post-check cells (a stapled Revoked under Off, an IP-literal
# against a DNS-only leaf), whose alert the library itself produces.
#
#   * server verifies client (mTLS live) - our SERVER verifies the peer CLIENT certificate live
#                 through the OS delegate (an in-process client presenter offers the cert). It roots
#                 against the in-memory exclusive client-CA anchors, never the machine store, so the
#                 good/revoked/unreachable cells need NO install and run locally too; only the
#                 exclusivity cell (foreign resolver CA) runs inside the install bracket, where it can
#                 discriminate. Its revoked(44)/indeterminate(113) alerts come from our resolver, not
#                 the OS map, so they are asserted exactly on both platforms.
#   * Windows AUTOROOT - informational, off unless MAKE_RUN_AUTOROOT=true, github-hosted CI only: removes one public root (and only it)
#                 from the stores, builds a chain for its public intermediate under our inline/live
#                 flags vs a control, and reports whether crypt32 re-installs the root. Always restored.
#   * macOS trust mode comparison - report-only, CI-gated: the same hosts through both modes, to see
#                 whether the Anchors harvest and Apple SecTrust ever disagree. Never fails the leg.
set -euo pipefail

SHIM="${1:?usage: run-trust.sh <TrustDelegateInterop binary>}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../../shared/common.sh
source "$HERE/../../shared/common.sh"

TMP="$(mktemp -d)"
CA="$TMP/ca"
RUNID="tlslib-trust-$(date +%s)-$$"
INSTALLED=0
FAILURES=0
OSNAME="$(uname -s)"
# a per-run loopback port + URL for the live OCSP responder (the live cells fetch it)
OCSP_PORT=$(( 20000 + (RANDOM % 20000) ))
while (echo >"/dev/tcp/127.0.0.1/$OCSP_PORT") 2>/dev/null; do
  OCSP_PORT=$(( 20000 + (RANDOM % 20000) ))  # in use (connect succeeded): pick another
done
OCSP_URL="http://127.0.0.1:$OCSP_PORT"
OCSP_PID=""
# a separate DEAD port for the server-verifies-client indeterminate cell: nothing ever listens here,
# so the live client-cert check reaches the network and is refused fast (a distinct URL that never
# changes state, so no cell ordering can flip the result)
DEAD_PORT=$(( 40000 + (RANDOM % 20000) ))
while [ "$DEAD_PORT" = "$OCSP_PORT" ] || (echo >"/dev/tcp/127.0.0.1/$DEAD_PORT") 2>/dev/null; do
  DEAD_PORT=$(( 40000 + (RANDOM % 20000) ))  # in use (connect succeeded): pick another
done
DEAD_URL="http://127.0.0.1:$DEAD_PORT"
# a third loopback port for the CRL server (the Windows-only CRL-source cell). Free and distinct from
# the OCSP and DEAD ports; the CDP is baked into the leaf at gen time, so it must be fixed before gen.
CRL_PORT=$(( 10000 + (RANDOM % 10000) ))
while [ "$CRL_PORT" = "$OCSP_PORT" ] || [ "$CRL_PORT" = "$DEAD_PORT" ] || (echo >"/dev/tcp/127.0.0.1/$CRL_PORT") 2>/dev/null; do
  CRL_PORT=$(( 10000 + (RANDOM % 10000) ))  # in use or clashes: pick another
done
CRL_URL="http://127.0.0.1:$CRL_PORT/root.crl"
CRL_PID=""
CRL_READY=0

THUMB=""   # set after the CA exists
DTHUMB=""  # the distrusted intermediate's thumbprint, set after the CA exists
DISTRUSTED=0

# parsed once up front, so a bad value fails before any store work
case "$(printf '%s' "${TLSLIB_TRUST_ALLOW_STORE_MUTATION:-}" | tr '[:upper:]' '[:lower:]' | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')" in
  ''|false) STORE_MUTATION_FORCED=false ;;
  true) STORE_MUTATION_FORCED=true ;;
  *) echo "TLSLIB_TRUST_ALLOW_STORE_MUTATION: \"$TLSLIB_TRUST_ALLOW_STORE_MUTATION\" is not true or false" >&2
     exit 2 ;;
esac

# The cells that install into the machine trust store only ever run on a CI runner (or when
# explicitly forced): a developer machine's store is never mutated by a casual local run.
ci_store_mutation_allowed() {
  { [ "${GITHUB_ACTIONS:-}" = "true" ] && [ "${RUNNER_ENVIRONMENT:-}" = "github-hosted" ]; } ||
    [ "$STORE_MUTATION_FORCED" = "true" ]
}

cleanup() {
  if [ -n "$OCSP_PID" ]; then kill "$OCSP_PID" >/dev/null 2>&1 || true; fi
  if [ -n "$CRL_PID" ]; then kill "$CRL_PID" >/dev/null 2>&1 || true; wait "$CRL_PID" 2>/dev/null || true; fi
  if [ "$DISTRUSTED" = 1 ]; then uninstall_distrust || true; fi
  if [ "$INSTALLED" = 1 ]; then uninstall_root || true; fi
  autoroot_svc_ensure || true
  autoroot_restore || true
  autoroot_policy_restore || true
  autoroot_capi_off || true
  rm -rf "$TMP"
}

install_root() { # add the test root to the machine store (non-interactive on an admin/root runner)
  case "$OSNAME" in
    MINGW*|MSYS*|CYGWIN*|Windows*)
      certutil -addstore -f Root "$(cygpath -w "$CA/root.pem")" >/dev/null 2>&1 ;;
    Darwin)
      sudo security add-trusted-cert -d -r trustRoot \
        -k /Library/Keychains/System.keychain "$CA/root.pem" >/dev/null 2>&1 ;;
    *) return 1 ;;
  esac
}
uninstall_root() { # remove the test root so the post-uninstall cell rejects again
  case "$OSNAME" in
    MINGW*|MSYS*|CYGWIN*|Windows*)
      certutil -delstore Root "$THUMB" >/dev/null 2>&1 || true ;;
    Darwin)
      # delete the keychain ITEM: with no keychain holding the root, trustd cannot build the path and
      # rejects. Non-interactive as root (the System keychain is unlocked); this is what un-anchors,
      # since remove-trusted-cert would need the SIP-restricted trust-settings.admin right.
      sudo security delete-certificate -Z "$THUMB" \
        /Library/Keychains/System.keychain >/dev/null 2>&1 || true ;;
  esac
}

install_distrust() { # mark the distrusted intermediate as explicitly untrusted by the OS
  case "$OSNAME" in
    MINGW*|MSYS*|CYGWIN*|Windows*)
      # both the machine and the current-user Disallowed store: the OS chain engine reads both, and
      # the Anchors harvest opens the current-user view
      certutil -addstore -f Disallowed "$(cygpath -w "$CA/distrust_issuer.pem")" >/dev/null 2>&1 &&
      certutil -user -addstore -f Disallowed "$(cygpath -w "$CA/distrust_issuer.pem")" >/dev/null 2>&1 ;;
    Darwin)
      # no -p: the Deny applies to every policy, as a user "Never Trust" does
      sudo security add-trusted-cert -d -r deny \
        -k /Library/Keychains/System.keychain "$CA/distrust_issuer.pem" >/dev/null 2>&1 ;;
    *) return 1 ;;
  esac
}
uninstall_distrust() {
  case "$OSNAME" in
    MINGW*|MSYS*|CYGWIN*|Windows*)
      certutil -delstore Disallowed "$DTHUMB" >/dev/null 2>&1 || true
      certutil -user -delstore Disallowed "$DTHUMB" >/dev/null 2>&1 || true ;;
    Darwin)
      sudo security delete-certificate -Z "$DTHUMB" \
        /Library/Keychains/System.keychain >/dev/null 2>&1 || true ;;
  esac
}

AUTOROOT_ARMED=0
autoroot_ps() { # <action> [extra args]: run the AUTOROOT helper bounded; a timeout warns on stderr, rc stays 0
  local action="$1" secs=60 rc=0 out; shift
  case "$action" in
    restore) secs=120 ;;
    diag|ctl|leaf|capidump|svcrestart|svcensure) secs=90 ;;
  esac
  mkdir -p "$TMP/autoroot"
  out="$TMP/autoroot/$action.out"
  ci_run_bounded "$secs" powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass \
    -File "$(cygpath -w "$HERE/autoroot-probe.ps1")" -Action "$action" \
    -Work "$(cygpath -w "$TMP/autoroot")" "$@" >"$out" 2>&1 </dev/null || rc=$?
  tr -d '\r' <"$out"
  case "$rc" in
    124|137|142|143) echo "  WARN  AUTOROOT $action timed out" >&2 ;;
  esac
  return 0
}
autoroot_restore() { # idempotent: put back every removed root and print the tally; a timeout never blocks the job
  [ "$AUTOROOT_ARMED" = 1 ] || return 0
  AUTOROOT_ARMED=0
  local out line missing
  out="$(autoroot_ps restore)"
  printf '%s\n' "$out" | sed 's/^/  /'
  line="$(printf '%s\n' "$out" | tail -n 1)"
  case "$line" in
    removed=*) ;;
    *) echo "  WARN  AUTOROOT restore result unreadable"; return 0 ;;
  esac
  echo "AUTOROOT RESTORE $line"
  missing="${line##*missing=}"
  case "$missing" in
    ''|*[!0-9]*) echo "  WARN  AUTOROOT restore result unreadable" ;;
    0) ;;
    *) echo "  WARN  $missing removed root(s) could not be restored"; AUTOROOT_ARMED=1 ;;
  esac
}

trap cleanup EXIT

OPENSSL="${OPENSSL:-openssl}"
# on the macOS runner /usr/bin/openssl is LibreSSL; prefer Homebrew openssl@3 (as the openssl matrix
# does) so the responder signs with SHA-256 and matches the rest of the interop
if [ "$OSNAME" = "Darwin" ] && command -v brew >/dev/null 2>&1; then
  BREW_SSL="$(brew --prefix openssl@3 2>/dev/null || true)"
  [ -n "$BREW_SSL" ] && [ -x "$BREW_SSL/bin/openssl" ] && OPENSSL="$BREW_SSL/bin/openssl"
fi
OPENSSL="$OPENSSL" bash "$HERE/gen-trust-ca.sh" "$CA" "$RUNID" "$OCSP_URL" "$DEAD_URL" "$CRL_URL"
THUMB="$("$OPENSSL" x509 -in "$CA/root.pem" -noout -fingerprint -sha1 | sed 's/.*=//; s/://g')"
DTHUMB="$("$OPENSSL" x509 -in "$CA/distrust_issuer.pem" -noout -fingerprint -sha1 | sed 's/.*=//; s/://g')"
case "$OSNAME" in
  MINGW*|MSYS*|CYGWIN*|Windows*|Darwin) HAS_DELEGATE=1 ;;
  *) HAS_DELEGATE=0 ;;
esac

# a loopback OCSP responder for the live cells: serves the live index (accept leaves Valid, revoked
# leaves Revoked) signed by the root-delegated OCSPSigning responder both crypt32 and trustd accept.
# Only the OS-delegate cells fetch from it, so it runs only where they do. It runs for the whole
# bracket and is killed by the EXIT trap. The server-verifies-client live cells below use it WITHOUT
# a store install, so it is load-bearing - wait for it to accept connections.
if [ "$HAS_DELEGATE" = 1 ]; then
  "$OPENSSL" ocsp -index "$CA/index_live.txt" -CA "$CA/root.pem" \
    -rsigner "$CA/ocsp_signer.pem" -rkey "$CA/ocsp_signer.key" \
    -port "$OCSP_PORT" -rmd sha256 >/dev/null 2>&1 &
  OCSP_PID=$!
  # readiness probe: a REAL OCSP query (live_leaf is serial 4001, Valid in the index). A raw TCP
  # connect would be read by the single-threaded responder as a malformed request and disturb it; a
  # valid query it answers and loops. The new server cells run before the cells that used to warm it up.
  OCSP_READY=0
  for _ in $(seq 1 50); do
    if ci_run_bounded 10 "$OPENSSL" ocsp -CAfile "$CA/root.pem" -issuer "$CA/root.pem" \
      -cert "$CA/live_leaf.pem" -url "$OCSP_URL" >/dev/null 2>&1; then OCSP_READY=1; break; fi
    sleep 0.2
  done
  if [ "$OCSP_READY" -ne 1 ]; then
    echo "ERROR: the OCSP responder never answered on $OCSP_URL" >&2
    exit 1
  fi
fi
# a loopback HTTP server for the root-signed CRL (the Windows-only CRL-source cell). Serves ONLY the
# CRL from a dedicated dir (never the CA dir with its keys). Threaded server tolerates raw probes;
# curl-probe until it answers. A missing or non-running python leaves CRL_READY=0 - the Windows cell
# then FAILS rather than skipping, so a broken server can never make the cell vacuously pass.
# A name that merely exists is not enough (Windows python3 can be the Store stub): take the first
# interpreter that runs.
PYRUN=()
for _py in "python3" "python" "py -3"; do
  # shellcheck disable=SC2086
  if $_py -c 'import sys' >/dev/null 2>&1; then read -r -a PYRUN <<< "$_py"; break; fi
done
CRL_LOG="$TMP/crl-server.log"
if [ "${#PYRUN[@]}" -gt 0 ]; then
  # --directory (not cd in a subshell): keep python's CWD off "www" so cleanup can rm it on Windows,
  # and so $! is python itself, not a wrapper subshell that would orphan python on kill.
  "${PYRUN[@]}" -m http.server "$CRL_PORT" --bind 127.0.0.1 --directory "$CA/www" >"$CRL_LOG" 2>&1 &
  CRL_PID=$!
  for _ in $(seq 1 50); do
    if curl -fsS --max-time 5 -o /dev/null "$CRL_URL" 2>/dev/null; then CRL_READY=1; break; fi
    sleep 0.2
  done
else
  echo "no working python3, python or py -3 found" > "$CRL_LOG"
fi
# a verify time past the 30-day leaf notAfter, to prove the injected clock reaches validation
FUTURE_MS=$(( ($(date +%s) + 60*86400) * 1000 ))

cell() { # <label> <shim-args...>
  local label="$1"; shift
  if ci_run_bounded 120 "$SHIM" "$@" > "$TMP/o" 2>&1; then
    echo "  PASS  $label"
  else
    echo "  FAIL  $label -> $(cat "$TMP/o")"; FAILURES=$((FAILURES+1))
  fi
}

echo "=== portable verifier (generated CA, no OS store) ==="
for V in 13 12; do
  cell "[$V] accept (good/Hard)" --tls-version $V --trust-mode portable --root "$CA/root.pem" \
    --server-cert "$CA/leaf_fullchain.pem" --server-key "$CA/leaf.key" \
    --staple "$CA/ocsp_good.der" --posture hard --expect accept
  cell "[$V] revoked staple -> certificate_revoked" --tls-version $V --trust-mode portable \
    --root "$CA/root.pem" --server-cert "$CA/leaf_fullchain.pem" --server-key "$CA/leaf.key" \
    --staple "$CA/ocsp_revoked.der" --posture soft --expect reject:44
  cell "[$V] must-staple, no staple -> bad_certificate_status_response" --tls-version $V \
    --trust-mode portable --root "$CA/root.pem" --server-cert "$CA/muststaple_fullchain.pem" \
    --server-key "$CA/muststaple.key" --posture off --expect reject:113
  cell "[$V] wrong EKU -> reject" --tls-version $V --trust-mode portable --root "$CA/root.pem" \
    --server-cert "$CA/wrongeku_fullchain.pem" --server-key "$CA/wrongeku.key" \
    --posture off --expect reject
  cell "[$V] hostname mismatch -> reject" --tls-version $V --trust-mode portable \
    --root "$CA/root.pem" --server-cert "$CA/leaf_fullchain.pem" --server-key "$CA/leaf.key" \
    --staple "$CA/ocsp_good.der" --posture hard --expect-name wrong.example --expect reject
  cell "[$V] expired via injected clock -> reject" --tls-version $V --trust-mode portable \
    --root "$CA/root.pem" --server-cert "$CA/leaf_fullchain.pem" --server-key "$CA/leaf.key" \
    --staple "$CA/ocsp_good.der" --posture hard --now-ms "$FUTURE_MS" --expect reject
  cell "[$V] untrusted root -> reject" --tls-version $V --trust-mode portable \
    --root "$CA/root.pem" --server-cert "$CA/foreign_fullchain.pem" \
    --server-key "$CA/foreign_leaf.key" --posture off --expect reject
done

if [ "$HAS_DELEGATE" = 1 ]; then
  echo "=== OS trust delegate (real machine store) ==="
  # bracket, before install: the store is the discriminator
  cell "delegate untrusted foreign root -> reject" --trust-mode os-delegate \
    --server-cert "$CA/foreign_fullchain.pem" --server-key "$CA/foreign_leaf.key" \
    --posture soft --expect reject
  cell "delegate pre-install our root -> reject" --trust-mode os-delegate \
    --server-cert "$CA/leaf_fullchain.pem" --server-key "$CA/leaf.key" \
    --staple "$CA/ocsp_good.der" --posture soft --expect reject

  # server verifies a CLIENT certificate live through the OS delegate. This roots against the
  # in-memory exclusive client-CA anchors (never the machine store), so it needs NO root install and
  # runs on any OS-delegate platform - locally included. The reject alerts (44 revoked, 113
  # indeterminate) come from our resolver, not the OS map, so they are asserted exactly on both
  # platforms. The server presents a root-signed server cert the in-process client presenter trusts;
  # the presenter offers the client leaf, whose AIA the OS server re-checks against the responder.
  echo "=== OS trust delegate: server verifies client certificate (live) ==="
  for V in 13 12; do
    cell "[$V] server live good client -> accept" --role server --tls-version $V \
      --root "$CA/root.pem" --server-cert "$CA/live_leaf_fullchain.pem" \
      --server-key "$CA/live_leaf.key" --client-cert "$CA/live_client_good.pem" \
      --client-key "$CA/live_client_good.key" --client-ca "$CA/root.pem" \
      --posture hard --expect accept
    cell "[$V] server live revoked client -> certificate_revoked" --role server --tls-version $V \
      --root "$CA/root.pem" --server-cert "$CA/live_leaf_fullchain.pem" \
      --server-key "$CA/live_leaf.key" --client-cert "$CA/live_client_revoked.pem" \
      --client-key "$CA/live_client_revoked.key" --client-ca "$CA/root.pem" \
      --posture hard --expect reject:44
  done

  # OS distrust beats a host root: the run root is NOT installed here, only passed as --host-root, so a
  # path through the OS-distrusted intermediate relies on the host root and must still be refused. The
  # baseline accept (host root, nothing distrusted) and the undistrusted-intermediate control keep the
  # reject from being a vacuous "host root ignored".
  echo "=== host root vs OS distrust (root not installed) ==="
  cell "delegate host root baseline -> accept" --trust-mode os-delegate \
    --host-root "$CA/root.pem" --server-cert "$CA/distrust_leaf_fullchain.pem" \
    --server-key "$CA/distrust_leaf.key" --posture soft --expect accept
  cell "anchors host root baseline -> accept" --trust-mode os-anchors \
    --host-root "$CA/root.pem" --server-cert "$CA/distrust_leaf_fullchain.pem" \
    --server-key "$CA/distrust_leaf.key" --posture soft --expect accept
  cell "delegate host root alone baseline -> accept" --trust-mode os-delegate \
    --host-root "$CA/root.pem" --host-roots-alone --server-cert "$CA/distrust_leaf_fullchain.pem" \
    --server-key "$CA/distrust_leaf.key" --posture soft --expect accept
  cell "anchors host root alone baseline -> accept" --trust-mode os-anchors \
    --host-root "$CA/root.pem" --host-roots-alone --server-cert "$CA/distrust_leaf_fullchain.pem" \
    --server-key "$CA/distrust_leaf.key" --posture soft --expect accept
  if ci_store_mutation_allowed && { DISTRUSTED=1; install_distrust; }; then
    echo "  (distrusted intermediate $DTHUMB, host root alone and with the OS roots)"
    cell "delegate host root alone + distrusted intermediate -> reject" --trust-mode os-delegate \
      --host-root "$CA/root.pem" --host-roots-alone --server-cert "$CA/distrust_leaf_fullchain.pem" \
      --server-key "$CA/distrust_leaf.key" --posture soft --expect reject
    cell "anchors host root alone + distrusted intermediate -> bad_certificate" \
      --trust-mode os-anchors --host-root "$CA/root.pem" --host-roots-alone \
      --server-cert "$CA/distrust_leaf_fullchain.pem" --server-key "$CA/distrust_leaf.key" \
      --posture soft --expect reject:42
    cell "delegate host root + distrusted intermediate -> reject" --trust-mode os-delegate \
      --host-root "$CA/root.pem" --server-cert "$CA/distrust_leaf_fullchain.pem" \
      --server-key "$CA/distrust_leaf.key" --posture soft --expect reject
    cell "[12] delegate host root + distrusted intermediate -> reject" --trust-mode os-delegate \
      --tls-version 12 --host-root "$CA/root.pem" --server-cert "$CA/distrust_leaf_fullchain.pem" \
      --server-key "$CA/distrust_leaf.key" --posture soft --expect reject
    cell "anchors host root + distrusted intermediate -> bad_certificate" --trust-mode os-anchors \
      --host-root "$CA/root.pem" --server-cert "$CA/distrust_leaf_fullchain.pem" \
      --server-key "$CA/distrust_leaf.key" --posture soft --expect reject:42
    cell "delegate host root, undistrusted intermediate (control) -> accept" \
      --trust-mode os-delegate --host-root "$CA/root.pem" --server-cert "$CA/leaf_fullchain.pem" \
      --server-key "$CA/leaf.key" --staple "$CA/ocsp_good.der" --posture soft --expect accept
    uninstall_distrust
    DISTRUSTED=0
    case "$OSNAME" in
      MINGW*|MSYS*|CYGWIN*|Windows*)
        cell "delegate host root after removing the distrust -> accept" --trust-mode os-delegate \
          --host-root "$CA/root.pem" --server-cert "$CA/distrust_leaf_fullchain.pem" \
          --server-key "$CA/distrust_leaf.key" --posture soft --expect accept ;;
      *) echo "  (skipped post-removal cell: a macOS trust setting needs the SIP-restricted right to remove)" ;;
    esac
  elif ci_store_mutation_allowed; then
    echo "  FAIL  could not install the distrusted intermediate"
    FAILURES=$((FAILURES+1))
  else
    echo "  SKIPPED: store mutation not allowed (set TLSLIB_TRUST_ALLOW_STORE_MUTATION=true to force)"
  fi

  if ci_store_mutation_allowed && { INSTALLED=1; install_root; }; then
    echo "  (installed test root $THUMB)"
    # 2-tier chain (root -> leaf, no intermediate) under Hard: the only non-anchor cert is the leaf,
    # which carries a good stapled OCSP, so every element trustd/crypt32 revocation-checks has a
    # positive answer (the anchor is exempt). A 3-tier chain would leave the intermediate with no
    # staple -> indeterminate -> Hard rejects on macOS; the 3-tier good/Hard path is asserted by the
    # portable cells instead.
    cell "delegate accept (2-tier, good/Hard)" --trust-mode os-delegate \
      --server-cert "$CA/direct_fullchain.pem" --server-key "$CA/direct_leaf.key" \
      --staple "$CA/ocsp_good_direct.der" --posture hard --expect accept
    # under Soft the OS engine revocation-checks cache-only and consumes the stapled Revoked as cached
    # revocation, so the engine itself renders Revoked -> certificate_revoked(44). An 80 here would
    # mean the engine returned Revoked with an empty path (the crypt32 CRYPT_E_REVOKED vs CERT_E_REVOKED
    # mapping is the one that bit us before), so pin the exact alert.
    cell "delegate revoked staple (Soft) -> certificate_revoked" --trust-mode os-delegate \
      --server-cert "$CA/leaf_fullchain.pem" --server-key "$CA/leaf.key" \
      --staple "$CA/ocsp_revoked.der" --posture soft --expect reject:44
    # a definitive stapled Revoked wins under EVERY posture, Off included: the OS engine skips
    # revocation under Off, so this reject comes solely from the library post-check - hence exact 44
    cell "delegate revoked staple under Off -> certificate_revoked" --trust-mode os-delegate \
      --server-cert "$CA/leaf_fullchain.pem" --server-key "$CA/leaf.key" \
      --staple "$CA/ocsp_revoked.der" --posture off --expect reject:44
    # IP-literal identity: the OS never name-checks an IP (it is handed ''); the library matches it
    # against the leaf's iPAddress SAN. An IP-SAN leaf accepts; a DNS-only leaf rejects (exact 42,
    # since only the library IP post-check can fire).
    cell "delegate IP-literal vs iPAddress SAN -> accept" --trust-mode os-delegate \
      --server-cert "$CA/ipleaf_fullchain.pem" --server-key "$CA/ipleaf.key" \
      --posture soft --expect-name 127.0.0.1 --expect accept
    cell "delegate IP-literal vs DNS-only leaf -> bad_certificate" --trust-mode os-delegate \
      --server-cert "$CA/leaf_fullchain.pem" --server-key "$CA/leaf.key" \
      --posture soft --expect-name 127.0.0.1 --expect reject:42
    cell "delegate hostname mismatch -> reject" --trust-mode os-delegate \
      --server-cert "$CA/leaf_fullchain.pem" --server-key "$CA/leaf.key" \
      --staple "$CA/ocsp_good.der" --posture hard --expect-name wrong.example --expect reject
    cell "delegate wrong EKU -> reject" --trust-mode os-delegate \
      --server-cert "$CA/wrongeku_fullchain.pem" --server-key "$CA/wrongeku.key" \
      --posture soft --expect reject
    cell "delegate expired via injected clock -> reject" --trust-mode os-delegate \
      --server-cert "$CA/leaf_fullchain.pem" --server-key "$CA/leaf.key" \
      --staple "$CA/ocsp_good.der" --posture hard --now-ms "$FUTURE_MS" --expect reject
    # host roots alone while the OS trusts the chain's root: an unrelated host root must not let the
    # installed root vouch (the OS roots never vouch), in the delegate and in Anchors mode. The
    # installed-root accepts above show the same chain is otherwise trusted.
    cell "delegate host root alone (unrelated) + OS-installed root -> reject" \
      --trust-mode os-delegate --host-root "$CA/foreign_root.pem" --host-roots-alone \
      --server-cert "$CA/leaf_fullchain.pem" --server-key "$CA/leaf.key" \
      --staple "$CA/ocsp_good.der" --posture soft --expect reject:48
    cell "anchors host root alone (unrelated) + OS-installed root -> reject" \
      --trust-mode os-anchors --host-root "$CA/foreign_root.pem" --host-roots-alone \
      --server-cert "$CA/leaf_fullchain.pem" --server-key "$CA/leaf.key" \
      --staple "$CA/ocsp_good.der" --posture soft --expect reject:48
    # OS-native LIVE revocation: the OS engine fetches the loopback responder off the engine
    # thread in the async park. Good -> accept under Hard; a definitive Revoked -> reject. No
    # --now-ms: a live response is produced at wall-clock time, so a fixed verify date would push
    # it outside its validity window.
    cell "delegate live accept (2-tier, good/Hard)" --trust-mode os-delegate \
      --revocation-fetch live --server-cert "$CA/live_leaf_fullchain.pem" \
      --server-key "$CA/live_leaf.key" --posture hard --expect accept
    cell "delegate live revoked -> certificate_revoked" --trust-mode os-delegate \
      --revocation-fetch live --server-cert "$CA/live_revoked_leaf_fullchain.pem" \
      --server-key "$CA/live_revoked_leaf.key" --posture hard --expect reject:44
    # with live fetch, host roots alone still decide: the run root alone accepts, and an unrelated
    # host root rejects although the OS trusts the installed run root (the OS roots never vouch)
    cell "delegate live host root alone -> accept" --trust-mode os-delegate \
      --revocation-fetch live --host-root "$CA/root.pem" --host-roots-alone \
      --server-cert "$CA/live_leaf_fullchain.pem" --server-key "$CA/live_leaf.key" \
      --posture hard --expect accept
    cell "delegate live host root alone (unrelated) + OS-installed root -> reject" \
      --trust-mode os-delegate --revocation-fetch live --host-root "$CA/foreign_root.pem" \
      --host-roots-alone --server-cert "$CA/live_leaf_fullchain.pem" \
      --server-key "$CA/live_leaf.key" --posture hard --expect reject:48
    # the same live accept/revoked pair over TLS 1.2: the 1.2 client cert-verdict park is a separate
    # code path from the 1.3 one and is otherwise unexercised on the client side
    cell "[12] delegate live accept (2-tier, good/Hard)" --trust-mode os-delegate \
      --revocation-fetch live --tls-version 12 --server-cert "$CA/live_leaf_fullchain.pem" \
      --server-key "$CA/live_leaf.key" --posture hard --expect accept
    cell "[12] delegate live revoked -> certificate_revoked" --trust-mode os-delegate \
      --revocation-fetch live --tls-version 12 --server-cert "$CA/live_revoked_leaf_fullchain.pem" \
      --server-key "$CA/live_revoked_leaf.key" --posture hard --expect reject:44
    # an RSA-2048 revoked leaf over the same live path: the OS engine renders Revoked from the fetched
    # OCSP before any key-type-dependent check, so an RSA leaf must still surface 44 (not divert to the
    # library key-strength alert). Both engines are algorithm-agnostic on revocation, so it runs on both.
    cell "delegate live revoked RSA leaf -> certificate_revoked" --trust-mode os-delegate \
      --revocation-fetch live --server-cert "$CA/live_revoked_leaf_rsa_fullchain.pem" \
      --server-key "$CA/live_revoked_leaf_rsa.key" --posture hard --expect reject:44
    cell "[12] delegate live revoked RSA leaf -> certificate_revoked" --trust-mode os-delegate \
      --revocation-fetch live --tls-version 12 --server-cert "$CA/live_revoked_leaf_rsa_fullchain.pem" \
      --server-key "$CA/live_revoked_leaf_rsa.key" --posture hard --expect reject:44
    # revocation sourced from a CRL, not OCSP (Windows only). The leaf has no OCSP AIA and a reachable
    # CDP; crypt32 fetches the root-signed CRL and renders Revoked -> certificate_revoked(44). trustd
    # does not fetch CRLs for TLS eval (the no-AIA leaf would be Indeterminate -> Hard -> 113), so the
    # CRL source axis is Windows-exclusive. No --now-ms: a fixed future time would push past the CRL's
    # 7-day nextUpdate and force an offline refetch.
    case "$OSNAME" in
      MINGW*|MSYS*|CYGWIN*|Windows*)
        if [ "$CRL_READY" = 1 ]; then
          cell "delegate CRL revoked -> certificate_revoked" --trust-mode os-delegate \
            --revocation-fetch live --server-cert "$CA/crl_revoked_leaf_fullchain.pem" \
            --server-key "$CA/crl_revoked_leaf.key" --posture hard --expect reject:44
        else
          echo "  FAIL  delegate CRL revoked -> CRL server never started: $(cat "$CRL_LOG" 2>/dev/null)"
          FAILURES=$((FAILURES+1))
        fi ;;
      *) echo "  (skipped CRL-source cell: $OSNAME trustd does not fetch CRLs for TLS)" ;;
    esac
    # effective-Soft must not let a revocation-unknown outcome mask a real error: a Soft cache-only
    # delegate cell with a hostname mismatch still rejects
    cell "delegate soft name-mismatch -> reject" --trust-mode os-delegate \
      --server-cert "$CA/direct_fullchain.pem" --server-key "$CA/direct_leaf.key" \
      --staple "$CA/ocsp_good_direct.der" --posture soft --expect-name wrong.example \
      --expect reject
    # server-verifies-client exclusivity: the live resolver must root against the configured client CA
    # ALONE. This is meaningful only with the run root installed - a broken (machine-store) live path
    # would then find it and accept; without the install both a sound and a broken path reject (vacuous),
    # which is why this pair runs inside the bracket. A baseline good->accept with the identical inline
    # config runs first, so a reject is attributable to the resolver's foreign anchor, not the inline pass.
    cell "server live exclusivity baseline -> accept" --role server \
      --root "$CA/root.pem" --server-cert "$CA/live_leaf_fullchain.pem" \
      --server-key "$CA/live_leaf.key" --client-cert "$CA/live_client_good.pem" \
      --client-key "$CA/live_client_good.key" --client-ca "$CA/root.pem" \
      --posture hard --expect accept
    cell "server live exclusivity (foreign resolver CA) -> reject" --role server \
      --root "$CA/root.pem" --server-cert "$CA/live_leaf_fullchain.pem" \
      --server-key "$CA/live_leaf.key" --client-cert "$CA/live_client_good.pem" \
      --client-key "$CA/live_client_good.key" --client-ca "$CA/root.pem" \
      --live-client-ca "$CA/foreign_root.pem" --posture hard --expect reject
    # --- OS distrust of an intermediate (the root is installed, so the OS trusts the whole chain) ---
    # Anchors mode feeds the OS root set AND its distrust set into our own verifier; the delegate
    # hands the verdict to the OS engine. Both must refuse a path through the distrusted
    # intermediate, which the OS itself now rejects. The pre-distrust os-anchors accept proves the
    # harvest sees the installed root, so the later reject cannot be a vacuous "no anchors".
    echo "=== OS distrust of an intermediate (os-anchors and os-delegate) ==="
    cell "anchors baseline (before distrust) -> accept" --trust-mode os-anchors \
      --server-cert "$CA/distrust_leaf_fullchain.pem" --server-key "$CA/distrust_leaf.key" \
      --posture soft --expect accept
    DISTRUSTED=1
    if install_distrust; then
      echo "  (distrusted intermediate $DTHUMB)"
      cell "delegate distrusted intermediate -> reject" --trust-mode os-delegate \
        --server-cert "$CA/distrust_leaf_fullchain.pem" --server-key "$CA/distrust_leaf.key" \
        --posture soft --expect reject
      cell "anchors distrusted intermediate -> bad_certificate" --trust-mode os-anchors \
        --server-cert "$CA/distrust_leaf_fullchain.pem" --server-key "$CA/distrust_leaf.key" \
        --posture soft --expect reject:42
      cell "[12] anchors distrusted intermediate -> bad_certificate" --trust-mode os-anchors \
        --tls-version 12 --server-cert "$CA/distrust_leaf_fullchain.pem" \
        --server-key "$CA/distrust_leaf.key" --posture soft --expect reject:42
      # control: the other intermediate is not distrusted, so a path through it is still trusted
      cell "anchors undistrusted intermediate (control) -> accept" --trust-mode os-anchors \
        --server-cert "$CA/leaf_fullchain.pem" --server-key "$CA/leaf.key" \
        --staple "$CA/ocsp_good.der" --posture soft --expect accept
      # the peer also sent a twin of the distrusted intermediate (a different certificate for the same
      # key): our verifier sets the distrusted one aside and builds the path through the twin
      cell "anchors alternate path around the distrusted intermediate -> accept" \
        --trust-mode os-anchors --server-cert "$CA/distrust_alt_fullchain.pem" \
        --server-key "$CA/distrust_leaf.key" --posture soft --expect accept
      uninstall_distrust
      DISTRUSTED=0
      case "$OSNAME" in
        MINGW*|MSYS*|CYGWIN*|Windows*)
          cell "anchors after removing the distrust -> accept" --trust-mode os-anchors \
            --server-cert "$CA/distrust_leaf_fullchain.pem" --server-key "$CA/distrust_leaf.key" \
            --posture soft --expect accept ;;
        *) echo "  (skipped post-removal cell: a macOS trust setting needs the SIP-restricted right to remove)" ;;
      esac
    else
      echo "  FAIL  could not install the distrusted intermediate"
      FAILURES=$((FAILURES+1))
    fi
    uninstall_root
    INSTALLED=0
    # bracket, after uninstall: cleanup verified - the same chain rejects again
    cell "delegate post-uninstall our root -> reject" --trust-mode os-delegate \
      --server-cert "$CA/leaf_fullchain.pem" --server-key "$CA/leaf.key" \
      --staple "$CA/ocsp_good.der" --posture soft --expect reject
  elif ci_store_mutation_allowed; then
    echo "  FAIL  could not install the test root"
    FAILURES=$((FAILURES+1))
  else
    echo "  SKIPPED: store mutation not allowed (set TLSLIB_TRUST_ALLOW_STORE_MUTATION=true to force); ran the reject path only"
  fi

  # server-verifies-client with an UNREACHABLE responder: the client leaf's AIA is the dead port, so
  # the live check is genuinely indeterminate. Soft accepts (proves the outcome is Indeterminate, not
  # a definitive reject); Hard rejects bad_certificate_status_response(113). Needs no install (exclusive
  # in-memory anchors); run LAST so no earlier cell can have warmed a cache for this URL (the port is
  # dead anyway, and each cell is a fresh process).
  echo "=== OS trust delegate: server verifies client, responder unreachable (live) ==="
  cell "server live unreachable client (Soft) -> accept" --role server \
    --root "$CA/root.pem" --server-cert "$CA/live_leaf_fullchain.pem" \
    --server-key "$CA/live_leaf.key" --client-cert "$CA/live_client_down.pem" \
    --client-key "$CA/live_client_down.key" --client-ca "$CA/root.pem" \
    --posture soft --expect accept
  cell "server live unreachable client (Hard) -> bad_certificate_status_response" --role server \
    --root "$CA/root.pem" --server-cert "$CA/live_leaf_fullchain.pem" \
    --server-key "$CA/live_leaf.key" --client-cert "$CA/live_client_down.pem" \
    --client-key "$CA/live_client_down.key" --client-ca "$CA/root.pem" \
    --posture hard --expect reject:113
else
  echo "=== OS trust delegate: SKIPPED (no OS delegate on $OSNAME) ==="
fi

resolve_ipv4() { # <host>: the shim dials a dotted IPv4 only
  case "$OSNAME" in
    Darwin)
      local ip=""
      if [ "${#PYRUN[@]}" -gt 0 ]; then
        ip="$("${PYRUN[@]}" -c'import socket,sys; print(socket.getaddrinfo(sys.argv[1], 443, socket.AF_INET)[0][4][0])' "$1" 2>/dev/null || true)"
      fi
      if [ -z "$ip" ]; then
        ip="$(dscacheutil -q host -a name "$1" 2>/dev/null | sed -n 's/^ip_address: *//p' | head -n 1 || true)"
      fi
      echo "$ip" ;;
    *)
      powershell -NoProfile -NonInteractive -Command "[System.Net.Dns]::GetHostAddresses('$1') | Where-Object { \$_.AddressFamily -eq 'InterNetwork' } | Select-Object -First 1 -ExpandProperty IPAddressToString" 2>/dev/null | tr -d '\r' || true ;;
  esac
}

probe_cell() { # <mode> <ip> <host>: prints ACCEPT | REFUSE:<alert> | NET
  local out rc=0
  out="$(ci_run_bounded 60 "$SHIM" --trust-mode "$1" --connect "$2:443" --expect-name "$3" \
    --posture soft --expect accept 2>&1)" || rc=$?
  if [ "$rc" = 0 ]; then
    echo ACCEPT
  elif [[ "$out" =~ got\ status\ 2\ alert\ ([0-9]+) ]]; then
    echo "REFUSE:${BASH_REMATCH[1]}"
  else
    echo NET
  fi
}

probe_setup() {
  PROBE_HOSTS=(letsencrypt.org digicert.com globalsign.com sectigo.com amazon.com google.com
               microsoft.com godaddy.com ssl.com entrust.com)
}

probe_run_modes() { # resolve every host, then anchors for all of them before any delegate run
  PROBE_IPS=(); PROBE_A=(); PROBE_D=()
  for I in "${!PROBE_HOSTS[@]}"; do
    PROBE_IPS[$I]="$(resolve_ipv4 "${PROBE_HOSTS[$I]}")"
    PROBE_A[$I]=NET; PROBE_D[$I]=NET
  done
  # anchors first: a delegate run can install a root a later anchors run would see
  for I in "${!PROBE_HOSTS[@]}"; do
    if [ -n "${PROBE_IPS[$I]}" ]; then
      PROBE_A[$I]="$(probe_cell os-anchors "${PROBE_IPS[$I]}" "${PROBE_HOSTS[$I]}")"
    fi
  done
  for I in "${!PROBE_HOSTS[@]}"; do
    if [ -n "${PROBE_IPS[$I]}" ]; then
      PROBE_D[$I]="$(probe_cell os-delegate "${PROBE_IPS[$I]}" "${PROBE_HOSTS[$I]}")"
    fi
  done
}

probe_classify() { # <anchors> <delegate>: net | delegate-only | both-ok | anchors-only | both-refused
  if [ "$1" = NET ] || [ "$2" = NET ]; then echo net
  elif [ "$2" = ACCEPT ] && [ "$1" != ACCEPT ]; then echo delegate-only
  elif [ "$2" = ACCEPT ]; then echo both-ok
  elif [ "$1" = ACCEPT ]; then echo anchors-only
  else echo both-refused
  fi
}

probe_table() { # print the table, fill the N_* counts
  N_HEALED=0; N_BOTH_OK=0; N_BOTH_REFUSED=0; N_REGRESSION=0; N_NET=0
  printf '  %-18s %-12s %s\n' host anchors delegate
  for I in "${!PROBE_HOSTS[@]}"; do
    A="${PROBE_A[$I]}"; D="${PROBE_D[$I]}"
    case "$(probe_classify "$A" "$D")" in
      net) N_NET=$((N_NET+1)) ;;
      delegate-only) N_HEALED=$((N_HEALED+1)) ;;
      both-ok) N_BOTH_OK=$((N_BOTH_OK+1)) ;;
      anchors-only) N_REGRESSION=$((N_REGRESSION+1)) ;;
      *) N_BOTH_REFUSED=$((N_BOTH_REFUSED+1)) ;;
    esac
    printf '  %-18s %-12s %s\n' "${PROBE_HOSTS[$I]}" "$A" "$D"
  done
}

# Informational, never fails the leg: with the one root that issues a public intermediate removed, does
# crypt32 re-install it under our inline/live chain flags (mirroring TWindowsTrustApi.ChainFlags, plus
# DISABLE_AIA) as it does under a control with no cache-only flag? Each run starts from the same stripped
# state; the removed certificates are restored right after the runs and again by the EXIT trap.
AUTOROOT_INLINE=48002004  # CACHE_ONLY_URL_RETRIEVAL | REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT | REVOCATION_ACCUMULATIVE_TIMEOUT | DISABLE_AIA
AUTOROOT_LIVE=48002000    # REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT | REVOCATION_ACCUMULATIVE_TIMEOUT | DISABLE_AIA, extended CERT_CHAIN_PARA
AUTOROOT_CONTROL=00002000 # DISABLE_AIA only
AUTOROOT_CAPI=0
AUTOROOT_POLICY=0
AUTOROOT_SVC=0

autoroot_svc_ensure() { # idempotent: a CryptSvc restart that timed out must not leave the service stopped
  [ "$AUTOROOT_SVC" = 1 ] || return 0
  AUTOROOT_SVC=0
  autoroot_ps svcensure | tail -n 1 | sed 's/^/  /'
}

autoroot_capi_off() { # idempotent: put the CAPI2 operational log back to its prior state
  [ "$AUTOROOT_CAPI" = 1 ] || return 0
  AUTOROOT_CAPI=0
  autoroot_ps capioff >/dev/null || true
}

autoroot_run() { # <flags> <plain|ex> <inter|leaf> [keep]: strip, build once in a fresh process, print the run line
  local keep=()
  if [ "${4:-}" = keep ]; then keep=(-KeepCache); fi
  autoroot_ps strip ${keep[@]+"${keep[@]}"} >/dev/null || true
  autoroot_ps build -Flags "$1" -Para "$2" -Target "$3" | tail -n 1
}

autoroot_policy_restore() { # idempotent: put DisableRootAutoUpdate back as it was
  [ "$AUTOROOT_POLICY" = 1 ] || return 0
  AUTOROOT_POLICY=0
  autoroot_ps policyrestore | tail -n 1 | sed 's/^/  /'
}

autoroot_installed() { # a run line shows R put into a root store by auto-update (an AIA fetch or a \CA store does not count)
  local where
  case "$1" in ''|*aia=True*) return 1 ;; esac
  where="${1#*reappeared=}"; where="${where%% *}"
  case ",$where," in
    *,LocalMachine\\AuthRoot,*|*,LocalMachine\\Root,*|*,CurrentUser\\AuthRoot,*|*,CurrentUser\\Root,*) return 0 ;;
  esac
  return 1
}

autoroot_probe() {
  local ctl thumb strip strip_out run_inline run_live c1 c2 c3 c5 c6 leaf_inline leaf_live
  mkdir -p "$TMP/autoroot"
  ctl="$(autoroot_ps ctl | tr '\n' ' ')"
  case "$ctl" in
    *NOTLISTED*) echo "AUTOROOT PRECONDITION FAILED: R not in authroot.stl"; return 0 ;;
    *LISTED*) ;;
    *) echo "AUTOROOT PRECONDITION FAILED: R not in authroot.stl"; echo "  (CTL check: $ctl)"; return 0 ;;
  esac
  thumb="${ctl#*sha1=}"; thumb="${thumb%% *}"
  autoroot_ps diag -Thumb "$thumb" || true
  echo "  $(autoroot_ps leaf | tail -n 1)"
  AUTOROOT_ARMED=1
  strip_out="$(autoroot_ps strip)"
  strip="$(printf '%s\n' "$strip_out" | tail -n 1)"
  printf '%s\n' "$strip_out" | grep '^  ' || true
  if [ "$strip" != "remaining=0" ]; then
    echo "AUTOROOT PRECONDITION FAILED: issuer still present after removal"
    autoroot_restore
    return 0
  fi
  AUTOROOT_POLICY=1
  autoroot_ps policyclear | tail -n 1
  AUTOROOT_CAPI=1
  echo "  $(autoroot_ps capion | tail -n 1)"
  run_inline="$(autoroot_run $AUTOROOT_INLINE plain inter)"
  run_live="$(autoroot_run $AUTOROOT_LIVE ex inter)"
  c1="$(autoroot_run $AUTOROOT_CONTROL plain inter)"
  c2="$(autoroot_run 00000000 plain inter)"
  c3="$(autoroot_run 00000000 plain leaf)"
  c5="$(autoroot_run $AUTOROOT_CONTROL plain inter keep)"
  echo "  inline:  $run_inline"
  echo "  live:    $run_live"
  echo "  C1 control (DISABLE_AIA):            $c1"
  echo "  C2 control (flags 0, AIA allowed):   $c2"
  echo "  C3 control (real leaf, chain+policy): $c3"
  echo "  C5 control (C1, URL cache kept):     $c5"
  c6=''
  if ! autoroot_installed "$c1" && ! autoroot_installed "$c3" && ! autoroot_installed "$c5"; then
    AUTOROOT_SVC=1
    echo "  $(autoroot_ps svcrestart | tail -n 1)"
    autoroot_svc_ensure
    c6="$(autoroot_run $AUTOROOT_CONTROL plain inter)"
    echo "  C6 control (C1 after CryptSvc restart): $c6"
  fi
  case "$c2" in *aia=True*) echo "  note: C2 issuer came from AIA, not counted as an auto-update install" ;; esac
  if autoroot_installed "$c3"; then
    leaf_inline="$(autoroot_run $AUTOROOT_INLINE plain leaf)"
    leaf_live="$(autoroot_run $AUTOROOT_LIVE ex leaf)"
    echo "  leaf inline: $leaf_inline"
    echo "  leaf live:   $leaf_live"
  fi
  autoroot_policy_restore
  autoroot_ps capidump || true
  autoroot_capi_off
  if autoroot_installed "$c1" || autoroot_installed "$c3" || autoroot_installed "$c5" || autoroot_installed "$c6"; then
    local i l
    if autoroot_installed "$run_inline"; then i=installs; else i=does-not-fire; fi
    if autoroot_installed "$run_live"; then l=installs; else l=does-not-fire; fi
    echo "AUTOROOT RESULT inline=$i live=$l control=installs"
    if autoroot_installed "$c3"; then
      if autoroot_installed "$leaf_inline"; then i=installs; else i=does-not-fire; fi
      if autoroot_installed "$leaf_live"; then l=installs; else l=does-not-fire; fi
      echo "AUTOROOT RESULT-LEAF inline=$i live=$l"
    fi
  else
    echo "AUTOROOT PRECONDITION FAILED: no unrestricted build installed R (see the diagnostics above)"
  fi
  autoroot_restore
}

echo "=== Windows root auto-update (AUTOROOT, informational) ==="
case "$OSNAME" in
  MINGW*|MSYS*|CYGWIN*|Windows*)
    if [ "${MAKE_RUN_AUTOROOT:-false}" != "true" ]; then
      echo "  SKIPPED: set MAKE_RUN_AUTOROOT=true to run"
    elif ! ci_store_mutation_allowed; then
      echo "  SKIPPED: store mutation not allowed (the probe removes a root from the machine store)"
    elif [ "${RUNNER_ENVIRONMENT:-}" != "github-hosted" ]; then
      echo "  SKIPPED: not a github-hosted runner (RUNNER_ENVIRONMENT=${RUNNER_ENVIRONMENT:-unset})"
    else
      autoroot_probe || true
    fi ;;
  *) echo "  SKIPPED: Windows only" ;;
esac

# Informational, never fails the leg: does the Anchors harvest ever disagree with the Apple SecTrust
# engine on real public hosts (the default is the delegate where the OS has an engine)?
echo "=== macOS trust mode comparison (informational) ==="
case "$OSNAME" in
  Darwin)
    if ! ci_store_mutation_allowed; then
      echo "  SKIPPED: store mutation not allowed (set TLSLIB_TRUST_ALLOW_STORE_MUTATION=true to force)"
    else
      probe_setup
      probe_run_modes
      probe_table
      for I in "${!PROBE_HOSTS[@]}"; do
        A="${PROBE_A[$I]}"; D="${PROBE_D[$I]}"
        case "$(probe_classify "$A" "$D")" in
          anchors-only)
            echo "  note: ${PROBE_HOSTS[$I]}: delegate refused (alert ${D#REFUSE:}), anchors accepted:" \
              "possible Apple policy difference (CT / validity cap), not necessarily a bug" ;;
          delegate-only)
            echo "  note: ${PROBE_HOSTS[$I]}: anchors refused (alert ${A#REFUSE:}), delegate accepted:" \
              "harvest may be missing a root the OS trusts" ;;
        esac
      done
      echo "  summary: both-accepted=$N_BOTH_OK both-refused=$N_BOTH_REFUSED delegate-only=$N_HEALED" \
        "anchors-only=$N_REGRESSION network=$N_NET"
      N_REACHED=$(( ${#PROBE_HOSTS[@]} - N_NET ))
      if [ "$N_REACHED" -eq 0 ]; then
        echo "  INCONCLUSIVE: no host was reachable (INFO, not a failure)"
      elif [ $((N_HEALED + N_REGRESSION)) -eq 0 ]; then
        echo "  modes agree on all $N_REACHED reachable hosts"
      else
        echo "  modes disagree on $((N_HEALED + N_REGRESSION)) host(s)"
      fi
    fi ;;
  *) echo "  SKIPPED: macOS only" ;;
esac

echo "=== native-trust cells: $FAILURES failure(s) ==="
[ "$FAILURES" -eq 0 ]
