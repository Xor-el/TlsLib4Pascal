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
#
# The server-cert delegate reject cells assert only that the handshake aborts (a fatal alert, not a
# hang or EOF); tightening them to the exact OsStatusToAlert code is a follow-up once a CI run shows
# the real mapping per OS.
#
#   * server verifies client (mTLS live) - our SERVER verifies the peer CLIENT certificate live
#                 through the OS delegate (an in-process client presenter offers the cert). It roots
#                 against the in-memory exclusive client-CA anchors, never the machine store, so the
#                 good/revoked/unreachable cells need NO install and run locally too; only the
#                 exclusivity cell (foreign resolver CA) runs inside the install bracket, where it can
#                 discriminate. Its revoked(44)/indeterminate(113) alerts come from our resolver, not
#                 the OS map, so they are asserted exactly on both platforms.
set -euo pipefail

SHIM="${1:?usage: run-trust.sh <TrustDelegateInterop binary>}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

TMP="$(mktemp -d)"
CA="$TMP/ca"
RUNID="tlslib-trust-$(date +%s)-$$"
INSTALLED=0
FAILURES=0
OSNAME="$(uname -s)"
# a per-run loopback port + URL for the live OCSP responder (the live cells fetch it)
OCSP_PORT=$(( 20000 + (RANDOM % 20000) ))
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

THUMB=""  # set after the CA exists

cleanup() {
  if [ -n "$OCSP_PID" ]; then kill "$OCSP_PID" >/dev/null 2>&1 || true; fi
  if [ "$INSTALLED" = 1 ]; then uninstall_root || true; fi
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

trap cleanup EXIT

OPENSSL="${OPENSSL:-openssl}"
# on the macOS runner /usr/bin/openssl is LibreSSL; prefer Homebrew openssl@3 (as the openssl matrix
# does) so the responder signs with SHA-256 and matches the rest of the interop
if [ "$OSNAME" = "Darwin" ] && command -v brew >/dev/null 2>&1; then
  BREW_SSL="$(brew --prefix openssl@3 2>/dev/null || true)"
  [ -n "$BREW_SSL" ] && [ -x "$BREW_SSL/bin/openssl" ] && OPENSSL="$BREW_SSL/bin/openssl"
fi
OPENSSL="$OPENSSL" bash "$HERE/gen-trust-ca.sh" "$CA" "$RUNID" "$OCSP_URL" "$DEAD_URL"
THUMB="$("$OPENSSL" x509 -in "$CA/root.pem" -noout -fingerprint -sha1 | sed 's/.*=//; s/://g')"
# a loopback OCSP responder for the live cells: serves the live index (accept leaves Valid, revoked
# leaves Revoked) signed by the root-delegated OCSPSigning responder both crypt32 and trustd accept.
# It runs for the whole bracket and is killed by the EXIT trap. The server-verifies-client live cells
# below use it WITHOUT a store install, so it is load-bearing - wait for it to accept connections.
"$OPENSSL" ocsp -index "$CA/index_live.txt" -CA "$CA/root.pem" \
  -rsigner "$CA/ocsp_signer.pem" -rkey "$CA/ocsp_signer.key" \
  -port "$OCSP_PORT" -rmd sha256 >/dev/null 2>&1 &
OCSP_PID=$!
# readiness probe: a REAL OCSP query (live_leaf is serial 4001, Valid in the index). A raw TCP
# connect would be read by the single-threaded responder as a malformed request and disturb it; a
# valid query it answers and loops. The new server cells run before the cells that used to warm it up.
for _ in $(seq 1 50); do
  if "$OPENSSL" ocsp -CAfile "$CA/root.pem" -issuer "$CA/root.pem" \
    -cert "$CA/live_leaf.pem" -url "$OCSP_URL" >/dev/null 2>&1; then break; fi
  sleep 0.2
done
# a verify time past the 30-day leaf notAfter, to prove the injected clock reaches validation
FUTURE_MS=$(( ($(date +%s) + 60*86400) * 1000 ))

cell() { # <label> <shim-args...>
  local label="$1"; shift
  if "$SHIM" "$@" > "$TMP/o" 2>&1; then
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

case "$OSNAME" in
  MINGW*|MSYS*|CYGWIN*|Windows*|Darwin) HAS_DELEGATE=1 ;;
  *) HAS_DELEGATE=0 ;;
esac

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

  if install_root; then
    INSTALLED=1
    echo "  (installed test root $THUMB)"
    # 2-tier chain (root -> leaf, no intermediate) under Hard: the only non-anchor cert is the leaf,
    # which carries a good stapled OCSP, so every element trustd/crypt32 revocation-checks has a
    # positive answer (the anchor is exempt). A 3-tier chain would leave the intermediate with no
    # staple -> indeterminate -> Hard rejects on macOS; the 3-tier good/Hard path is asserted by the
    # portable cells instead.
    cell "delegate accept (2-tier, good/Hard)" --trust-mode os-delegate \
      --server-cert "$CA/direct_fullchain.pem" --server-key "$CA/direct_leaf.key" \
      --staple "$CA/ocsp_good_direct.der" --posture hard --expect accept
    cell "delegate revoked staple -> reject" --trust-mode os-delegate \
      --server-cert "$CA/leaf_fullchain.pem" --server-key "$CA/leaf.key" \
      --staple "$CA/ocsp_revoked.der" --posture soft --expect reject
    cell "delegate hostname mismatch -> reject" --trust-mode os-delegate \
      --server-cert "$CA/leaf_fullchain.pem" --server-key "$CA/leaf.key" \
      --staple "$CA/ocsp_good.der" --posture hard --expect-name wrong.example --expect reject
    cell "delegate wrong EKU -> reject" --trust-mode os-delegate \
      --server-cert "$CA/wrongeku_fullchain.pem" --server-key "$CA/wrongeku.key" \
      --posture soft --expect reject
    cell "delegate expired via injected clock -> reject" --trust-mode os-delegate \
      --server-cert "$CA/leaf_fullchain.pem" --server-key "$CA/leaf.key" \
      --staple "$CA/ocsp_good.der" --posture hard --now-ms "$FUTURE_MS" --expect reject
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
    uninstall_root
    INSTALLED=0
    # bracket, after uninstall: cleanup verified - the same chain rejects again
    cell "delegate post-uninstall our root -> reject" --trust-mode os-delegate \
      --server-cert "$CA/leaf_fullchain.pem" --server-key "$CA/leaf.key" \
      --staple "$CA/ocsp_good.der" --posture soft --expect reject
  else
    echo "  SKIPPED: could not install the test root (need privilege); ran the reject path only"
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

echo "=== native-trust cells: $FAILURES failure(s) ==="
[ "$FAILURES" -eq 0 ]
