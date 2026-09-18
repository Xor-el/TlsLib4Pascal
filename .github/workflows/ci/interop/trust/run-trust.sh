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
# The delegate reject cells assert only that the handshake aborts (a fatal alert, not a hang or
# EOF); tightening them to the exact OsStatusToAlert code (e.g. certificate_revoked) is a
# follow-up once a CI run shows the real mapping per OS.
set -euo pipefail

SHIM="${1:?usage: run-trust.sh <TrustDelegateInterop binary>}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

TMP="$(mktemp -d)"
CA="$TMP/ca"
RUNID="tlslib-trust-$(date +%s)-$$"
INSTALLED=0
FAILURES=0
OSNAME="$(uname -s)"

THUMB=""  # set after the CA exists

# Hard-bound a command so a stray macOS auth prompt can never wedge the CI job (macOS has no
# reliable GNU timeout). Returns 124 on timeout, tearing down the whole tree - the sudo child
# (root-owned) and any pending SecurityAgent dialog. macOS-only kills are no-ops elsewhere.
bounded() { # <secs> <cmd...>
  local secs="$1"; shift
  "$@" &
  local pid=$!
  ( sleep "$secs"; kill -0 "$pid" 2>/dev/null || exit 0
    echo "  TIMEOUT(${secs}s): $*" >&2
    sudo pkill -x SecurityAgent 2>/dev/null || true  # cancel the auth dialog -> caller returns
    sudo pkill -9 -P "$pid" 2>/dev/null || true       # the security process under sudo
    sudo kill -9 "$pid" 2>/dev/null || true
  ) &
  local wd=$!
  local rc=0
  wait "$pid" 2>/dev/null || rc=$?
  kill "$wd" 2>/dev/null || true
  wait "$wd" 2>/dev/null || true
  if [ "$rc" -ge 128 ]; then rc=124; fi
  return "$rc"
}

# macOS: SecTrustSettings and System-keychain writes can demand a GUI authorization even as root on
# Big Sur+, which hangs a headless runner. Pre-authorize the rights they request (add AND remove hit
# them), and verify the write took - a silent failure is what makes add work but remove still prompt.
darwin_preauth() {
  local r
  for r in com.apple.trust-settings.admin system.keychain.modify; do
    bounded 20 sudo security authorizationdb write "$r" allow >/dev/null 2>&1 || true
  done
  sudo security authorizationdb read com.apple.trust-settings.admin 2>/dev/null \
    | grep -q '<string>allow</string>' || echo "  WARN: trust-settings.admin rule is not 'allow'"
}
darwin_unauth() {
  local r
  for r in com.apple.trust-settings.admin system.keychain.modify; do
    bounded 20 sudo security authorizationdb remove "$r" >/dev/null 2>&1 || true
  done
}

cleanup() {
  if [ "$INSTALLED" = 1 ]; then uninstall_root || true; fi
  rm -rf "$TMP"
}

install_root() { # into the machine store, non-interactively
  case "$OSNAME" in
    MINGW*|MSYS*|CYGWIN*|Windows*)
      certutil -addstore -f Root "$(cygpath -w "$CA/root.pem")" >/dev/null 2>&1 ;;
    Darwin)
      darwin_preauth
      bounded 60 sudo security add-trusted-cert -d -r trustRoot \
        -k /Library/Keychains/System.keychain "$CA/root.pem" >/dev/null 2>&1 ;;
    *) return 1 ;;
  esac
}
uninstall_root() { # un-anchor the root; every step bounded so a stray prompt can't wedge the job
  case "$OSNAME" in
    MINGW*|MSYS*|CYGWIN*|Windows*)
      certutil -delstore Root "$THUMB" >/dev/null 2>&1 || true ;;
    Darwin)
      # remove-trusted-cert -d is unreliable on the runner (it needs the trust-settings.admin right,
      # whose authorizationdb write does not stick under SIP - it hangs or no-ops). So deleting the
      # keychain ITEM is the primary un-anchor: the server never sends the root, so with no keychain
      # holding it trustd cannot build the path and rejects. As root the System keychain is unlocked,
      # so this is non-interactive; bounded guards a stray prompt regardless.
      bounded 60 sudo security remove-trusted-cert -d "$CA/root.pem" >/dev/null 2>&1 || true
      bounded 60 sudo security delete-certificate -Z "$THUMB" \
        /Library/Keychains/System.keychain >/dev/null 2>&1 || true
      # last resort if a trust setting still lists our run id: root owns Admin.plist
      if sudo security dump-trust-settings -d 2>/dev/null | grep -q "$RUNID"; then
        sudo /usr/libexec/PlistBuddy -c "Delete :trustList:$THUMB" \
          "/Library/Security/Trust Settings/Admin.plist" >/dev/null 2>&1 || true
        sudo killall trustd >/dev/null 2>&1 || true
      fi
      if sudo security find-certificate -c "TlsLib Test Root $RUNID" \
        /Library/Keychains/System.keychain >/dev/null 2>&1; then
        echo "  uninstall: WARN root cert still in the System keychain"
      else
        echo "  uninstall: root cert removed"
      fi
      darwin_unauth ;;
  esac
}

# trustd's own verdict, at its own clock, against the SAME installed root: verify-cert OK while our
# accept cell FAILs isolates the bug to our process; both failing points at certs/store/runner clock
macos_diag() {
  echo "  diag: $(date -u +%FT%TZ) macOS $(sw_vers -productVersion 2>/dev/null) $(uname -m)"
  local f
  for f in root issuer leaf; do
    echo "  diag: $f $("$OPENSSL" x509 -in "$CA/$f.pem" -noout -dates 2>&1 | tr '\n' ' ')"
  done
  bounded 30 sudo security verify-cert -c "$CA/leaf.pem" -c "$CA/issuer.pem" -p ssl -s localhost -L \
    2>&1 | sed 's/^/  diag: verify-cert /' || true
}

trap cleanup EXIT

OPENSSL="${OPENSSL:-openssl}"
# on the macOS runner /usr/bin/openssl is LibreSSL; prefer Homebrew openssl@3 (as the openssl matrix
# does) so the responder signs with SHA-256 and matches the rest of the interop
if [ "$OSNAME" = "Darwin" ] && command -v brew >/dev/null 2>&1; then
  BREW_SSL="$(brew --prefix openssl@3 2>/dev/null || true)"
  [ -n "$BREW_SSL" ] && [ -x "$BREW_SSL/bin/openssl" ] && OPENSSL="$BREW_SSL/bin/openssl"
fi
OPENSSL="$OPENSSL" bash "$HERE/gen-trust-ca.sh" "$CA" "$RUNID"
THUMB="$("$OPENSSL" x509 -in "$CA/root.pem" -noout -fingerprint -sha1 | sed 's/.*=//; s/://g')"
# a verify time past the 30-day leaf notAfter, to prove the injected clock reaches validation
FUTURE_MS=$(( ($(date +%s) + 60*86400) * 1000 ))

cell() { # <label> <shim-args...>
  local label="$1"; shift
  # bounded: a wedged delegate handshake is the other way a job gets wasted
  if bounded 60 "$SHIM" "$@" > "$TMP/o" 2>&1; then
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

  if install_root; then
    INSTALLED=1
    echo "  (installed test root $THUMB)"
    if [ "$OSNAME" = "Darwin" ]; then macos_diag; fi
    # posture Soft here: this cell proves the OS store trusts a chain to the installed root; it
    # does not assert the delegate honours our issuer-signed good staple under Hard (crypt32 does,
    # macOS trustd treats it as indeterminate). The portable cells cover good/Hard on every OS.
    cell "delegate accept (root installed, good/Soft)" --trust-mode os-delegate \
      --server-cert "$CA/leaf_fullchain.pem" --server-key "$CA/leaf.key" \
      --staple "$CA/ocsp_good.der" --posture soft --expect accept
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
    uninstall_root
    INSTALLED=0
    # bracket, after uninstall: cleanup verified - the same chain rejects again
    cell "delegate post-uninstall our root -> reject" --trust-mode os-delegate \
      --server-cert "$CA/leaf_fullchain.pem" --server-key "$CA/leaf.key" \
      --staple "$CA/ocsp_good.der" --posture soft --expect reject
  else
    echo "  SKIPPED: could not install the test root (need privilege); ran the reject path only"
  fi
else
  echo "=== OS trust delegate: SKIPPED (no OS delegate on $OSNAME) ==="
fi

echo "=== native-trust cells: $FAILURES failure(s) ==="
[ "$FAILURES" -eq 0 ]
