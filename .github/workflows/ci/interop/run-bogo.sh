#!/usr/bin/env bash
# Hard-gate BoGo run: the WHOLE suite, driven from bogo-shim-config.json (not an
# allowlist). Every test must PASS or match a disable glob, else this leg fails - a FAIL,
# an in-scope UNIMPLEMENTED, a now-passing policy disable (stale), or a policy glob that
# matches nothing (dead). The coverage boundary is printed and archived every run.
# Peer pinned at BOGO_REF, -loose-errors, no -allow-unimplemented on the gate pass. Runs at
# -num-workers=BOGO_WORKERS: this local default is 1 for deterministic triage; CI passes 4
# for speed (a truncated/crashed run is still caught precisely by BoGo's interrupted flag,
# so parallelism never turns an incomplete run into a spurious PASS).
#
# REVIEW RULE: a broad [out-of-scope]/[deferred] disable glob can silently shadow an in-scope
# (modern-TLS) test that would FAIL - and a disabled test never runs, so the gate cannot see it.
# Reviewing every new/broadened such glob (version-anchor it) is the only guard; see the
# _comment in bogo-shim-config.json.
#
#   BOGO_SRC        BoringSSL checkout (has ssl/test/runner)        [required]
#   BOGO_REF        commit to pin the peer at                       [optional]
#   BOGO_TESTS      run only these (glob;glob) and report, no gate  [optional]
#   BOGO_LOG_DIR    archive gate.json / audit.json / the boundary   [optional]
# A partial/crashed run is caught precisely by BoGo's own top-level "interrupted" flag in the
# gate JSON (and a missing/corrupt file), which the classifier checks - no test-count guessing.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../../../.." && pwd)"
CONFIG="$HERE/bogo-shim-config.json"
CLASSIFY="$HERE/bogo-classify.py"
BIN_DIR="$REPO_ROOT/TlsLib.Interop/FreePascal.Interop/bin"
WORKERS="${BOGO_WORKERS:-1}"
# the peer commit the ledger was reconciled against; override BOGO_REF to move it
BOGO_REF="${BOGO_REF:-ae49d2681a56ca7b8609f6039a770fda2a8eb550}"
WORK="$(mktemp -d)"
GATE_JSON="$WORK/gate.json"
AUDIT_JSON="$WORK/audit.json"

command -v go >/dev/null 2>&1 || { echo "ERROR: Go is required to run BoGo"; exit 2; }
# python3 on POSIX, python (or the py launcher) on Windows - probe by actually running each
# candidate so the Microsoft Store's non-functional python3 alias is skipped, not selected
PYTHON=""
for p in python3 python py; do
  if command -v "$p" >/dev/null 2>&1 && "$p" -c "import sys" >/dev/null 2>&1; then
    PYTHON="$p"
    break
  fi
done
[ -n "$PYTHON" ] || { echo "ERROR: a working python3 (or python) is required to classify results"; exit 2; }
[ -n "${BOGO_SRC:-}" ] || { echo "ERROR: set BOGO_SRC to a BoringSSL checkout"; exit 2; }
[ -d "$BOGO_SRC/ssl/test/runner" ] || { echo "ERROR: $BOGO_SRC/ssl/test/runner missing"; exit 2; }

# use the prebuilt shim; interop-build.sh compiles it against the CI packages
SHIM=""
for c in "$BIN_DIR/BoGoShim" "$BIN_DIR/BoGoShim.exe"; do
  [ -x "$c" ] && SHIM="$c" && break
done
[ -n "$SHIM" ] || { echo "ERROR: BoGoShim binary not found under $BIN_DIR (run interop-build.sh first)"; exit 2; }
echo "shim: $SHIM"

# pin the peer if a ref was given
if [ -n "${BOGO_REF:-}" ]; then
  echo "pinning BoGo peer to $BOGO_REF"
  git -C "$BOGO_SRC" fetch --depth 1 origin "$BOGO_REF" 2>/dev/null || true
  git -C "$BOGO_SRC" checkout -q "$BOGO_REF"
fi
echo "BoGo peer at: $(git -C "$BOGO_SRC" rev-parse HEAD)"

RUNNER_DIR="$BOGO_SRC/ssl/test/runner"

# --- exploratory scoped override: run only BOGO_TESTS and report (NOT the gate) --------
if [ -n "${BOGO_TESTS:-}" ]; then
  echo "=== exploratory scoped run (BOGO_TESTS set; not the hard gate) ==="
  ( cd "$RUNNER_DIR" && go test -timeout 60m \
      -shim-path="$SHIM" -shim-config="$CONFIG" \
      -loose-errors -num-workers="$WORKERS" -test "$BOGO_TESTS" )
  exit $?
fi

# the policy-difference globs are FORCE-RUN each gate to catch a stale disable (a peer bump can
# move BoringSSL's default so the difference disappears). [deferred]/[out-of-scope] are NOT
# force-run: an unsupported scheme passes a negative test spuriously, which would be a false stale.
AUDIT_GLOBS="$("$PYTHON" "$CLASSIFY" audit-globs "$CONFIG")"

# --- pass 1: the gate - the WHOLE suite, DisabledTests skipped by the runner ----------
# no -allow-unimplemented: an in-scope test the shim cannot drive is an UNEXPECTED gap.
# We do NOT swallow the exit with `|| true`: go test exits nonzero whenever any test is
# unexpected (normal while the boundary is nonzero), so we capture it and let the classifier
# render the verdict - a truncated/crashed run is caught by BoGo's "interrupted" flag (and the
# missing-file check), not silently reported as PASS.
echo "=== gate: full BoGo suite minus the disable ledger ==="
set +e
( cd "$RUNNER_DIR" && go test -timeout 60m \
    -shim-path="$SHIM" -shim-config="$CONFIG" \
    -loose-errors -num-workers="$WORKERS" \
    -json-output="$GATE_JSON" )
GATE_RC=$?
set -e
echo "gate go test exit: $GATE_RC (nonzero is expected while the boundary is nonzero; the"
echo "classifier decides the verdict, and fails on an interrupted/incomplete run)"
[ -f "$GATE_JSON" ] || { echo "ERROR: gate pass produced no JSON ($GATE_JSON)"; exit 2; }

# --- pass 2: the stale-disable audit - FORCE-RUN the policy-difference disables -------
# -include-disabled runs them despite the config; -allow-unimplemented keeps an
# unimplemented one a clean SKIP. Any that now PASS = stale; any that fail-open (the shim
# accepts what it must reject) is caught from the recorded error string.
if [ -n "$AUDIT_GLOBS" ]; then
  echo "=== audit: re-confirming the policy + deferred disables still hold ==="
  ( cd "$RUNNER_DIR" && go test -timeout 60m \
      -shim-path="$SHIM" -shim-config="$CONFIG" \
      -loose-errors -num-workers="$WORKERS" \
      -include-disabled -allow-unimplemented \
      -test "$AUDIT_GLOBS" -json-output="$AUDIT_JSON" ) || true
fi
[ -f "$AUDIT_JSON" ] || echo '{"tests":{}}' > "$AUDIT_JSON"

# --- classify + coverage boundary (no silent caps) + verdict --------------------------
BOUNDARY_LOG="$WORK/coverage-boundary.txt"
set +e
"$PYTHON" "$CLASSIFY" gate "$CONFIG" "$GATE_JSON" "$AUDIT_JSON" \
  | tee "$BOUNDARY_LOG"
VERDICT=${PIPESTATUS[0]}
set -e

# archive the boundary + raw JSON for auditability over time
if [ -n "${BOGO_LOG_DIR:-}" ]; then
  mkdir -p "$BOGO_LOG_DIR"
  cp -f "$GATE_JSON" "$AUDIT_JSON" "$BOUNDARY_LOG" "$BOGO_LOG_DIR/" 2>/dev/null || true
  echo "archived gate.json / audit.json / coverage-boundary.txt to $BOGO_LOG_DIR"
fi

exit "$VERDICT"
