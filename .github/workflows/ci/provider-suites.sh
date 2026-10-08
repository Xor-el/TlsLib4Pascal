#!/usr/bin/env bash
# Re-runs the unit suites on the console binary the Build step already produced, against the
# crypto and PKIX providers selected by TLSLIB_CRYPTO_PROVIDER / TLSLIB_PKIX_PROVIDER
# (portable, or os for the platform's native crypto facets). The portable pass in Build is
# unaffected; this one is additive and needs no rebuild.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$HERE/shared/common.sh"
ci_init_paths
cd "$REPO_ROOT"

BIN="$REPO_ROOT/TlsLib.Tests/FreePascal.Tests/bin/TlsLib"
[ -f "$BIN.exe" ] && BIN="$BIN.exe"
if [ ! -f "$BIN" ]; then
  echo "::error::the console test binary was not built ($BIN); the Build step must run first"
  exit 1
fi

echo "==> unit suites on crypto=${TLSLIB_CRYPTO_PROVIDER:-portable} pkix=${TLSLIB_PKIX_PROVIDER:-portable}"
"$BIN" --all --format=plain --progress
