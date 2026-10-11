#!/usr/bin/env bash
# Fails when a test TearDown or test method frees an object field with a bare 'FThing.Free;'. The GUI runners
# re-run the same test instances, and a field freed this way is left dangling: if the next SetUp
# raises before reassigning it, TearDown frees it a second time. Register the object with
# Own<T>(...) in SetUp instead and let TTlsLibTestCase dispose it.
#
# Scope: every *.pas under TlsLib.Tests/src. Only a field (F-prefixed) is flagged; a local freed
# in its own method is fine.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." || exit 2

hits="$(find TlsLib.Tests/src -name '*.pas' -not -path '*/__history/*' -print0 |
  xargs -0 awk '
    /^procedure [A-Za-z0-9_.]+\.(TearDown|Test[A-Za-z0-9_]*);/ { inTearDown = 1; next }
    inTearDown && /^end;/                   { inTearDown = 0; next }
    inTearDown {
      code = $0
      sub(/\/\/.*/, "", code)
      if (code ~ /(^|[^A-Za-z0-9_.])F[A-Za-z0-9_]*\.Free[[:space:]]*(;|$)/)
        printf "  %s:%d: %s\n", FILENAME, FNR, $0
    }
  ')"

if [ -n "$hits" ]; then
  printf '\nteardown-lint FAIL: a TearDown or test method frees a field with a bare Free (use Own<T> in SetUp):\n%s\n' "$hits"
  exit 1
fi
echo "teardown-lint: clean"
