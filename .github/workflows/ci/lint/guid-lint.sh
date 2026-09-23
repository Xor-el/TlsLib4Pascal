#!/usr/bin/env bash
# Fails when two interfaces share the same IID GUID. A duplicate interface GUID makes
# Supports / QueryInterface resolve to the wrong interface (the latent landmine BL-6
# fixed), so this fast CI guard keeps every interface IID globally unique.
#
# Scope: every *.pas in the repo (an IID must be unique everywhere - a test interface
# colliding with a production one is just as broken), minus the editor __history backups.
# Matches only the interface-IID form ['{...}']; a bare '{...}' GUID constant is ignored.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." || exit 2

IID='\[[[:space:]]*'\''\{[0-9A-Fa-f]{8}-([0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12}\}'\''[[:space:]]*\]'

matches="$(grep -rnoE "$IID" --include='*.pas' . 2>/dev/null | grep -v '/__history/')"

dups="$(printf '%s\n' "$matches" | awk '
  {
    if (match($0, /\{[0-9A-Fa-f]{8}-([0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12}\}/)) {
      g = toupper(substr($0, RSTART + 1, RLENGTH - 2))   # the GUID, braces stripped, upper-cased
      loc = substr($0, 1, RSTART - 1)                    # the file:line: prefix
      sub(/:[[:space:]]*\[[[:space:]]*'\''$/, "", loc)   # trim the trailing match fragment
      seen[g] = seen[g] "\n    " loc
      cnt[g]++
    }
  }
  END {
    for (g in cnt)
      if (cnt[g] > 1)
        printf "  duplicate IID {%s}:%s\n", g, seen[g]
  }
')"

if [ -n "$dups" ]; then
  printf '\nguid-lint FAIL: interface IID reused (each interface needs its own GUID):\n%s\n' "$dups"
  printf '\nGenerate a fresh GUID for the offending interface (Ctrl+Shift+G in the IDE).\n'
  exit 1
fi
echo "guid-lint: clean ($(printf '%s\n' "$matches" | grep -c . ) interface IIDs, all unique)"
