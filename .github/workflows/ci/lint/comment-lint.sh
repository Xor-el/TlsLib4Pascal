#!/usr/bin/env bash
# Fails when a production Pascal comment reintroduces an internal codename, a design-doc
# section reference, or an implementation name-drop describing our own behaviour. A fast CI
# guard so the lean-comment conventions do not regress.
#
# Scope: the production source - TlsLib/src, the OS-trust and OS-crypto packages, and the four
# adapter units. The interop and benchmark trees are deliberately excluded: there the OpenSSL /
# BoGo peer is the test subject, not a description of our own behaviour. Backend/host-framework
# names are handled per-pattern (OpenSSL is fine in an adapter, which bridges it; CryptoLib is
# fine as a code identifier in a provider unit, but not in a comment).
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." || exit 2

CORE="TlsLib/src"
PROD=("TlsLib/src" "TlsLib.Trust.System/src" "TlsLib.Crypto.System/src")
# shellcheck disable=SC2207
ADAPTERS=($(ls -d TlsLib.Adapters/*/Adapter 2>/dev/null))

fail=0
report() { # <label> <matches>
  if [ -n "$2" ]; then
    printf '\ncomment-lint FAIL: %s\n%s\n' "$1" "$2"
    fail=1
  fi
}
noh() { grep -v '/__history/'; }

# internal codenames and design-doc section references (never legitimate in production)
report "internal codename / section reference (XC-/MED-/LOW-/BL-/Tier-/§)" \
  "$(grep -rnE '\b(XC-[0-9]|MED-[0-9]|LOW-[0-9]|BL-[0-9])\b|\bTier[- ][0-9]|§' \
     --include='*.pas' "${PROD[@]}" "${ADAPTERS[@]}" 2>/dev/null | noh)"

# implementations we do not name-drop when describing our own behaviour
report "implementation name-drop (rustls / BoringSSL / s2n)" \
  "$(grep -rnwE 'rustls|BoringSSL|s2n' \
     --include='*.pas' "${PROD[@]}" "${ADAPTERS[@]}" 2>/dev/null | noh)"

# OpenSSL is legitimate in an adapter (it bridges the host framework's OpenSSL surface), so
# only the core is checked
report "OpenSSL name-drop in core" \
  "$(grep -rnw 'OpenSSL' --include='*.pas' "$CORE" 2>/dev/null | noh)"

# CryptoLib as a backend name-drop in a core comment: the provider units reference it as a code
# identifier (Clp*, ECryptoLibException), which is allowed; a // or /// comment mention is not
report "CryptoLib name-drop in a core comment" \
  "$(grep -rnE '//.*\bCryptoLib' --include='*.pas' "$CORE" 2>/dev/null | noh)"

if [ "$fail" -ne 0 ]; then
  printf '\nA production comment reintroduced a banned reference. Describe the behaviour in our\n'
  printf 'own terms (RFC citations are fine); do not cite an internal codename or an\n'
  printf 'implementation we do not bind. If a match names a platform API the code genuinely\n'
  printf 'calls, refine this guard rather than the comment.\n'
  exit 1
fi
echo "comment-lint: clean"
