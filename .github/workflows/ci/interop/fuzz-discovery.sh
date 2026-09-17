#!/usr/bin/env bash
# Scheduled fuzzing discovery soak (not a PR gate): compile TlsFuzzer against the prebuilt
# packages and run a large --discovery budget. A new crasher/hang persists to
# TlsLib.Interop/Data/Corpus/regress/ and fails this scheduled run only.
#   FUZZ_DISCOVERY_SECONDS  wall-clock cap (default 1200)
#   FUZZ_DISCOVERY_ITERS    per-target ceiling (default 500000; the cap dominates)

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$HERE/../shared/common.sh"
ci_init_paths
ci_export_toolchain_path

: "${FPC_TARGET:?FPC_TARGET is required (e.g. x86_64-linux)}"
CPU="${FPC_TARGET%-*}"
OS="${FPC_TARGET#*-}"
EXE=""
case "$OS" in win*|*windows*) EXE=".exe" ;; esac

INTEROP="$REPO_ROOT/TlsLib.Interop"
SRC="$INTEROP/src"
# the opt-in OS-native crypto overlay is pure source layered on the prebuilt core, so compile
# its units on demand from src rather than prebuilding them
CRYPTO_SYSTEM_SRC="$REPO_ROOT/TlsLib.Crypto.System/src"
LPR_DIR="$INTEROP/FreePascal.Interop"
BIN_DIR="$LPR_DIR/bin"
mkdir -p "$BIN_DIR"

# Locate the prebuilt package unit dirs (same discovery-by-known-.ppu as interop-build.sh)
find_units_dir() {
  local f
  f="$(find "$REPO_ROOT" "$(dirname "$REPO_ROOT")" "$HOME" -type f -path "$1" 2>/dev/null | head -1 || true)"
  [ -n "$f" ] && dirname "$f"
}
CRYPTO_UNITS="$(find_units_dir "*/lib/$FPC_TARGET/ClpAesEngine.ppu")"
HASH_UNITS="$(find_units_dir "*HashLib*/*$FPC_TARGET/*.ppu")"
SB_UNITS="$(find_units_dir "*SimpleBase*/*$FPC_TARGET/*.ppu")"
TLS_UNITS="$(find_units_dir "*/lib/$FPC_TARGET/TlpTlsEngineFactory.ppu")"

for pair in "CryptoLib:$CRYPTO_UNITS" "HashLib:$HASH_UNITS" "SimpleBase:$SB_UNITS" "TlsLib:$TLS_UNITS"; do
  name="${pair%%:*}"; dir="${pair#*:}"
  if [ -z "$dir" ] || [ ! -d "$dir" ]; then
    echo "::error::could not locate prebuilt $name units for $FPC_TARGET (was the build step run first?)"
    exit 1
  fi
done

echo "==> compiling TlsFuzzer against the prebuilt packages"
BUILD_DIR="$(mktemp -d)"
# native fpc.exe on Windows ignores MSYS (/c/...) / mixed (C:/...) paths in -Fu/-FU/-o;
# hand it backslash paths via cygpath -w there. A no-op on Unix.
to_native() {
  case "$OS" in win*|*windows*) cygpath -w "$1" ;; *) printf '%s' "$1" ;; esac
}
fpc "-T$OS" "-P$CPU" -MDelphi -O2 -B \
  -Fu"$(to_native "$CRYPTO_UNITS")" -Fu"$(to_native "$HASH_UNITS")" \
  -Fu"$(to_native "$SB_UNITS")" -Fu"$(to_native "$TLS_UNITS")" \
  -Fu"$(to_native "$CRYPTO_SYSTEM_SRC")" -Fu"$(to_native "$SRC")" \
  -FU"$(to_native "$BUILD_DIR")" -o"$(to_native "$BIN_DIR/TlsFuzzer$EXE")" "$(to_native "$LPR_DIR/TlsFuzzer.lpr")"
chmod +x "$BIN_DIR/TlsFuzzer$EXE"

echo "==> fuzzing discovery soak (off the PR path; new crashers persist to Data/Corpus/regress/)"
"$BIN_DIR/TlsFuzzer$EXE" --discovery \
  --max-seconds "${FUZZ_DISCOVERY_SECONDS:-1200}" \
  --iterations "${FUZZ_DISCOVERY_ITERS:-500000}"
