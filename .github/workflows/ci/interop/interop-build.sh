#!/usr/bin/env bash
# Interop harness for the native legs. Platform- and architecture-generic: keys off
# FPC_TARGET, so the same script serves every native job (Linux, Windows, macOS).
#
# Runs AFTER that job's standard build step, so the CryptoLib / HashLib / SimpleBase /
# TlsLib packages are already compiled into their lib/<target> unit dirs. We compile
# the interop console programs against those prebuilt .ppu (no from-source rebuild)
# and run:
#   * InteropSelfTest  - a loopback TLS 1.3 handshake over real TCP (no external deps),
#   * TlsFuzzer        - the two-tier structure-aware parser fuzz (per-push tier: replay
#                        the whole regression corpus through every target + a fixed-seed
#                        bounded mutation smoke; any crash/hang/assert fails the leg),
#   * run-openssl-matrix.sh - our engine vs openssl s_client/s_server, both directions,
#   * run-bogo.sh      - the full-suite hard-gate BoGo run, when MAKE_RUN_BOGO=true.
#
# Opt out of the whole step with MAKE_RUN_INTEROP=false, of BoGo alone with
# MAKE_RUN_BOGO=false, or of the openssl matrix alone with MAKE_RUN_OPENSSL=false. The
# matrix additionally self-skips where no suitable OpenSSL is found (see run-openssl-matrix.sh),
# so it is safe to leave on everywhere. BoGo needs Go and a BoringSSL checkout in BOGO_SRC
# (the job provisions both when MAKE_RUN_BOGO=true).

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$HERE/../shared/common.sh"
ci_init_paths
ci_export_toolchain_path

if [ "${MAKE_RUN_INTEROP:-true}" != "true" ]; then
  echo "MAKE_RUN_INTEROP != true - skipping the interop harness."
  exit 0
fi

: "${FPC_TARGET:?FPC_TARGET is required (e.g. x86_64-linux)}"
CPU="${FPC_TARGET%-*}"
OS="${FPC_TARGET#*-}"
# FPC appends .exe to executables on Windows; account for it when touching / running them
EXE=""
case "$OS" in win*|*windows*) EXE=".exe" ;; esac

INTEROP="$REPO_ROOT/TlsLib.Interop"
SRC="$INTEROP/src"
# the opt-in OS-native crypto overlay is a small pure-source package layered on the already
# prebuilt core, so we compile its units on demand from src rather than prebuilding them
CRYPTO_SYSTEM_SRC="$REPO_ROOT/TlsLib.Crypto.System/src"
LPR_DIR="$INTEROP/FreePascal.Interop"
BIN_DIR="$LPR_DIR/bin"
mkdir -p "$BIN_DIR"

# Locate the prebuilt package unit dirs (each package outputs to <pkg>/lib/<target>),
# discovering by a known .ppu so we do not hard-code a layout that varies per package.
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
  echo "    $name units: $dir"
done

echo "==> compiling the interop programs against the prebuilt packages"
BUILD_DIR="$(mktemp -d)"
# fpc on Windows is a native binary: it does not understand MSYS (/c/...) or mixed
# (C:/...) paths in -Fu/-FU/-o and silently ignores them, so the leg fails to find the
# prebuilt units. Hand it backslash paths via cygpath -w there; a no-op on Unix.
to_native() {
  case "$OS" in win*|*windows*) cygpath -w "$1" ;; *) printf '%s' "$1" ;; esac
}
compile() {  # <program-name>
  fpc "-T$OS" "-P$CPU" -MDelphi -O2 -B \
    -Fu"$(to_native "$CRYPTO_UNITS")" -Fu"$(to_native "$HASH_UNITS")" \
    -Fu"$(to_native "$SB_UNITS")" -Fu"$(to_native "$TLS_UNITS")" \
    -Fu"$(to_native "$CRYPTO_SYSTEM_SRC")" -Fu"$(to_native "$SRC")" \
    -FU"$(to_native "$BUILD_DIR")" -o"$(to_native "$BIN_DIR/$1$EXE")" "$(to_native "$LPR_DIR/$1.lpr")"
}
for p in InteropSelfTest OpenSslInterop TlsFuzzer BoGoShim; do
  echo "    - $p"
  compile "$p"
  chmod +x "$BIN_DIR/$p$EXE"
done

echo "==> self-test (loopback TLS 1.3 over real TCP, no external deps)"
"$BIN_DIR/InteropSelfTest$EXE"

echo "==> structure-aware parser fuzzer (per-push tier: regression replay + fixed-seed smoke)"
# --iterations is the per-target smoke budget; the regression-corpus replay always runs.
# The scheduled discovery soak (a far larger budget) lives in fuzz-nightly.yml, off the
# per-push path, so a genuine new crasher never makes an unrelated PR flaky.
"$BIN_DIR/TlsFuzzer$EXE" --iterations "${FUZZ_ITERS:-500}"

if [ "${MAKE_RUN_OPENSSL:-true}" = "true" ]; then
  echo "==> openssl s_client/s_server matrix"
  bash "$HERE/run-openssl-matrix.sh"
else
  echo "MAKE_RUN_OPENSSL != true - skipping the openssl s_client/s_server matrix."
fi

if [ "${MAKE_RUN_BOGO:-true}" = "true" ]; then
  echo "==> BoGo full-suite hard gate"
  bash "$HERE/run-bogo.sh"
else
  echo "MAKE_RUN_BOGO != true - skipping the BoGo hard gate."
fi
