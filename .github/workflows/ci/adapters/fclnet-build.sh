#!/usr/bin/env bash
# FclNet adapter coverage for the native legs. Platform/architecture-generic: keys off
# FPC_TARGET, so one script serves every native job.
#
# Runs AFTER the standard build step, so CryptoLib / HashLib / SimpleBase / TlsLib are
# already compiled into their lib/<target> unit dirs. make.pas only builds+runs the
# TlsLib.Tests closure, so no adapter is otherwise exercised in CI. FclNet is the one
# adapter whose only external dependency (fcl-net) ships in the FPC tarball CI installs,
# so it is the one that can be compiled AND run here; the other three adapters need
# third-party frameworks CI does not install and stay out of scope.
#
# Compiles all six FclNet examples against the prebuilt packages (proving the whole
# adapter surface, including the TFPHTTPClient hooks in the real-world example), then runs
# the four deterministic in-process loopbacks over 127.0.0.1. The real-world example hits
# an external host and the wedge demo is throughput/timing-based, so both are compile-only.
#
# Opt out of the whole step with MAKE_RUN_FCLNET=false.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$HERE/../shared/common.sh"
ci_init_paths
ci_export_toolchain_path

if [ "${MAKE_RUN_FCLNET:-true}" != "true" ]; then
  echo "MAKE_RUN_FCLNET != true - skipping the FclNet adapter step."
  exit 0
fi

: "${FPC_TARGET:?FPC_TARGET is required (e.g. x86_64-linux)}"
CPU="${FPC_TARGET%-*}"
OS="${FPC_TARGET#*-}"
EXE=""
case "$OS" in win*|*windows*) EXE=".exe" ;; esac

ADAPTER="$REPO_ROOT/TlsLib.Adapters/FclNet"
ADAPTER_SRC="$ADAPTER/Adapter"
EXAMPLE_SRC="$ADAPTER/Examples/src"
LPR_DIR="$ADAPTER/Examples/Lazarus"
BIN_DIR="$LPR_DIR/bin"
# the adapter uses the OS-trust facade; compile that package from src like interop-build.sh does
TRUST_SYSTEM_SRC="$REPO_ROOT/TlsLib.Trust.System/src"
# the ECH loopback example generates an ECH key via the EchKeyGen tool unit
ECHKEYGEN_SRC="$REPO_ROOT/TlsLib.Tools/EchKeyGen/src"
INCLUDE_DIR="$REPO_ROOT/TlsLib/src/Include"
mkdir -p "$BIN_DIR"

# fcl-net (ssockets/sslsockets/sslbase) ships in the FPC tarball CI installs, so it resolves
# from the FPC unit path like any RTL/FCL unit - no -Fu for it. A leg whose FPC lacks it (a
# split-package distro FPC, e.g. FreeBSD - which is not wired for this step) fails the compile
# below with a clear "Can't find unit ssockets".

# Locate the prebuilt package unit dirs by a known .ppu (each package -> <pkg>/lib/<target>).
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

echo "==> compiling the FclNet adapter examples against the prebuilt packages"
BUILD_DIR="$(mktemp -d)"
# fpc on Windows is a native binary that ignores MSYS (/c/...) paths in -Fu/-FU/-o; hand it
# backslash paths via cygpath -w there. A no-op on Unix.
to_native() {
  case "$OS" in win*|*windows*) cygpath -w "$1" ;; *) printf '%s' "$1" ;; esac
}
compile() {  # <program-name>
  fpc "-T$OS" "-P$CPU" -MDelphi -O2 -B \
    -Fi"$(to_native "$INCLUDE_DIR")" \
    -Fu"$(to_native "$CRYPTO_UNITS")" -Fu"$(to_native "$HASH_UNITS")" \
    -Fu"$(to_native "$SB_UNITS")" -Fu"$(to_native "$TLS_UNITS")" \
    -Fu"$(to_native "$TRUST_SYSTEM_SRC")" -Fu"$(to_native "$ECHKEYGEN_SRC")" \
    -Fu"$(to_native "$ADAPTER_SRC")" -Fu"$(to_native "$EXAMPLE_SRC")" \
    -FU"$(to_native "$BUILD_DIR")" -o"$(to_native "$BIN_DIR/$1$EXE")" "$(to_native "$LPR_DIR/$1.lpr")"
}
for p in FclNetLoopback FclNetEchLoopback FclNetResumptionScope FclNetAdvancedConfig \
         FclNetWedgeDemo FclNetRealWorld; do
  echo "    - $p"
  compile "$p"
  chmod +x "$BIN_DIR/$p$EXE"
done

# Bound each run so a server-side hang (the examples' final WaitFor is unbounded) cannot
# stall the job. Prefer timeout, then macOS's gtimeout; fall back to unbounded.
run_bounded() {  # <seconds> <cmd...>
  local secs="$1"; shift
  if command -v timeout >/dev/null 2>&1; then timeout "$secs" "$@"
  elif command -v gtimeout >/dev/null 2>&1; then gtimeout "$secs" "$@"
  else "$@"; fi
}

echo "==> running the deterministic in-process loopbacks (127.0.0.1, no network)"
for p in FclNetLoopback FclNetEchLoopback FclNetResumptionScope FclNetAdvancedConfig; do
  echo "    - $p"
  run_bounded 120 "$BIN_DIR/$p$EXE"
done
