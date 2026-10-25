#!/usr/bin/env bash
# Interop phase for the VM legs. Runs inside the VM after the build and does what the
# interop-harness action does for the native legs: provisions Go and the pinned BoGo peer,
# then runs interop-build.sh (self-test, fuzzer, trust cells, openssl matrix, BoGo).
# Also runs the FclNet adapter step where the installed FPC ships fcl-net.
#
# Opt out with MAKE_RUN_INTEROP=false, of BoGo alone with MAKE_RUN_BOGO=false.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=shared/common.sh
source "$HERE/shared/common.sh"
ci_init_paths
ci_export_toolchain_path

if [ "${MAKE_RUN_INTEROP:-true}" != "true" ]; then
  echo "MAKE_RUN_INTEROP != true - skipping the interop phase."
  exit 0
fi

# Install the first package name in the list that the manager accepts.
install_first() {  # <install command...> -- <candidate>...
  local cmd=() pkg
  while [ "$1" != "--" ]; do cmd+=("$1"); shift; done
  shift
  for pkg in "$@"; do
    if "${cmd[@]}" "$pkg"; then return 0; fi
  done
  echo "WARN(vm-interop): none of: $* could be installed"
  return 1
}

provision_tools() {
  case "$(uname -s)" in
    FreeBSD|DragonFly)
      pkg install -y go python3 || true
      ;;
    NetBSD)
      export PKG_PATH="https://cdn.NetBSD.org/pub/pkgsrc/packages/NetBSD/$(uname -p)/$(uname -r | cut -d_ -f1)/All"
      pkg_add -u go || true
      install_first pkg_add -u -- python313 python312 python311 python310 || true
      ;;
  esac
}

# Solaris offers Go 1.7 (obsolete) and gccgo (Go 1.18), and the BoGo runner needs a far newer Go
if [ "$(uname -s)" = "SunOS" ] && [ "${MAKE_RUN_BOGO:-true}" = "true" ]; then
  echo "BoGo skipped on SunOS: no Go new enough for the BoGo runner is available."
  export MAKE_RUN_BOGO=false
fi

if [ "${MAKE_RUN_BOGO:-true}" = "true" ]; then
  provision_tools
  command -v go >/dev/null 2>&1 || echo "::warning::no go on $(uname -s); BoGo will fail"
  export BOGO_SRC="${BOGO_SRC:-$HOME/boringssl}"
  : "${BOGO_REF:?BOGO_REF is required}"
  if [ ! -d "$BOGO_SRC/.git" ]; then
    git init -q "$BOGO_SRC"
    git -C "$BOGO_SRC" remote add origin https://boringssl.googlesource.com/boringssl
  fi
  # fetch exactly the pinned commit, as the interop-harness action does
  git -C "$BOGO_SRC" fetch --depth 1 origin "$BOGO_REF"
  git -C "$BOGO_SRC" checkout -q FETCH_HEAD
fi

# fcl-net ships with the FPC tarball but not with every pkg-installed FPC
fclnet_available() {
  local dir rc
  dir="$(mktemp -d)"
  printf 'uses ssockets;\nbegin\nend.\n' > "$dir/probe.pas"
  rc=0
  fpc -FE"$dir" -FU"$dir" "$dir/probe.pas" >/dev/null 2>&1 || rc=$?
  rm -rf "$dir"
  return "$rc"
}

if [ "${MAKE_RUN_FCLNET:-true}" = "true" ]; then
  if fclnet_available; then
    bash "$HERE/adapters/fclnet-build.sh"
  else
    echo "fcl-net is not installed with this FPC - skipping the FclNet adapter step."
  fi
fi

bash "$HERE/interop/interop-build.sh"
