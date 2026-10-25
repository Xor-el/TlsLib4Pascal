#!/usr/bin/env bash
# Interop phase for the VM legs. Runs inside the VM after the build and does what the
# interop-harness action does for the native legs: runs the FclNet adapter step where the
# installed FPC ships fcl-net, installs python3, then (with BoGo) provisions Go and the pinned
# BoGo peer and runs interop-build.sh (self-test, fuzzer, trust cells, openssl matrix, BoGo).
#
# MAKE_RUN_FCLNET=false skips the FclNet step; MAKE_RUN_INTEROP=false skips the rest, and
# MAKE_RUN_BOGO=false skips BoGo alone.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=shared/common.sh
source "$HERE/shared/common.sh"
ci_init_paths
ci_export_toolchain_path

export TLSLIB_CRYPTO_PROVIDER="${MAKE_CRYPTO_PROVIDER:-portable}"
export TLSLIB_PKIX_PROVIDER="${MAKE_PKIX_PROVIDER:-portable}"

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
    echo "::warning::fcl-net is not installed with this FPC - skipping the FclNet adapter step."
  fi
fi

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

# The latest stable Go from the official archive for this OS (go.dev ships amd64 builds for these
# systems; their package repositories carry an old Go or none), unpacked under $HOME and put on PATH.
install_official_go() {  # <go.dev OS name>
  local dir="$HOME/go-dist" ver archive list tarbin
  mkdir -p "$dir"
  ci_download "https://go.dev/VERSION?m=text" "$dir/version"
  ver="$(head -1 "$dir/version" | tr -d '\015')"
  archive="$ver.$1-amd64.tar.gz"
  # go.dev/dl/<file>.sha256 is an HTML redirect page; the raw checksum is served from dl.google.com
  ci_download "https://dl.google.com/go/$archive" "$dir/$archive"
  ci_download "https://dl.google.com/go/$archive.sha256" "$dir/$archive.sha256"
  list="$dir/sha256.list"
  printf '%s  %s\n' "$(tr -d '\015\012' < "$dir/$archive.sha256")" "$archive" > "$list"
  ci_verify_sha256 "$dir/$archive" "$list"
  # Solaris tar does not read the PAX headers in the archive, so prefer GNU tar where there is one
  for tarbin in gtar /usr/gnu/bin/tar tar; do
    if command -v "$tarbin" >/dev/null 2>&1; then break; fi
  done
  (cd "$dir" && gzip -dc "$archive" | "$tarbin" xf -)
  export PATH="$dir/go/bin:$PATH"
  go version
}

provision_python() {
  case "$(uname -s)" in
    FreeBSD|DragonFly)
      pkg install -y python3 || true
      ;;
    NetBSD)
      export PKG_PATH="https://cdn.NetBSD.org/pub/pkgsrc/packages/NetBSD/$(uname -p)/$(uname -r | cut -d_ -f1)/All"
      install_first pkg_add -u -- python313 python312 python311 python310 || true
      # pkgsrc installs only the versioned name, python3.13 and the like
      for py in /usr/pkg/bin/python3.[0-9][0-9]; do
        if [ -x "$py" ] && ! command -v python3 >/dev/null 2>&1; then
          ln -s "$py" /usr/pkg/bin/python3
          break
        fi
      done
      ;;
    SunOS)
      command -v python3 >/dev/null 2>&1 || pkg install --accept python-39 || true
      ;;
  esac
}

provision_go() {
  case "$(uname -s)" in
    FreeBSD)
      install_official_go freebsd
      ;;
    DragonFly)
      install_official_go dragonfly
      ;;
    NetBSD)
      install_official_go netbsd
      ;;
    SunOS)
      [ -x /usr/gnu/bin/tar ] || pkg install --accept archiver/gnu-tar || true
      install_official_go solaris
      ;;
  esac
}

provision_python

if [ "${MAKE_RUN_BOGO:-true}" = "true" ]; then
  provision_go
  export BOGO_WORKERS="${BOGO_WORKERS:-4}"
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

# DragonFly's base openssl is LibreSSL; dports installs a real one here
if [ -x /usr/local/bin/openssl ] && [ -z "${OPENSSL:-}" ]; then
  export OPENSSL=/usr/local/bin/openssl
fi

# NetBSD's base openssl has no config file and `openssl req` refuses to run without one
ossl_dir="$("${OPENSSL:-openssl}" version -d 2>/dev/null | sed -e 's/^OPENSSLDIR: "//' -e 's/"$//' || true)"
if [ -z "${OPENSSL_CONF:-}" ] && [ -n "$ossl_dir" ] && [ ! -r "$ossl_dir/openssl.cnf" ]; then
  printf '[req]\ndistinguished_name = req_dn\n[req_dn]\n' > "$HOME/openssl-minimal.cnf"
  export OPENSSL_CONF="$HOME/openssl-minimal.cnf"
fi

bash "$HERE/interop/interop-build.sh"
