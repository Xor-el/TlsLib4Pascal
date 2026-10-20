#!/usr/bin/env bash
# Prints the exact OS build of the runner to the step log and, when set, $GITHUB_STEP_SUMMARY, so a
# leg can be compared with the builds a platform certificate lists. Windows reports the full
# build.UBR and bcryptprimitives.dll version (os-build-info.ps1); other systems report uname.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=shared/common.sh
source "$HERE/shared/common.sh"

if ci_is_windows; then
  powershell -NoProfile -ExecutionPolicy Bypass -File "$(cygpath -w "$HERE/os-build-info.ps1")"
else
  info="$(uname -srm)"
  echo "$info"
  if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
    {
      echo "### OS build"
      echo "- $info"
    } >> "$GITHUB_STEP_SUMMARY"
  fi
fi
