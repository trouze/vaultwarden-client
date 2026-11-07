#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
XCODEGEN="${XCODEGEN:-xcodegen}"
if ! command -v "$XCODEGEN" >/dev/null 2>&1; then
  echo "Install XcodeGen 2.44+ first (for example: brew install xcodegen)." >&2
  exit 1
fi
bash scripts/build-core.sh
"$XCODEGEN" generate --spec apps/macos/project.yml --project apps/macos
