#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

ALLOW_PROVISIONING=false
if [[ $# -gt 0 ]]; then
  if [[ $# -eq 1 && "$1" == "--provision" ]]; then
    # Explicit user opt-in: Xcode may contact Apple, register IDs/devices, and
    # create/update signing profiles/certificates using the signed-in account.
    ALLOW_PROVISIONING=true
  else
    echo "Usage: bash scripts/build-development.sh [--provision]" >&2
    exit 1
  fi
fi

if [[ -z "${DEVELOPER_DIR:-}" && -d /Applications/Xcode.app/Contents/Developer ]]; then
  export DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer
fi
if ! xcodebuild -version >/dev/null 2>&1; then
  echo "Complete full Xcode setup first; Command Line Tools alone cannot build this signing configuration." >&2
  exit 1
fi

python3 - <<'PY'
from pathlib import Path
import re
import subprocess
import sys
path = Path('apps/macos/Config/Signing.local.xcconfig')
if not path.is_file():
    sys.exit('Copy Config/Signing.local.xcconfig.template to Signing.local.xcconfig and set your team locally.')
text = path.read_text()
if not re.search(r'^\s*DEVELOPMENT_TEAM\s*=\s*[A-Z0-9]{10}\s*$', text, re.MULTILINE):
    sys.exit('Set a valid DEVELOPMENT_TEAM in the ignored local config. Do not post account details.')
result = subprocess.run(['security', 'find-identity', '-v', '-p', 'codesigning'], capture_output=True, text=True)
if '"Apple Development:' not in result.stdout and '"Mac Developer:' not in result.stdout:
    sys.exit('No usable development certificate. Create Apple Development in Xcode Accounts > Manage Certificates first.')
print('Local signing configuration and development identity are available (details redacted).')
PY

bash scripts/generate-project.sh
mkdir -p build/development
echo "Building local Apple Development app; signing/account output goes to ignored build/development/build.log."
XCODE_ARGS=(-project apps/macos/VaultwardenClient.xcodeproj -scheme VaultwardenDevelopment
  -configuration Development -destination 'generic/platform=macOS' -derivedDataPath build/development)
if [[ "$ALLOW_PROVISIONING" == true ]]; then
  XCODE_ARGS+=(-allowProvisioningUpdates)
fi
if ! xcodebuild "${XCODE_ARGS[@]}" build >build/development/build.log 2>&1; then
  echo "Development build failed. Inspect the ignored local log or Xcode Signing & Capabilities." >&2
  echo "Provisioning/account updates are off unless you explicitly pass --provision." >&2
  exit 1
fi
APP="$ROOT/build/development/Build/Products/Development/Vaultwarden.app"
python3 scripts/verify-development-signing.py "$APP"
echo "Built development app: $APP"
echo "Quit the ad-hoc app before opening this separately signed build. Existing ad-hoc cache is not migrated or deleted."
