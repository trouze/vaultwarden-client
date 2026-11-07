#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [[ "$(uname -s)" != Darwin || "$(uname -m)" != arm64 ]]; then
  echo "The first macOS prototype requires an Apple Silicon Mac." >&2
  exit 1
fi

bash scripts/build-core.sh
APP="$ROOT/build/Vaultwarden.app"
mkdir -p "$APP/Contents/MacOS"
xcrun swiftc -swift-version 6 -target arm64-apple-macos26.0 \
  -I build/generated -Xcc -fmodule-map-file=build/generated/VaultCoreFFI.modulemap \
  -parse-as-library build/generated/VaultCore.swift \
  apps/macos/Shared/*.swift apps/macos/App/*.swift apps/macos/App/Services/*.swift \
  target/debug/libvault_ffi.a -o "$APP/Contents/MacOS/Vaultwarden"

# Expand only the public provisional bundle ID; no user configuration is copied.
python3 - "$ROOT/apps/macos/App/Info.plist" "$APP/Contents/Info.plist" <<'PY'
import plistlib
import sys
with open(sys.argv[1], 'rb') as f:
    info = plistlib.load(f)
info['CFBundleIdentifier'] = 'org.vaultwardenclient.desktop.demo'
info['CFBundleExecutable'] = 'Vaultwarden'
with open(sys.argv[2], 'wb') as f:
    plistlib.dump(info, f)
PY

# This app-only CLT build is ad-hoc signed. It does not install an AutoFill
# extension or claim Developer ID / provisioning / notarization validation.
codesign --force --sign - "$APP"
codesign --verify --strict "$APP"
echo "Built read-only Vaultwarden: $APP"
echo "Open with: open build/Vaultwarden.app"
