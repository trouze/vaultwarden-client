#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
bash scripts/build-core.sh

FLAGS=(-swift-version 6 -target arm64-apple-macos26.0 -I build/generated
  -Xcc -fmodule-map-file=build/generated/VaultCoreFFI.modulemap)
xcrun swiftc "${FLAGS[@]}" -parse-as-library \
  build/generated/VaultCore.swift apps/macos/Shared/*.swift \
  apps/macos/App/CategoryTilesView.swift \
  apps/macos/App/Services/*.swift apps/macos/App/QuickAccessView.swift apps/macos/App/QuickSearchField.swift \
  tests/swift/BridgeSmoke.swift tests/swift/InteractionChecks.swift \
  target/debug/libvault_ffi.a -o build/bridge-smoke
build/bridge-smoke

# Compile-check actual extension API overrides and extension-safe Swift code.
# This does not establish provisioning, installation, or end-to-end AutoFill.
xcrun swiftc "${FLAGS[@]}" -application-extension -parse-as-library -typecheck \
  build/generated/VaultCore.swift apps/macos/Shared/*.swift \
  apps/macos/CredentialProvider/CredentialProviderViewController.swift
echo "Credential Provider extension typecheck passed"
