#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# Finder-launched Xcode does not inherit an interactive shell's Rust/Homebrew
# PATH. Use conventional tool directories without sourcing shell profiles,
# which can have side effects or contain credentials.
for BIN in "${CARGO_HOME:-$HOME/.cargo}/bin" /opt/homebrew/bin /usr/local/bin; do
  if [[ -d "$BIN" ]]; then
    export PATH="$BIN:$PATH"
  fi
done
if ! command -v cargo >/dev/null 2>&1; then
  echo "Cargo was not found. Install Rust or set CARGO_HOME for Xcode's build environment." >&2
  exit 1
fi

# Keep UniFFI codegen and runtime at the same Cargo-locked version.
cargo build --locked -p vault-ffi
mkdir -p build/generated
cargo run --locked -p vault-ffi --features bindgen --bin uniffi-bindgen -- \
  generate --library target/debug/libvault_ffi.dylib \
  --language swift --out-dir build/generated
