# Third-party material

The initial Swift views and Rust implementation are original project code,
licensed under MIT. No code, assets, patches, or ports from Keyguard or Prizm
are included. Keyguard may serve only as a feature/requirements reference.
Future Prizm imports require its MIT + Commons Clause notices and a recorded
source revision; they are not implicitly covered by this project's MIT license.

Direct Rust dependencies:

| Dependency | License | Purpose |
| --- | --- | --- |
| UniFFI 0.32.2 | MPL-2.0 | FFI runtime and generated Swift/C bindings |
| url | MIT OR Apache-2.0 | Endpoint validation and credential service matching |
| zeroize | Apache-2.0 OR MIT | Zeroization of Rust-owned keys/tokens/secret buffers |
| aes, cbc, hkdf, hmac, pbkdf2, sha2 | MIT OR Apache-2.0 | Maintained RustCrypto primitives for encryption-v1 compatibility |
| argon2 | MIT OR Apache-2.0 | Argon2id key derivation |
| base64 | MIT OR Apache-2.0 | Cipher-string and authorization-hash encoding |
| reqwest | MIT OR Apache-2.0 | Bounded HTTPS API requests with Rustls |
| serde / serde_json | MIT OR Apache-2.0 | Wire response parsing |
| uuid | MIT OR Apache-2.0 | Runtime authentication device identifiers |
| chacha20poly1305 | MIT OR Apache-2.0 | Device-layer authenticated cache encryption |
| getrandom | MIT OR Apache-2.0 | OS entropy for cache keys/nonces/temp names |
| rustix | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT | Safe Unix descriptor-relative cache operations |
| subtle | BSD-3-Clause | Constant-time account/key fingerprint checks |

No Bitwarden SDK code is linked or copied. Protocol composition is implemented
independently using public formats and maintained primitives. Public synthetic
fixtures were generated independently with Python `cryptography` and
`argon2-cffi`, not copied from another client's source/test corpus. Fixture
generation tools are development-only and are not shipped in the app.
`tiny_http` (MIT OR Apache-2.0) is also a development-only dependency for isolated
loopback mock-server tests; it is not a production server or app dependency.

Exact versions and transitive packages are in `Cargo.lock`. Dependency license
obligations remain applicable to distributed binaries and generated code.
Before distributing releases, generate a full dependency license inventory and
include required notices and MPL-covered source/codegen availability. This file
is not yet a complete release attribution bundle.
