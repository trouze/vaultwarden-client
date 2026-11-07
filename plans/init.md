# Native macOS Vaultwarden client — initial build plan

Status: early real read-only personal-vault path implemented and mock-tested;
live interoperability and independent security review have not been performed.

Implemented: Rust session/search/detail/reveal core, generated UniFFI bindings,
SwiftUI demo app/menu bar, synthetic password-provider scaffold, and test/build
scripts. Later increments add quick access, clickable credential boxes, category tiles,
inactivity locking, local UI preferences, and a three-column category/list/detail
layout with middle-column sorting. Add remains disabled until creation support
is implemented. Password/authenticator-code login, token refresh, PBKDF2/Argon2id,
authenticated cipher/account/item key decryption, personal record types, and
in-memory cached unlock, opt-in encrypted persistent cache and offline restart
are implemented. Optional biometric enrollment uses a real protected Keychain
ACL and requires interactive device/signing validation; no weak fallback. See
`docs/capabilities.md` for scope.

**Product direction:** standalone app with local/ad-hoc builds. No Developer ID
certification, notarization, App Store, native-provider activation, or browser
extension is planned. The earlier provider scaffold remains compile-only and is
not embedded in the normal app. It is not an acceptance gate for the reader.

## Goal

App name: **Vaultwarden**. Repository/internal project name: `vaultwarden-client`
/ `VaultwardenClient`. Demo status remains explicit within the interface.

Build a native SwiftUI macOS password manager backed by Rust. Any integration
endpoint is supplied privately at runtime, never as a repository preset. Aim for the feel of
Apple Passwords without replacing Vaultwarden as the source of truth.

Active end state:

- Vault browsing, search, details, editing, folders, favorites, trash, and TOTP.
- Keychain-backed, Touch ID-gated unlock; offline access and reliable sync.
- Fast search-and-copy with clipboard expiration, local-only exclusion markers,
  native menus, shortcuts, menu bar UI and a global quick-access panel.
- SSH agent and account management without paid Apple signing dependencies.
- Reproducible source/local builds; evaluate unsigned direct releases later.

Deferred/out of active scope: native AutoFill/passkey provider activation, browser
extensions, Developer ID signing/notarization, and a polished Homebrew release.
Passkey record preservation is distinct from acting as a native authenticator.

This is security software: start with synthetic accounts and read-only access,
prove protocol compatibility, then enable writes. Do not use a primary vault as
the initial test corpus.

## Feasibility and initial decisions

| Area | Initial decision | Constraint / validation |
| --- | --- | --- |
| UI | SwiftUI with targeted AppKit integration | Adapt Prizm presentation components, not its Swift backend. |
| Core | Rust behind UniFFI | Own protocol, encryption, storage, search, and operations in one place. |
| Platform | Provisionally macOS 26+, Apple Silicon first | Prizm currently requires macOS 26 and Xcode 26; revisit older OS/Intel support after auditing imported views. |
| AutoFill | Manual search-and-copy | Native-provider scaffold is compile-only; no Accessibility auto-type or browser extension in this increment. |
| Passkeys | Preserve compatible records in future vault operations | Native passkey creation/assertion is deferred; do not suggest that copying a record enables sign-in. |
| Distribution | Source and local/ad-hoc app builds | No paid certification plan; no Gatekeeper-disabling install scripts. |
| Server | Configurable HTTPS endpoint | No personal hostnames in source, documentation, fixtures, presets, or CI. |
| Account scope | One self-hosted account initially | Namespace storage and keys by account/server from day one. |

Manual copy/paste is the current integration strategy. Native provider and browser
extension work are deferred, not hidden prerequisites for using the standalone
app. Accessibility-based auto-type is not a substitute for native passkeys and
is not the baseline solution. Avoid asking for broad input-monitoring privileges.

## Upstream reuse and licensing gate

Inspected upstream on 2026-11-07:

| Upstream | Inspected revision | Findings / policy |
| --- | --- | --- |
| [Prizm](https://github.com/b0x42/prizm) | `e55b788f9c4c275fdd1ec3fe92359205ddc01623` | `LICENSE` contains MIT **plus Commons Clause**, restricting sale. Preserve both notices on copied material; do not label the resulting app plain MIT without reviewing obligations. |
| [Keyguard](https://github.com/AChep/keyguard-app) | `a88533ed57026af8dcea78ecf051644755fc728a` | Feature guidance only. No code, ports, assets, or patches will be copied into this project. |
| [Bitwarden SDK](https://github.com/bitwarden/sdk-internal) | Not yet pinned | Root license offers GPLv3 or Bitwarden SDK License, with some directories SDK-license-only. Evaluate exact crates, headers, and terms before adopting; not an automatic permissive dependency. |

Personal intent alone does not establish redistribution permission. Keyguard
code reuse is excluded; use independently licensed crates and documented
protocols. Keep any other upstream-derived material traceable
in `THIRD_PARTY_NOTICES.md`, including source revision, original path, license,
and local changes. Review any vendored third-party code separately.

Prizm candidates to adapt after license review:

- `Prizm/Presentation/Vault/VaultBrowserView.swift`, sidebar, item list/rows.
- Detail and edit forms for logins, cards, identities, notes, and SSH keys.
- `Components/FieldRowView.swift`, `MaskedFieldView.swift`, design/accessibility helpers.
- Login, unlock, settings, verification-code views, and keyboard interactions.

Replace view-model dependencies with a Swift adapter to the Rust core. Do not
carry over Prizm's crypto/network/storage implementation. Audit favicon fetching:
no third-party requests revealing vault domains by default.

Keyguard is Kotlin/Compose Multiplatform with native Rust modules, not a reusable
complete Rust Vaultwarden backend. Its feature set may inform requirements,
but implementation here will be independent. Its desktop native library also
has JNI-oriented glue unsuitable for direct Swift reuse.

## Architecture

```text
macOS app (Swift)
├── SwiftUI: vault, search, detail/edit, account/settings, quick access
├── AppKit: windows, menus, hotkey, lifecycle, clipboard
├── Apple adapters: Keychain, LocalAuthentication, credential identity store
└── CoreAdapter → generated UniFFI Swift bindings
    └── Rust core
        ├── Vaultwarden API, authentication, token refresh, sync
        ├── Bitwarden wire models, KDFs, key hierarchy, cipher operations
        ├── Encrypted local persistence, migrations, encrypted mutation queue
        ├── Search, URI matching, TOTP, vault operations
        └── Passkey generation, credential encoding, assertion signing

Credential Provider Extension (retained compile-only experiment; not embedded)
├── ASCredentialProviderViewController + native selection/unlock UI
├── Password/passkey entry points; supported TOTP APIs later
└── Same Rust library + narrowly scoped shared-state adapter

SSH agent (separate Rust helper/process, opt-in)
├── OpenSSH agent protocol on a user-owned Unix socket
└── Authenticated requests to app-owned key/signing broker

Potential shared resources (deferred with native-provider work)
├── App Group: encrypted snapshots, schema/version and lock coordination
└── Keychain access group: device-bound, access-controlled wrapping material
```

The Rust core is platform-independent where practical. Swift owns OS prompts and
lifecycle decisions; Rust owns vault semantics. Native UI must never implement a
second crypto or sync path. App Group/keychain access is an entitlement boundary,
not permission to bypass unlock. UniFFI is an in-process FFI boundary, **not IPC**;
the helper requires a separate reviewed transport and authorization design.

### Small, explicit FFI API

Start with typed operations, not arbitrary JSON commands:

- `configure_account`, `prelogin`, `login`, `submit_two_factor`, `logout`.
- `unlock`, `lock`, `session_state`, `sync`, `sync_status`.
- `search` / `list_items` returning summaries, `get_item`, `reveal_field`.
- `create_item`, `update_item(expected_revision)`, `trash_item`, `restore_item`.
- `match_credentials`, `resolve_password`, `register_passkey`, `assert_passkey`.
- Narrow signing operations for SSH; no bulk private-key export to the helper.

Exact signatures follow the protocol spike. Use structured errors and auth
challenges, async calls off the main actor, cancellation, and versioned bindings.
List summaries should not include passwords, TOTP seeds, or private keys.
Lock clears Rust decrypted state and Swift view models; minimize secret copies
across FFI. Rust zeroization cannot guarantee Swift String copies are erased.
Callbacks/streams should carry state changes, not a live decrypted vault dump.

### Storage and cross-process access

- Persist server cipher envelopes encrypted as received. Encrypt local-only
  metadata, indexes, and queued edits with a separate device-local data key;
  decide SQLite field encryption vs an encrypted database in the storage spike.
- Keep the search index in memory while unlocked. No plaintext searchable vault
  database or plaintext export used as an extension cache.
- Begin with the main app as snapshot writer; the extension reads a versioned,
  atomically published encrypted snapshot. Never assume the app is running.
- Extension unlock must authenticate independently under the chosen policy.
  Share a lock generation/epoch and invalidate active requests on lock/logout,
  sleep, or account switch; test missed notifications and stale-process races.
- Before passkey registration, design an encrypted extension mutation journal
  and coordinated commits. Durably persist a new credential before returning
  registration success, even offline; merge/upload when the app next syncs.
- Serialize writes, use optimistic revision checks, and quarantine conflicts.
  Crash recovery and schema migration must work across app/extension versions.
- The credential identity store intentionally exposes limited usernames/domains
  to macOS for suggestions. Document this metadata tradeoff and remove identities
  on logout/deletion; define whether suggestions remain visible while locked.
- Store refresh tokens and wrapping secrets under reviewed Keychain access
  controls. Validate biometric enrollment changes and password fallback. Touch ID
  authorizes access; the Secure Enclave does not automatically hold arbitrary
  portable Bitwarden/passkey private keys.

## Protocol and security requirements

- Support prelogin KDF discovery, PBKDF2-SHA256 and Argon2id, encrypted user keys,
  cipher-string variants, per-item keys, and organization-key hierarchies as
  required by fixtures. Cap untrusted KDF parameters to avoid resource exhaustion;
  reject unsupported settings explicitly rather than deriving the wrong key.
- Prefer a license-compatible maintained SDK where viable. Otherwise compose
  maintained crypto crates with published Bitwarden formats and known-answer
  tests; do not invent cryptography or infer the protocol solely from Prizm.
- Preserve unknown fields/cipher types; block writes that cannot round-trip
  without loss. Respect organization/collection permissions and reprompt rules.
- Normal TLS verification only. Do not send credentials across unexpected
  redirects; sanitize endpoint paths and keep development HTTP isolated.
- Never log master passwords, vault contents, tokens, passkey keys, SSH signing
  payloads, or raw authentication responses. No analytics or third-party crash
  uploads by default.
- Auto-lock on sleep, screen lock, inactivity, and manual command. Clipboard
  expiration clears only the value this app wrote, and marks secrets concealed
  and non-universal where supported. Hide secrets from accessibility labels.
- Passkey assertions must validate RP ID/request binding, allow lists, user
  presence/verification, supported algorithms, and authenticator-data/signature
  encoding. Respect system-validated client data; do not synthesize trust from an
  arbitrary caller-supplied origin. Test discoverable credentials and counter /
  backup-state behavior appropriate to syncable credentials.
- SSH signing is denied while locked, scoped to enabled keys, and approved
  explicitly by default. Bound packet sizes, validate socket ownership and IPC
  peers, expire approval sessions, and reject arbitrary key mutation requests.
  Do not claim the agent can reliably identify the remote SSH destination solely
  from a standard signing request; forwarding/delegation require separate policy.

## Repository layout (proposed)

```text
apps/macos/                 Xcode app + Credential Provider Extension targets
packages/VaultCoreBindings/ Generated Swift bindings and Rust library packaging
crates/vault-core/         Models, crypto, search, operations, session state
crates/vault-api/          HTTP/auth/sync adapter and wire types
crates/vault-storage/      Encrypted persistence and mutation queue
crates/vault-ffi/          UniFFI export layer
crates/vault-ssh-agent/    Agent protocol/helper
scripts/                  Binding generation, build, packaging, release checks
tests/fixtures/           Synthetic protocol/crypto/interoperability fixtures
docs/                     Threat model, protocol notes, capability matrix, ADRs
plans/                    Milestones and task checklists
```

Pin Rust, UniFFI runtime/codegen, and dependency versions; commit lockfiles.
Generate reproducible bindings and an Apple Silicon static library initially;
add a universal/XCFramework distribution only when Intel support is chosen.
Choose a reproducible Xcode-project approach during scaffolding; extension
targets/entitlements mean a Swift executable package alone is insufficient.

## Milestones and acceptance gates

### M0 — standalone foundation (no paid signing prerequisites)

- [x] Record upstream licenses; exclude all Keyguard code reuse.
- [x] Choose app name: **Vaultwarden**.
- [ ] Choose stable bundle identifiers, deployment target, and
  initial crypto/SDK dependency policy.
- [x] Complete full Xcode setup and validate the standalone ad-hoc app target.
  Initial machine check: macOS 27.2 arm64, Rust 1.99.1, Swift 6.4; selected developer
  directory is `/Library/Developer/CommandLineTools`, not full Xcode.
- [x] Make a tiny SwiftUI app call Rust through generated UniFFI bindings.
- [ ] **Deferred:** create a **synthetic-credential** provider prototype, enable it in System
  Settings, and exercise password fill and passkey registration/assertion in
  Safari and a native test app. Verify required capabilities and provisioned
  entitlements in actual signed builds, not just plist declarations.
- [ ] **Deferred:** prove App Group access, Keychain sharing, independent extension unlock,
  extension operation with the app stopped, and lock propagation.

Gate: working Rust/Swift round-trip and standalone local build. Native-provider
signing/activation and cross-process shared state are not active gates.

### M1 — protocol-compatible read-only core

- [x] Implement independent fixtures and known-answer crypto tests before authenticated use.
- [x] Prelogin, password login, authenticator-code challenge/retry, token refresh.
- [ ] Email/hardware-key/SSO/captcha/device approval authentication support.
- [x] Fetch sync and decrypt supported personal login/note/card/identity/SSH/custom fields.
- [ ] Folders and organization
  fixtures or clearly mark org content unsupported without dropping it.
- [x] In-memory encrypted snapshot, master-password unlock, generation invalidation, lock/logout.
- [x] Opt-in encrypted persistent cache and locked offline restart, owner-only
  anchored I/O, atomic publication and authenticated previous-snapshot recovery.
- [x] Cache-key Keychain adapter and optional account-bound biometric credential
  path with `biometryCurrentSet` ACL; no stored master password or token.
- [ ] Interactive Keychain/biometric validation: signing/rebuild access, fingerprint
  changes, cancellation and disabled/forgotten credential cleanup.
- [ ] Opt-in read-only smoke test with a dedicated account on the hosted server.

Gate: fixtures match expected values; dedicated test vault reads correctly;
no plaintext secrets in logs/storage and locked APIs refuse secret access.

### M2 — native daily-use reader

- [ ] Adapt reviewed Prizm views to CoreAdapter-backed view models.
- [ ] Vault navigation/search/details, favorites/folders, TOTP, accessible forms.
- [ ] Touch ID enrollment/unlock, lifecycle auto-lock, clipboard safety.
- [ ] Menu bar item, quick-access panel/global hotkey, native commands/settings.
  Defaults: ⌃⇧Space, five-minute app inactivity lock, thirty-second clipboard
  expiration; keyboard selection/copy, typed category tiles and clickable field
  boxes, configurable safe presets. Tile counts remain totals while searching.
- [ ] Explain sync/error/offline states without leaking internal secret data.

Gate: usable read-only client online/offline, keyboard/VoiceOver coverage, and
no secret retained in visible view state after lock. This is the first usable
vertical slice; passkeys and SSH are not prerequisites for this milestone.

### M3 — safe writes and full vault operations

- [ ] Encrypted create/edit/trash/restore, password/passphrase generation.
- [ ] Revision-aware mutation queue, retry idempotency, offline edits and conflict UI.
- [ ] Preserve unknown fields; permissions, org/collection keys, item-key handling.
- [ ] Add cards/identities/notes/SSH item editing, then encrypted attachments.

Gate: edits round-trip through official Bitwarden clients and Vaultwarden without
data loss. Conflict/crash tests pass; no destructive reconciliation by default.

### M4 — production native password AutoFill (deferred; not planned currently)

- [ ] Credential identity-store updates and minimal selection UI.
- [ ] Domain/URI matching policies, user-confirmed selection, password requests.
- [ ] Independent locked/offline unlock, reprompt enforcement, timeouts/cancel.
- [ ] Upgrade/signing tests and per-browser/native-app capability matrix.
- [ ] Add native TOTP provision only where validated SDK/OS APIs support it.

Gate: correct credential supplied to supported hosts with the main app stopped;
wrong-domain, stale-identity, canceled-biometric and lock-race requests fail safely.

### M5 — interoperable native passkeys (deferred; not planned currently)

- [ ] Read existing Bitwarden passkey records, including compatible key encoding.
- [ ] Assertion generation and system request binding/user verification checks.
- [ ] Registration, durable local commits, encrypted sync and identity updates.
- [ ] Test passkeys made here in official Bitwarden clients and vice versa using
  disposable relying-party accounts; handle offline sync failures explicitly.

Gate: registration and authentication work end-to-end through macOS APIs; keys
survive restart/sync and cannot be used while locked or for another RP.

### M6 — SSH agent

- [ ] Independently licensed SSH protocol/key crates, bounded parser tests.
- [ ] User-owned socket, app broker transport and peer-authentication design.
- [ ] Per-key enablement, signing approval UI, timeout and lock revocation.
- [ ] Support Ed25519 and reviewed RSA-SHA2 signing first; document unsupported
  key types. Test `ssh`, `ssh-add -L`, and Git-over-SSH without exporting keys.
- [ ] Document `SSH_AUTH_SOCK`/IdentityAgent configuration; opt-in helper launch
  and login-item management. Do not rewrite shell or SSH configs automatically.

Gate: OpenSSH interoperability and negative authorization tests pass; helper
crashes/disconnects/lock events revoke access rather than silently approving.

### M7 — signed releases and Homebrew (deferred; not planned currently)

- [ ] CI: Rust tests/clippy/fmt, binding drift checks, Swift tests, macOS builds,
  dependency/license audits, fixture-only integration tests on untrusted PRs.
- [ ] Trusted release job signs app, extension and helper with appropriate
  entitlements/hardened runtime; notarizes and staples an app/DMG artifact.
- [ ] Upgrade/migration and clean-machine Gatekeeper/AutoFill registration tests.
- [ ] Publish versioned artifacts/checksums/notices after redistribution clearance.
- [ ] Add `Casks/<app-name>.rb` to `trouze/homebrew-tap`, with version, URL, SHA256,
  macOS requirement, app artifact and safe uninstall behavior. Keep vault/keychain
  deletion out of ordinary uninstall; any zap is explicit and documented.

Historical install goal (not available or actively planned):

```sh
brew tap trouze/tap
brew install --cask <app-name>
```

Do not modify/publish the tap or create remote releases during initial planning.

## Testing policy

- Default tests use synthetic fixtures/local mock services and require no account.
- Live tests require explicit opt-in and a dedicated disposable account on a
  privately configured endpoint; discover server version/config during that run.
  No live authentication, mutation, or server configuration changes were made
  while preparing this plan. Credentials are not committed or requested in chat.
- Live write tests touch only created test items and have explicit cleanup;
  never import/export or wipe a real vault as test setup.
- Cover both KDFs, tampered MACs, malformed/oversized records, organization keys,
  token expiry, two-factor retries, network failures and unsupported item types.
- Cover app/extension concurrent reads/writes, interrupted migrations, stale
  snapshots, account switches, lock races, biometric changes and process death.
- Fuzz cipher/agent parsers; test FFI cancellation/error handling and avoid panics
  crossing ABI boundaries. Security review is required before primary-vault use;
  tests alone are not an independent audit.

## Open decisions before implementation

1. Stable standalone bundle IDs. No Apple Developer membership or Developer ID
   certificate is an active requirement; revisit only if product scope changes.
2. Accept Prizm's Commons Clause for future reused views or seek a different grant.
   The initial scaffold uses original views; Keyguard code is permanently excluded.
3. SDK licensing vs maintained Rust crypto/protocol composition.
4. Confirm macOS 26+/Apple Silicon scope; Intel/older macOS is not yet promised.
5. **Deferred:** unlock policy across processes: independent authentication by default;
   convenience grants require explicit, short-lived, revocable authorization.

## References

- [Prizm license](https://github.com/b0x42/prizm/blob/e55b788f9c4c275fdd1ec3fe92359205ddc01623/LICENSE)
- [Prizm development guide](https://github.com/b0x42/prizm/blob/e55b788f9c4c275fdd1ec3fe92359205ddc01623/DEVELOPMENT.md)
- [Keyguard license](https://github.com/AChep/keyguard-app/blob/a88533ed57026af8dcea78ecf051644755fc728a/LICENSE)
- [Keyguard Rust workspace](https://github.com/AChep/keyguard-app/blob/a88533ed57026af8dcea78ecf051644755fc728a/Cargo.toml)
- [Bitwarden SDK licensing](https://github.com/bitwarden/sdk-internal/blob/main/LICENSE)
- [Apple Credential Provider APIs](https://developer.apple.com/documentation/authenticationservices/ascredentialproviderviewcontroller)
- [AutoFill entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.authentication-services.autofill-credential-provider)
- [Credential identity store](https://developer.apple.com/documentation/authenticationservices/ascredentialidentitystore)
- [UniFFI](https://mozilla.github.io/uniffi-rs/latest/)
- [Homebrew tap](https://github.com/trouze/homebrew-tap)
