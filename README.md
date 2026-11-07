# vaultwarden-client

**Vaultwarden** is a native SwiftUI macOS app with a Rust core and a small UniFFI
boundary. The repository remains `vaultwarden-client` for clarity.

**Current status: early read-only personal-vault client.** Password login,
authenticator-code 2FA, encrypted sync/decryption, opt-in encrypted offline cache,
and an optional protected Touch ID unlock path
are implemented. Protocol tests use independent synthetic fixtures and loopback
mock servers; **live Vaultwarden interoperability and independent security review
have not been performed**. Start with a disposable test account, not a primary vault.

## Implemented

- SwiftUI vault list, Rust-backed search, item details, explicit password reveal.
- Rust session state: locked by default, secret reads denied while locked,
  generation checks to reject stale-session reveals.
- Menu bar interface, quick access, keyboard selection/copy, and counted category tiles.
- Click-to-copy credential boxes, with password reveal kept separate.
- Configurable global shortcut, clipboard expiration, and inactivity lock.
- Settings/status, ⌘L, and lock hooks on sleep/session deactivation.
- Generated UniFFI Swift/C bindings linked against a Rust static library.
- Native Credential Provider Extension **retained as a compile-only experiment**,
  not embedded in the standalone app.
- Rust tests, executable Swift/FFI smoke tests, extension typechecking, CI.
- Runtime-only HTTPS server/email configuration, password grant with locally
  derived authorization hash, authenticator-code challenge/retry, and token refresh.
- PBKDF2-SHA256 / Argon2id, HKDF key stretching, authenticated type-2 cipher
  strings, encrypted account keys and per-item keys, using maintained RustCrypto crates.
- Personal logins, notes, cards, identities, SSH-key fields, and custom fields.
  Sensitive fields remain masked until explicitly revealed or copied.
- Opt-in persistent cache with device-layer ChaCha20-Poly1305 authenticated
  encryption, owner-only files, atomic publication and last-good recovery.
- Keychain cache-protection key; optional account-bound biometric credential
  protected by a real `biometryCurrentSet` ACL, never an unprotected user-key fallback.

Editing, verification-code generation, and SSH agent remain future work.
Actual biometric enrollment/Keychain behavior still requires interactive device
testing. **No Developer ID certification,
notarization, native AutoFill/passkey
provider activation, App Store release, or browser extension is planned.**
The standalone experience uses search-and-copy, not automatic form injection.
See [the implementation plan](plans/init.md) and [capability matrix](docs/capabilities.md).

## Connect safely

Enter your **trusted HTTPS server base URL**, email, and master password in the
app. Addresses and credentials are not embedded in source, examples, defaults,
or CI, and are never logged by the client. The master password is not sent to the
server; its derived authorization hash is credential-equivalent and is sent
only to the endpoint you explicitly choose. No redirects or environment proxies
are used, and TLS validation is never disabled.

Authenticator-app account 2FA is supported. Email/hardware-key/SSO/captcha/device
approval flows are not supported yet. After a challenge, re-enter the master
password and current verification code; password/code form buffers are cleared
on submission. Swift/FFI/network libraries can still create transient copies.

**Read-only means this client has no vault create/edit/delete requests.** Its
server-issued OAuth tokens are not intrinsically read-only and must be protected.
Persistence is **off by default**. Choose **Remember encrypted vault on this Mac**
before login, or **Settings → Save Encrypted Cache on This Mac** while unlocked.
The app stores server ciphertext plus required account/KDF metadata inside an
additional authenticated encrypted file under its Application Support directory.
Email/profile metadata is not left readable on disk. The outer cache key is in
the ordinary, non-synchronizing login Keychain; it cannot decrypt vault contents
without the master password or separately protected biometric credential.

Lock drops decrypted items, user keys, and tokens. A saved cache can be restored
after restart but remains **locked** until authentication. Cached unlock does not
restore online tokens: sign out and sign in again to resume sync. **Forget Account /
Sign Out** attempts to delete current/recovery files and this app's Keychain items,
with visible errors if cleanup is denied. It does not revoke server-side tokens.

**Settings → Enable Touch ID Unlock** also saves the cache, asks for biometric
confirmation, and stores an account-bound user-key credential only in the Data
Protection Keychain behind a `biometryCurrentSet` access control. Unsupported
signing/device configurations fail closed; the app never puts that credential in
ordinary Keychain or fakes security with a biometric dialog. Fingerprint changes,
lost access, or a mismatched account require master-password unlock/re-enrollment.
Ad-hoc rebuilds may prompt for ordinary Keychain access; protected Keychain support
can be unavailable. Password unlock does not depend on successful Touch ID enrollment.

If Touch ID succeeds but enrollment fails afterward, that is a separate Keychain
operation—not evidence of an incorrect fingerprint. The app now checks protected
Keychain access before prompting and reports the failing operation plus a safe
numeric `OSStatus`. `-34018` indicates missing signing/access-group authorization;
`-50` means macOS rejected the query/policy. Do not add arbitrary access-group
entitlements or weaken the ACL to bypass this. Share only the operation/status
for troubleshooting, not credentials, endpoints, or Keychain contents.

Organization, reprompt-protected, deleted, unknown-type, and unsupported cipher
records are omitted with a visible count rather than interpreted unsafely. Bad
MACs on parsed fields abort the sync transaction. Legacy unauthenticated cipher
formats and newer encryption-v2/COSE formats are not supported. See
[security notes](docs/security.md) before using real data.

## Standalone interaction

- The main window has three resizable columns: category tiles → filtered item
  list → selected-item details. Add (disabled until creation is implemented) and
  Sort share a split Liquid Glass toolbar pill; choose name A–Z/Z–A, username, or website.
  Selecting a list row shows details without copying or revealing a password.
- Search and Lock sit together in the top toolbar with native Liquid Glass
  styling. Quick Access remains in the menu bar and keyboard shortcuts, not the
  main window toolbar or lock screen. Sync downloads encrypted changes while a
  signed-in session is available; Sign Out forgets the saved/local account.
- **⌃⇧Space** opens quick access globally; choose **⌃⌥Space** or disable it in Settings.
  Conflicting shortcuts report an error; the menu bar always offers Quick Access.
- Search independently from the main window, use **↑/↓** to select, **Return** to
  copy the primary field, **⌥Return** to copy a login username, and **Escape** to dismiss.
  Quick access does not activate or inspect the destination app. Paste manually.
- Click a quick-access item to copy its primary field: login password, note,
  card number, identity email, or SSH public key (**⌥click** copies a login username).
  In the main detail view, click any field box to copy
  that field. Revealing a password is a separate eye control, not a copy action.
- Native-style **All, Passwords, Passkeys, Codes, Notes, Cards, Identities, SSH Keys**
  tiles replace favorites filtering. Counts use Rust type/capability metadata and
  remain vault totals while searching. The optional UI demo contains only three
  login items; the independent encrypted fixture covers all five cipher types. Passkey/code tiles
  do not imply authentication or TOTP generation has been implemented.
- In the main app: **⌘F** search, **⌘K** quick access, **⌘L** lock,
  **⇧⌘C** copy username, **⌥⌘C** copy password, **⌥⇧⌘C** copy website.
- Copies expire after **30 seconds** by default (15/30/60-second presets), or on
  lock/normal quit. A changed clipboard is left alone. Exclusion markers for
  clipboard history and Universal Clipboard are best effort, not a guarantee.
- The vault locks after **5 minutes without app interaction** by default
  (1/5/15-minute presets). Activity in other apps does not keep it unlocked.
- Only non-sensitive UI preferences are in UserDefaults. Opt-in cache/account
  metadata is encrypted, and keys are subject to the Keychain policies above.
  The global shortcut needs no Accessibility or Input
  Monitoring permission; there is no auto-type or global keyboard logger.

## Build the app

Requires an Apple Silicon Mac with macOS 26+, matching Command Line Tools or
Xcode with the macOS 26+ SDK, and Rust/Cargo 1.91+ (tested with 1.99.1). Full Xcode
is **not** required for the app-only build.

```sh
bash scripts/build-app.sh
open build/Vaultwarden.app
```

The app is built locally and ad-hoc signed, not Developer ID signed/notarized.
The app-only build does not embed/register the Credential Provider Extension.
No tooling is installed globally by these scripts; Cargo downloads locked Rust
dependencies. Build output and generated bindings are ignored by Git.

## Test

```sh
cargo test --locked --workspace
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
bash scripts/test-swift.sh
```

The Swift script runs real Swift → UniFFI → Rust calls, checks lock/reveal/search,
typed category counts/filtering, deterministic inactivity/clipboard deadlines, quick-access selection/click actions,
preference validation, and exclusion markers on an isolated named pasteboard.
It never reads or writes your general clipboard or registers test hotkeys. It
also typechecks the retained extension experiment against AuthenticationServices.
Rust tests validate independent crypto vectors, corrupted MAC rejection,
per-item key unwrap, bounded KDFs, HTTPS/redirect policy, mock login/2FA/refresh,
in-memory unlock, cancellation, cache restart/corruption/recovery, permission and
symlink rejection, account-bound biometric material, and cache publication guards.
Swift uses fake persistence/Keychain services to test opt-in and error handling;
no normal test creates real Keychain entries or displays biometric prompts.
Swift also exercises worker-call error
handling and stale queued login rejection without making external requests.
Tests need no live accounts, servers, signing identities, or secrets.

## Standalone Xcode target (no paid account)

Command Line Tools include Swift and the macOS SDK, but not the full Xcode build
system. Check the active developer directory and Xcode availability with:

```sh
xcode-select -p
xcodebuild -version
```

If the developer directory is `/Library/Developer/CommandLineTools`, app-only
builds still work. For Xcode target builds, install full Xcode and choose it in
**Xcode → Settings → Locations → Command Line Tools**. No system-wide developer
directory changes are made by this repository's scripts.

Install full Xcode 26+ and XcodeGen 2.44+ first, then generate the project:

```sh
bash scripts/generate-project.sh
open apps/macos/VaultwardenClient.xcodeproj
```

You can set `XCODEGEN=/path/to/xcodegen` instead of installing it globally.
The project is generated from `apps/macos/project.yml`; edit that spec rather
than the ignored `.xcodeproj`. Generated bindings must exist before generation,
which the script handles. Build phases also regenerate Rust/bindings.
Finder-launched Xcode has a minimal PATH; the Rust build phase explicitly checks
the conventional Cargo/Homebrew tool directories without sourcing shell profiles.
If Cargo lives elsewhere, set `CARGO_HOME` in Xcode's build environment.

The `VaultwardenClient` scheme builds **only the standalone app**, with ad-hoc
signing (`CODE_SIGN_IDENTITY=-`) and no paid AutoFill entitlement. No development
team is needed. The public `org.vaultwardenclient` IDs are provisional. Build it:

```sh
xcodebuild -project apps/macos/VaultwardenClient.xcodeproj \
  -scheme VaultwardenClient -configuration Debug \
  -destination 'generic/platform=macOS' \
  -derivedDataPath build/xcode build
```

To avoid changing system-wide tool selection, prefix commands with
`DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer` after completing
Xcode's license/first-launch setup yourself.

The separate `CredentialProviderPrototype` scheme is an **unsigned compile-only
experiment**. It is not embedded, enabled in System Settings, or an acceptance
gate for the app. Native-provider activation requires Apple's paid capability
provisioning and is outside the current product plan.

## Optional Personal Team signing for protected Keychain

Ad-hoc signing can run the app but does not authorize the Data Protection
Keychain; `OSStatus -34018` confirms that missing authorization. Apple lists
macOS Keychain Sharing as available to free developer accounts, so local Apple
Development/Personal Team signing is the next supported route to test—not paid
Developer ID certification. Actual provisioning and biometric ACL support must
still be verified on the signed app.

1. In **Xcode → Settings → Accounts**, select your signed-in account/team.
2. Under **Manage Certificates → +**, create **Apple Development** if no usable
   development identity exists. Signing in alone does not create a certificate.
3. Copy `apps/macos/Config/Signing.local.xcconfig.template` to
   `apps/macos/Config/Signing.local.xcconfig` and set the team ID locally. The local
   file is Git-ignored; do not post account details. Use a unique app-ID prefix
   authorized for your team if the public provisional identifier is unavailable.
4. Generate/open the project and select **VaultwardenDevelopment**. This separate
   scheme/configuration requests automatic Apple Development signing and a
   team-qualified Keychain group. Debug/Release and `build-app.sh` stay ad-hoc.
5. Build in Xcode, or run:

```sh
bash scripts/build-development.sh
```

The CLI does not permit automatic account/provisioning updates by default. If
you explicitly authorize Xcode to contact Apple and register/update app IDs,
devices, profiles or certificates, run `bash scripts/build-development.sh --provision`
or approve the corresponding steps in Xcode yourself. There is no automatic
paid enrollment, certificate export, private-key extraction or notarization.
Full signing output stays in ignored `build/development/build.log`.

The script verifies a non-ad-hoc Apple team signature, matching app identifier,
and concrete matching Keychain group without printing identifiers/account names.
It does not prove successful biometric enrollment. Quit the old app, open the
development-signed bundle, then try Touch ID with a disposable account. Do not
use `build-app.sh` for that test—it produces an ad-hoc app again.

Development and ad-hoc builds may have different bundle IDs, sandbox container
paths and Keychain ACLs. No automatic cache/key migration or deletion is performed.
Your existing ad-hoc cache remains untouched; validate the new build separately.

## Privacy and reuse policy

- Personal server addresses must never appear in source, examples, fixtures,
  plans, screenshots, issue reports, CI, or release artifacts.
- Live integration configuration must be supplied privately at runtime.
  Machine-local `.env*`, `*.local.json`, `*.local.toml`, and `*.local.xcconfig`
  files are ignored; configuration is entered only in the app and not persisted.
- Keep live credentials and endpoints out of command output and test logs.
  Obscuring an address reduces disclosure; it does not replace server security.
- **No Keyguard code, ports, patches, or assets are copied.** It may inform feature
  requirements only. The initial UI is original too; future Prizm reuse requires
  its MIT + Commons Clause notices and license review.

Original project code is [MIT licensed](LICENSE). Dependency obligations are
tracked in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md). Not affiliated with
Bitwarden, Vaultwarden, Prizm, or Keyguard.
