# Security boundary of the read-only client

This early client now has a real password-grant/sync/decryption path, validated
with independent synthetic crypto fixtures and mock HTTP servers. It has not
been interoperability-tested against a live Vaultwarden instance or independently
audited. Use disposable test accounts; do not treat it as a primary-vault replacement.

## Authentication, transport, and cryptography

- Server and email are entered privately at runtime, not saved in app preferences.
  Enter only a trusted HTTPS base URL: the server receives a credential-equivalent
  password-derived authorization hash. The raw master password stays on-device.
- Production endpoints require HTTPS, no URL credentials/query/fragment, ordinary
  Rustls TLS verification, no redirects, no environment proxies. Errors never
  include endpoint URLs, response bodies, tokens, or passwords. No log subscriber
  or telemetry is enabled. Test-only loopback HTTP uses a private helper.
- Network/KDF work runs off Swift's main actor. The operation gate rejects
  overlap; lock/logout generation checks reject queued or late commits. Between
  stages, cancellation stops new requests. A running blocking request/KDF cannot
  be immediately aborted; its worker's transient key/password copies survive
  until it returns (network timeout 30 seconds per request), then drop.
- PBKDF2-SHA256 (5,000–2,000,000 iterations) and Argon2id v1.3 (16–256 MiB,
  2–10 passes, parallelism 1–16, at most 1,024 MiB-passes) are accepted. Unsafe or
  unknown parameters are rejected, never reduced or silently defaulted.
- Type-2 AES-256-CBC + HMAC-SHA256 cipher strings only. MAC verification is
  constant-time and occurs before CBC/padding processing. HKDF-Expand uses
  separate `enc` and `mac` contexts. Account/per-item keys must be 64 bytes.
  Unsupported legacy unauthenticated formats and newer encryption-v2/COSE
  formats are not guessed or decrypted through fallback algorithms.
- Responses are bounded to 32 MiB, a cipher string to 4 MiB, records to 20,000,
  URIs to 100 per login, and custom fields to 128 per item. Malformed responses,
  duplicate IDs, invalid UTF-8, or bad MACs on parsed fields fail the transaction.
- Authenticator-app account 2FA is supported. Email/hardware-key/captcha/SSO and
  device approval flows are unsupported. No remembered-2FA device token is stored.
- The client issues only prelogin, token/refresh grants, and GET sync. It cannot
  create/edit/delete vault data. OAuth `api` tokens still have server-defined
  capabilities; **read-only UI is not a server-enforced read-only credential**.
- Organization, reprompt-protected, deleted, unknown-kind, and unsupported-cipher
  records are omitted with a count. Reprompt is not bypassed. Unknown ciphertext
  is retained only in the in-memory snapshot, never rewritten. Ignored fields
  (attachments, passkey key material, TOTP seeds/history, etc.) are not exposed.

## Lock and encrypted local cache

Persistence is opt-in, never applied to the fictional demo. The server snapshot
contains plaintext profile metadata in memory, but serialization is written only
inside device-layer ChaCha20-Poly1305 authenticated encryption. Version/header
are authenticated, each write gets a CSPRNG nonce, and keys are 32 random bytes.
No master password, raw user key, or access/refresh token enters the cache payload.
Without persistence, the earlier memory-only behavior remains available.

Directories/files must be owner-only (0700/0600), owned by the current UID,
regular/single-link files, and opened without following symlinks. Directory-relative
I/O pins a validated directory descriptor. Temporary files contain ciphertext
only, use exclusive random names, are synced before atomic rename, and are removed
on a cancelled/failed prepared write. Publication holds the session/state guard;
logout cannot be followed by a late worker republishing old account data.

The last authenticated current file becomes `vault.previous`. Truncated/tampered
current files may recover from that valid backup with a visible stale-data warning.
Unsafe permissions, unsupported versions, missing keys, and failed authentication
never silently become an empty vault. Future versions are not downgraded by backup
fallback. No anti-rollback guarantee is claimed; an old valid encrypted snapshot
can be replayed. Backup exclusion is best effort; disk encryption is not secure
erasure and APFS snapshots/backups may retain deleted ciphertext.

The outer cache key is stored in the ordinary non-synchronizing login Keychain,
not a shared access group. Its access is subject to macOS login-Keychain ACLs and
may prompt after ad-hoc rebuilds. It is not claimed to be hardware-bound or immune
to migration. Losing it makes that saved cache unreadable; re-login can redownload
server data. It must never be replaced automatically for an existing cache.

Lock drops decrypted records, live user key, and access/refresh tokens. The saved
cache restores locked after restart; master-password validation unwraps the user
key and authenticates item ciphertext. Cached unlock has no tokens, so online
sync requires fresh login. Explicit Forget attempts to delete exact current/backup
files and this app's cache/biometric Keychain entries. Failure is visible, not a
false guarantee of removal; server token revocation is not implemented.

## Optional biometric unlock

Enrollment is explicit, requires an unlocked real account and a saved cache,
and confirms biometrics. The account-bound credential includes a user key, so it
is stored **only** in the Data Protection Keychain with `biometryCurrentSet` and
device-only accessibility. Retrieval is gated by that ACL itself, not an LA dialog
followed by a read of an ordinary/unprotected key. No fallback silently weakens
the ACL. Missing signing entitlement/device support fails closed and leaves
master-password unlock available. Protected-key support for the current ad-hoc
configuration is not promised until interactively tested.

`-34018` is a confirmed missing access-group authorization, not a biometric
hardware failure. The optional `Development` configuration/`VaultwardenDevelopment`
scheme uses a locally selected Apple Development/Personal Team identity and
team-qualified group; no invented group is injected into ad-hoc signatures.
Certificate/team configuration remains local and ignored. CLI provisioning
updates require explicit `--provision`, and no Keychain secret is read by signing
verification. Account setup must be approved in Xcode by the owner.

The Rust bridge verifies credential version/length, account binding and a user-key
fingerprint before decrypting even an empty snapshot. Fingerprint enrollment changes
invalidate access. Lock invalidates the active LAContext; generation checks prevent
late unlocks and stale credential enrollment. Biometric bytes may pass through
Swift/FFI copies transiently; wiping owned buffers is not complete memory erasure.
The Secure Enclave is not claimed to store arbitrary portable Bitwarden keys.

## Current guarantees and limits

- Rust starts locked; list/detail/reveal/match operations check lock state. A
  state mutex protects reads/commits; poisoned state refuses further access.
- Rust-owned keys, tokens, field values, and summary buffers are zeroized on drop. This is
  **not complete memory erasure**: FFI serialization, returned Rust Strings,
  Swift Strings, and system credential objects may create additional copies.
- The Swift adapter clears items/selection/search/field descriptors/revealed values
  on lock; changing selection hides previous values. Field-descriptor APIs carry
  no secrets; secret values require explicit read/reveal/copy. No persistent
  credential-identity indexing exists.
- Clipboard copying uses a change-count/deadline rather than retaining the copied
  value in the clipboard service. It clears while ownership still matches on
  expiry, lock, or normal quit, and leaves later copies alone. The OS does not
  offer an atomic compare-and-clear transaction; a cross-process race remains
  possible. Clipboard data, Swift copies, and clipboard-manager histories are
  not guaranteed erased. Concealed/transient/Universal Clipboard exclusion
  markers are best effort; abrupt process termination can leave a copy behind.
- Global quick access registers only one exact shortcut through Carbon event
  hotkey APIs, with conflict reporting and explicit shutdown cleanup. It does not
  monitor arbitrary global key events, require Accessibility/Input Monitoring,
  inspect the foreground app, or inject input. Activity monitoring is app-local.
- Inactivity deadlines use monotonic process uptime and bounded safe preferences.
  Lifecycle hooks live in an app-owned runtime rather than a window. They still
  require interactive sleep/lock/multi-space testing before real-vault use.
  While unlocked, a scoped process activity prevents App Nap from deferring
  deadlines without preventing system sleep; lock/quit ends it. Wake also forces
  lock. Cleanup runs on the next timer turn, not a guaranteed realtime deadline;
  suspension or abrupt process termination can still prevent it.
- Demo unlock has **no authentication**. The UI labels it explicitly and only
  creates public fictional records. Do not reinterpret it as a secure unlock.
- The retained compile-only extension (not embedded in the app) starts each request locked, offers explicit selection, verifies
  the service/record match again before completion, and never silently returns
  credentials. A missing service list permits manual demo selection as specified
  by Apple's provider API; supplied services never fall back to unrelated items.
- The app and experimental extension use independent cores. No claim is made
  about cross-process locks, shared biometric credentials, authorization IPC, or provider activation.

## Endpoint privacy

Private endpoints belong in runtime configuration, not the public repository.
Use reserved `example.com`, `example.org`, `example.net`, or local mock hosts in
fixtures and documentation. Local environment/signing/config files and build
outputs are Git-ignored. Ignoring files is not an authorization mechanism or a
secret scanner: review staged files and logs before publishing.

Future live tests must be opt-in, use disposable accounts, redact endpoint/token
information, and never access a primary vault by default. PR CI must remain
fixture-only and receive no live-vault or signing secrets.

## Required before primary-vault use

Live disposable-account interoperability, interactive Keychain/biometric lifecycle
tests (including rebuilds/fingerprint changes), lifecycle/clipboard tests, cache migration review,
fuzzing and independent security review. Writes additionally require known-answer
encryption tests, revision-aware conflict handling and crash-safe mutations.
Native extension authentication,
cross-process shared locks, and passkey interoperability gates apply only if the
currently deferred provider scope is resumed. The
[initial plan](../plans/init.md) defines the remaining implementation gates.
