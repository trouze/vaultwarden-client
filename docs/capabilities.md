# Standalone read-only capability matrix

Product scope: no Developer ID certification/notarization or browser extension
planned. Native password/passkey provider activation is deferred. The normal
Xcode scheme builds only an ad-hoc-signed standalone app, not the extension.

| Capability | Implemented | Validation / limit |
| --- | --- | --- |
| Rust → Swift UniFFI boundary | Yes | Generated bindings/static library; executable smoke tests. |
| Vault list/search/detail/reveal | Personal records | Login/note/card/identity/SSH/custom fields; secret descriptors separate from explicit value reads. No editing. |
| Three-column vault layout | Yes | Category sidebar → sorted middle list → copyable details. Toolbar search/lock/sync and joined glass Add/Sort pill. Add remains disabled. |
| Category tiles | Yes | Rust-backed type/capability metadata and search-independent counts. Passkeys/Codes grouping does not implement authentication/code generation. |
| Quick-access panel | Yes | Independent query/category, arrow selection, click/Return password copy, Option-click/Option-Return username copy, Escape/click-away dismissal. Nonactivating AppKit panel. |
| Click-to-copy field boxes | Yes | Username/website/password fields are full-box accessible buttons; reveal remains separate and no password is exposed in accessibility metadata. |
| Global shortcut | Yes | ⌃⇧Space or ⌃⌥Space; opt-out/conflict reporting. No Accessibility/Input Monitoring. Interactive registration/Spaces testing remains necessary. |
| Credential clipboard copy | Yes | 15/30/60-second expiration, change-count ownership, clearing on lock/normal quit. Isolated native pasteboard and deterministic deadline tests. |
| Clipboard history / Universal Clipboard exclusion | Best effort | Writes exclusion markers; cannot guarantee every clipboard tool honors them. |
| Inactivity lock | Yes | 1/5/15-minute app-interaction timeout, default five. Monotonic clock tests; does not observe typing in other apps. |
| Sleep / session-deactivation lock | App runtime hooks | No longer tied to a window; interactive lifecycle testing remains necessary. |
| Lock/session invalidation | Yes, in-process demo | Drops picker/view state, clears owned clipboard, denies locked reads. |
| Native app bundle | Yes | CLI and full Xcode ad-hoc builds pass without a paid team. Rust/native TLS objects target macOS 26 consistently. No notarization. |
| Menu bar / ⌘L / settings | Yes | Quick-access entry and safe persisted non-sensitive settings. |
| Native Credential Provider | Compile-only scaffold | Separate experimental scheme, not embedded or activated; not a reader acceptance gate. |
| Native passkeys / TOTP provider | Deferred | Not advertised or implemented; no paid capability plan. |
| Browser extension / Accessibility auto-type | Not planned | Manual search-and-copy is the active integration strategy. |
| Password login / authenticator-code 2FA | Implemented, mock-tested | Runtime-only HTTPS configuration, locally derived auth hash, structured challenge. Other 2FA/SSO/captcha/device approval unsupported. |
| Encrypted personal sync / token refresh | Implemented, mock-tested | PBKDF2/Argon2id, HKDF, type-2 cipher strings/account/per-item keys; atomic commit and cancellation generations. No live interoperability test yet. |
| Cached offline unlock / restart | Yes, opt-in persistence | Restore stays locked; master-password verification. Outer device AEAD hides metadata/ciphertext, atomic saves and visible last-good recovery. No stored tokens; fresh login for sync. |
| Organizations / reprompt / trash / newer cipher versions | Unsupported | Omitted with a count; corrupt parsed MACs reject the transaction. No unsafe fallback or rewriting. |
| Persistent encrypted cache | Implemented/tested | CSPRNG ChaCha20-Poly1305, owner-only anchored filesystem operations, tamper/size/version checks and stale-write rejection. No plaintext temp files. |
| Keychain metadata key | Implemented, interactive validation pending | Ordinary non-synchronizing login Keychain. No master/user keys in that entry; ad-hoc rebuild approval may be required. |
| Touch ID user-key unlock | Optional implementation, interactive validation pending | Data Protection Keychain `biometryCurrentSet` ACL only; account/key binding, no weak fallback. OS/signing restrictions may make enrollment unavailable. |
| SSH agent | Future work | Independent of paid Apple provider signing. |
| Signed/notarized releases / Homebrew | Deferred | No Developer ID certification plan. |

## Next standalone validation steps

1. Generate the project and build/run the standalone `VaultwardenClient` scheme
   without a development team; full Xcode is now available for local validation.
2. Test the global shortcut, repeated opening/dismissal, search-field focus,
   shortcut conflicts, fullscreen/Spaces, and focus returning to the target app.
3. Test clipboard expiration and manual/idle/sleep lock with the main window
   closed. The menu bar runtime must remain responsible for security services.
4. Validate disposable-account live interoperability without disclosing endpoints
   or credentials, then interactively validate Keychain ACLs, ad-hoc rebuild behavior,
   biometric cancellation/enrollment changes and persistent-cache recovery.
5. Security review before loading a primary vault. Provider/passkey/shared-state
   gates apply only if that deferred scope is explicitly resumed later.
