//! Typed read-only boundary. Blocking network/KDF calls belong on Swift workers.
//! UniFFI is not an IPC transport; lock generations protect late operation commits.

use std::sync::{Arc, Mutex, MutexGuard};
use zeroize::Zeroizing;

uniffi::setup_scaffolding!();

#[derive(Clone, Copy, uniffi::Enum)]
pub enum SessionState {
    Locked,
    DemoUnlocked,
    Unlocked,
}

#[derive(uniffi::Record)]
pub struct Session {
    pub state: SessionState,
    pub generation: u64,
}

impl From<vault_core::Session> for Session {
    fn from(value: vault_core::Session) -> Self {
        Self {
            state: match value.state {
                vault_core::SessionState::Locked => SessionState::Locked,
                vault_core::SessionState::DemoUnlocked => SessionState::DemoUnlocked,
                vault_core::SessionState::Unlocked => SessionState::Unlocked,
            },
            generation: value.generation,
        }
    }
}

#[derive(uniffi::Record)]
pub struct ItemSummary {
    pub id: String,
    pub title: String,
    pub username: String,
    pub website: String,
    pub favorite: bool,
    pub kind: ItemKind,
    pub has_passkey: bool,
    pub has_totp: bool,
}

#[derive(Clone, Copy, uniffi::Enum)]
pub enum ItemKind {
    Login,
    SecureNote,
    Card,
    Identity,
    SshKey,
}

impl From<vault_core::ItemKind> for ItemKind {
    fn from(value: vault_core::ItemKind) -> Self {
        match value {
            vault_core::ItemKind::Login => Self::Login,
            vault_core::ItemKind::SecureNote => Self::SecureNote,
            vault_core::ItemKind::Card => Self::Card,
            vault_core::ItemKind::Identity => Self::Identity,
            vault_core::ItemKind::SshKey => Self::SshKey,
        }
    }
}

impl From<vault_core::ItemSummary> for ItemSummary {
    fn from(value: vault_core::ItemSummary) -> Self {
        Self {
            id: value.id,
            title: value.title,
            username: value.username,
            website: value.website,
            favorite: value.favorite,
            kind: value.kind.into(),
            has_passkey: value.has_passkey,
            has_totp: value.has_totp,
        }
    }
}

#[derive(Debug, uniffi::Error)]
pub enum CoreError {
    Locked,
    NotFound,
    StaleSession,
    InvalidQuery,
    InvalidService,
    Unavailable,
    Busy,
    InvalidServer,
    InvalidInput,
    Network,
    AuthenticationFailed,
    SessionExpired,
    RateLimited,
    TwoFactorRequired { providers: Vec<u32> },
    UnsupportedChallenge,
    UnsupportedCrypto,
    DecryptionFailed,
    InvalidResponse,
    CacheUnavailable,
    CacheCorrupt,
    CacheVersion,
    CachePermissions,
}

impl std::fmt::Display for CoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Locked => "Vault is locked",
            Self::NotFound => "Item not found",
            Self::StaleSession => "Session changed; retry after unlocking",
            Self::InvalidQuery => "Search query is too long",
            Self::InvalidService => "Unsupported service identifier",
            Self::Unavailable => "Core is unavailable",
            Self::Busy => "Another vault operation is still running",
            Self::InvalidServer => "Enter a valid HTTPS server URL",
            Self::InvalidInput => "Check the login fields",
            Self::Network => "Could not connect securely to the server",
            Self::AuthenticationFailed => {
                "Login failed; check the account credentials or verification code"
            }
            Self::SessionExpired => "Session expired; sign in again",
            Self::RateLimited => "Server rate limit reached; try again later",
            Self::TwoFactorRequired { .. } => "Two-factor authentication required",
            Self::UnsupportedChallenge => {
                "This server requires an unsupported authentication challenge"
            }
            Self::UnsupportedCrypto => "Unsupported encryption or KDF parameters",
            Self::DecryptionFailed => "Could not authenticate and decrypt the vault",
            Self::InvalidResponse => "Server returned an incompatible response",
            Self::CacheUnavailable => "Local cache could not be read or saved",
            Self::CacheCorrupt => "Local cache authentication failed; no vault data was opened",
            Self::CacheVersion => {
                "This cache version is unsupported; update the app before opening it"
            }
            Self::CachePermissions => "Local cache permissions or file type are unsafe",
        })
    }
}

impl std::error::Error for CoreError {}

impl From<vault_storage::StorageError> for CoreError {
    fn from(error: vault_storage::StorageError) -> Self {
        use vault_storage::StorageError as S;
        match error {
            S::Corrupt | S::InvalidKey => Self::CacheCorrupt,
            S::UnsupportedVersion => Self::CacheVersion,
            S::Permissions => Self::CachePermissions,
            S::Io | S::TooLarge | S::Entropy => Self::CacheUnavailable,
        }
    }
}

impl From<vault_api::ApiError> for CoreError {
    fn from(error: vault_api::ApiError) -> Self {
        use vault_api::ApiError as A;
        use vault_core::crypto::CryptoError as C;
        match error {
            A::InvalidServer => Self::InvalidServer,
            A::InvalidInput => Self::InvalidInput,
            A::Network => Self::Network,
            A::AuthenticationFailed => Self::AuthenticationFailed,
            A::SessionExpired | A::KeyChanged => Self::SessionExpired,
            A::RateLimited => Self::RateLimited,
            A::TwoFactorRequired(providers) => Self::TwoFactorRequired { providers },
            A::UnsupportedChallenge => Self::UnsupportedChallenge,
            A::Crypto(C::UnsupportedKdf | C::UnsafeKdf | C::UnsupportedCipher) => {
                Self::UnsupportedCrypto
            }
            A::Crypto(_) => Self::DecryptionFailed,
            A::MalformedResponse | A::Rejected => Self::InvalidResponse,
            A::Cancelled => Self::StaleSession,
        }
    }
}

#[derive(uniffi::Record)]
pub struct FieldInfo {
    pub id: String,
    pub label: String,
    pub is_secret: bool,
}

#[derive(uniffi::Record)]
pub struct AccountStatus {
    pub has_cached_vault: bool,
    pub can_sync: bool,
    pub omitted_items: u32,
    pub cache_saved: bool,
    pub recovered_cache: bool,
}

#[derive(Default)]
struct ClientState {
    vault: vault_core::Vault,
    account: Option<vault_api::LockedAccount>,
    live: Option<vault_api::LiveSession>,
    omitted: u32,
    unlocked_key: Option<vault_core::crypto::UserKey>,
    cache: Option<vault_storage::CacheStore>,
    cache_saved: bool,
    recovered_cache: bool,
}

impl From<vault_core::VaultError> for CoreError {
    fn from(value: vault_core::VaultError) -> Self {
        match value {
            vault_core::VaultError::Locked => Self::Locked,
            vault_core::VaultError::NotFound => Self::NotFound,
            vault_core::VaultError::StaleSession => Self::StaleSession,
            vault_core::VaultError::InvalidQuery => Self::InvalidQuery,
            vault_core::VaultError::InvalidService => Self::InvalidService,
        }
    }
}

#[derive(uniffi::Object)]
pub struct VaultClient {
    state: Mutex<ClientState>,
    operation: Mutex<()>,
}

impl VaultClient {
    fn guarded(&self) -> Result<MutexGuard<'_, ClientState>, CoreError> {
        // A poisoned core fails closed; never ignore a panic and return secrets.
        self.state.lock().map_err(|_| CoreError::Unavailable)
    }

    fn operation(&self) -> Result<MutexGuard<'_, ()>, CoreError> {
        self.operation.try_lock().map_err(|error| match error {
            std::sync::TryLockError::WouldBlock => CoreError::Busy,
            std::sync::TryLockError::Poisoned(_) => CoreError::Unavailable,
        })
    }

    fn validate_generation(&self, expected: u64) -> Result<(), CoreError> {
        if self.guarded()?.vault.session().generation != expected {
            return Err(CoreError::StaleSession);
        }
        Ok(())
    }

    fn commit(&self, loaded: vault_api::LoadedVault, expected: u64) -> Result<Session, CoreError> {
        let mut state = self.guarded()?;
        if state.vault.session().generation != expected {
            return Err(CoreError::StaleSession);
        }
        state.account = Some(loaded.account);
        state.live = loaded.live;
        state.omitted = loaded.omitted;
        state.unlocked_key = Some(loaded.key);
        Ok(state.vault.install(loaded.items).into())
    }
}

#[uniffi::export]
impl VaultClient {
    #[uniffi::constructor]
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(ClientState::default()),
            operation: Mutex::new(()),
        })
    }

    pub fn session(&self) -> Result<Session, CoreError> {
        Ok(self.guarded()?.vault.session().into())
    }

    pub fn unlock_demo(&self) -> Result<Session, CoreError> {
        let mut state = self.guarded()?;
        if state.account.is_some() || state.cache_saved {
            return Err(CoreError::InvalidInput);
        }
        state.account = None;
        state.live = None;
        state.unlocked_key = None;
        state.omitted = 0;
        Ok(state.vault.unlock_demo().into())
    }

    pub fn lock(&self) -> Result<Session, CoreError> {
        let mut state = self.guarded()?;
        state.live = None;
        state.unlocked_key = None;
        Ok(state.vault.lock().into())
    }

    pub fn search(&self, query: String) -> Result<Vec<ItemSummary>, CoreError> {
        Ok(self
            .guarded()?
            .vault
            .search(&query)?
            .into_iter()
            .map(Into::into)
            .collect())
    }

    pub fn item(&self, id: String) -> Result<ItemSummary, CoreError> {
        Ok(self.guarded()?.vault.item(&id)?.into())
    }

    pub fn reveal_password(
        &self,
        id: String,
        expected_generation: u64,
    ) -> Result<String, CoreError> {
        Ok(self
            .guarded()?
            .vault
            .reveal_password(&id, expected_generation)?)
    }

    pub fn match_service(&self, service: String) -> Result<Vec<ItemSummary>, CoreError> {
        Ok(self
            .guarded()?
            .vault
            .match_service(&service)?
            .into_iter()
            .map(Into::into)
            .collect())
    }

    pub fn fields(&self, id: String) -> Result<Vec<FieldInfo>, CoreError> {
        Ok(self
            .guarded()?
            .vault
            .fields(&id)?
            .into_iter()
            .map(|field| FieldInfo {
                id: field.id,
                label: field.label,
                is_secret: field.is_secret,
            })
            .collect())
    }

    pub fn read_field(
        &self,
        id: String,
        field_id: String,
        expected_generation: u64,
    ) -> Result<String, CoreError> {
        Ok(self
            .guarded()?
            .vault
            .read_field(&id, &field_id, expected_generation)?)
    }

    pub fn account_status(&self) -> Result<AccountStatus, CoreError> {
        let state = self.guarded()?;
        Ok(AccountStatus {
            has_cached_vault: state.account.is_some(),
            can_sync: state.live.is_some(),
            omitted_items: state.omitted,
            cache_saved: state.cache_saved,
            recovered_cache: state.recovered_cache,
        })
    }

    pub fn logout(&self) -> Result<Session, CoreError> {
        let generation = self.guarded()?.vault.session().generation;
        self.logout_if_current(generation)
    }

    pub fn logout_if_current(&self, expected_generation: u64) -> Result<Session, CoreError> {
        let mut state = self.guarded()?;
        if state.vault.session().generation != expected_generation {
            return Err(CoreError::StaleSession);
        }
        // Revoke UI/worker access before any filesystem failure can occur.
        let session = state.vault.lock();
        state.account = None;
        state.live = None;
        state.unlocked_key = None;
        state.omitted = 0;
        state.cache_saved = false;
        state.recovered_cache = false;
        if let Some(cache) = &state.cache {
            cache.clear()?;
        }
        state.cache = None;
        Ok(session.into())
    }

    /// Blocking work: Swift must call on a worker, never on its main actor.
    /// The caller's lock generation also prevents a queued request resurrecting a vault.
    pub fn login(
        &self,
        server: String,
        email: String,
        password: String,
        two_factor_code: Option<String>,
        expected_generation: u64,
    ) -> Result<Session, CoreError> {
        let password = Zeroizing::new(password);
        let code = two_factor_code.map(Zeroizing::new);
        let _operation = self.operation()?;
        {
            let mut state = self.guarded()?;
            if state.vault.session().generation != expected_generation
                || state.vault.session().state != vault_core::SessionState::Locked
            {
                return Err(CoreError::StaleSession);
            }
            if state.account.is_some() || state.cache_saved {
                return Err(CoreError::InvalidInput);
            }
            state.account = None;
            state.live = None;
            state.unlocked_key = None;
        }
        let loaded = vault_api::login(
            &server,
            &email,
            &password,
            code.as_deref().map(|s| s.as_str()),
            &|| self.validate_generation(expected_generation).is_ok(),
        )?;
        self.commit(loaded, expected_generation)
    }

    pub fn unlock_cached(
        &self,
        password: String,
        expected_generation: u64,
    ) -> Result<Session, CoreError> {
        let password = Zeroizing::new(password);
        let _operation = self.operation()?;
        self.validate_generation(expected_generation)?;
        let account = self.guarded()?.account.clone().ok_or(CoreError::NotFound)?;
        let loaded = account.unlock(&password, &|| {
            self.validate_generation(expected_generation).is_ok()
        })?;
        self.commit(loaded, expected_generation)
    }

    pub fn sync(&self, expected_generation: u64) -> Result<Session, CoreError> {
        let _operation = self.operation()?;
        let (account, live) = {
            let state = self.guarded()?;
            if state.vault.session().generation != expected_generation {
                return Err(CoreError::StaleSession);
            }
            if state.vault.session().state != vault_core::SessionState::Unlocked {
                return Err(CoreError::Locked);
            }
            (
                state.account.clone().ok_or(CoreError::NotFound)?,
                state.live.clone().ok_or(CoreError::SessionExpired)?,
            )
        };
        self.commit(
            live.sync(&account, &|| {
                self.validate_generation(expected_generation).is_ok()
            })?,
            expected_generation,
        )
    }

    pub fn new_cache_key(&self) -> Result<Vec<u8>, CoreError> {
        Ok(vault_storage::CacheStore::random_key()?)
    }

    pub fn discard_saved_cache(
        &self,
        directory: String,
        expected_generation: u64,
    ) -> Result<(), CoreError> {
        let _operation = self.operation()?;
        let state = self.guarded()?;
        if state.vault.session().generation != expected_generation {
            return Err(CoreError::StaleSession);
        }
        if state.vault.session().state != vault_core::SessionState::Locked
            || state.account.is_some()
        {
            return Err(CoreError::InvalidInput);
        }
        // No key is needed to unlink exact cache names. Never decrypt/rewrite
        // with this dummy key and never recursively delete the directory.
        let store = vault_storage::CacheStore::new(std::path::Path::new(&directory), &[0u8; 32])?;
        store.clear()?;
        Ok(())
    }

    /// This key protects only cache metadata and server ciphertext, not the
    /// plaintext vault. Never supply a biometric user key as a cache device key.
    pub fn configure_cache(
        &self,
        directory: String,
        device_key: Vec<u8>,
        expected_generation: u64,
    ) -> Result<(), CoreError> {
        let device_key = Zeroizing::new(device_key);
        let _operation = self.operation()?;
        self.validate_generation(expected_generation)?;
        let cache = vault_storage::CacheStore::new(std::path::Path::new(&directory), &device_key)?;
        let mut state = self.guarded()?;
        if state.vault.session().generation != expected_generation {
            return Err(CoreError::StaleSession);
        }
        state.cache = Some(cache);
        Ok(())
    }

    pub fn restore_cache(&self, expected_generation: u64) -> Result<Session, CoreError> {
        let _operation = self.operation()?;
        let cache = {
            let state = self.guarded()?;
            if state.vault.session().generation != expected_generation {
                return Err(CoreError::StaleSession);
            }
            if state.vault.session().state != vault_core::SessionState::Locked
                || state.account.is_some()
            {
                return Err(CoreError::InvalidInput);
            }
            state.cache.clone().ok_or(CoreError::CacheUnavailable)?
        };
        let loaded = cache.load()?.ok_or(CoreError::NotFound)?;
        let account = vault_api::LockedAccount::from_cache(&loaded.payload)?;
        let mut state = self.guarded()?;
        if state.vault.session().generation != expected_generation {
            return Err(CoreError::StaleSession);
        }
        state.account = Some(account);
        state.cache_saved = true;
        state.recovered_cache = loaded.recovered;
        Ok(state.vault.session().into()) // Still locked; a password/ACL-protected key is required.
    }

    pub fn save_cache(&self, expected_generation: u64) -> Result<(), CoreError> {
        let _operation = self.operation()?;
        let (cache, account) = {
            let state = self.guarded()?;
            if state.vault.session().generation != expected_generation {
                return Err(CoreError::StaleSession);
            }
            if state.vault.session().state != vault_core::SessionState::Unlocked {
                return Err(CoreError::Locked);
            }
            (
                state.cache.clone().ok_or(CoreError::CacheUnavailable)?,
                state.account.clone().ok_or(CoreError::NotFound)?,
            )
        };
        let payload = account.cache_bytes()?;
        let prepared = cache.prepare(&payload)?;
        let mut state = self.guarded()?;
        if state.vault.session().generation != expected_generation {
            return Err(CoreError::StaleSession);
        }
        prepared.publish()?; // Guard is held through atomic publication, not bulk encryption/I/O.
        state.cache_saved = true;
        state.recovered_cache = false;
        Ok(())
    }

    pub fn biometric_material(&self, expected_generation: u64) -> Result<Vec<u8>, CoreError> {
        let state = self.guarded()?;
        if state.vault.session().generation != expected_generation {
            return Err(CoreError::StaleSession);
        }
        if state.vault.session().state != vault_core::SessionState::Unlocked || !state.cache_saved {
            return Err(CoreError::Locked);
        }
        let account = state.account.as_ref().ok_or(CoreError::NotFound)?;
        let key = state.unlocked_key.as_ref().ok_or(CoreError::Locked)?;
        let mut material = b"VWBIO1\0\0".to_vec();
        material.extend_from_slice(&account.binding()?);
        material.extend_from_slice(&key.encoded());
        Ok(material)
    }

    pub fn unlock_biometric(
        &self,
        material: Vec<u8>,
        expected_generation: u64,
    ) -> Result<Session, CoreError> {
        use subtle::ConstantTimeEq;
        let material = Zeroizing::new(material);
        let _operation = self.operation()?;
        self.validate_generation(expected_generation)?;
        if material.len() != 104 || &material[..8] != b"VWBIO1\0\0" {
            return Err(CoreError::InvalidInput);
        }
        let account = self.guarded()?.account.clone().ok_or(CoreError::NotFound)?;
        if !bool::from(account.binding()?.ct_eq(&material[8..40])) {
            return Err(CoreError::AuthenticationFailed);
        }
        let key = vault_core::crypto::UserKey::from_bytes(Zeroizing::new(material[40..].to_vec()))
            .map_err(|_| CoreError::DecryptionFailed)?;
        self.commit(
            account.unlock_with_key(key, &|| {
                self.validate_generation(expected_generation).is_ok()
            })?,
            expected_generation,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn fixture_account() -> Result<vault_api::LockedAccount, CoreError> {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../../../tests/fixtures/read-only.json"))
                .map_err(|_| CoreError::InvalidResponse)?;
        let email = fixture["email"]
            .as_str()
            .ok_or(CoreError::InvalidResponse)?;
        let password = fixture["password"]
            .as_str()
            .ok_or(CoreError::InvalidResponse)?;
        let wrapped = fixture["tokens"]["Key"]
            .as_str()
            .ok_or(CoreError::InvalidResponse)?;
        let kdf = vault_core::crypto::KdfParameters {
            kind: 0,
            iterations: 10000,
            memory_mib: None,
            parallelism: None,
        };
        let key = vault_core::crypto::MasterKey::derive(password, email, kdf)
            .map_err(|_| CoreError::DecryptionFailed)?
            .unwrap_user_key(wrapped)
            .map_err(|_| CoreError::DecryptionFailed)?;
        let payload = serde_json::json!({"version":1, "email":email, "kdf":kdf,
            "protected_key": wrapped, "encrypted_snapshot":fixture["sync"], "user_key_fingerprint":key.fingerprint()});
        Ok(vault_api::LockedAccount::from_cache(
            payload.to_string().as_bytes(),
        )?)
    }

    #[test]
    fn disk_restart_stays_locked_and_biometric_material_is_account_bound() -> Result<(), CoreError>
    {
        let directory = tempfile::tempdir().map_err(|_| CoreError::CacheUnavailable)?;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
            .map_err(|_| CoreError::CacheUnavailable)?;
        let path = directory
            .path()
            .to_str()
            .ok_or(CoreError::CacheUnavailable)?
            .to_owned();
        let client = VaultClient::new();
        client.configure_cache(path.clone(), vec![42; 32], 0)?;
        let account = fixture_account()?;
        let loaded = account.unlock("PUBLIC-FIXTURE-password-not-for-real-use", &|| true)?;
        client.commit(loaded, 0)?;
        client.save_cache(0)?;
        let material = client.biometric_material(0)?;
        client.lock()?;
        assert!(matches!(
            client.biometric_material(client.session()?.generation),
            Err(CoreError::Locked)
        ));
        let restarted = VaultClient::new();
        restarted.configure_cache(path, vec![42; 32], 0)?;
        restarted.restore_cache(0)?;
        assert!(matches!(restarted.session()?.state, SessionState::Locked));
        assert!(matches!(
            restarted.search(String::new()),
            Err(CoreError::Locked)
        ));
        assert!(matches!(
            restarted.unlock_cached("wrong-public-password".into(), 0),
            Err(CoreError::DecryptionFailed)
        ));
        let mut stale = material.clone();
        stale[8] ^= 1;
        assert!(matches!(
            restarted.unlock_biometric(stale, 0),
            Err(CoreError::AuthenticationFailed)
        ));
        restarted.unlock_biometric(material, 0)?;
        assert_eq!(restarted.search(String::new())?.len(), 5);
        restarted.logout()?;
        assert!(!restarted.account_status()?.has_cached_vault);
        assert!(!directory.path().join("vault.cache").exists());
        assert!(!directory.path().join("vault.previous").exists());
        Ok(())
    }

    #[test]
    fn save_and_restore_reject_late_generations_without_publishing() -> Result<(), CoreError> {
        let directory = tempfile::tempdir().map_err(|_| CoreError::CacheUnavailable)?;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
            .map_err(|_| CoreError::CacheUnavailable)?;
        let client = VaultClient::new();
        client.configure_cache(
            directory
                .path()
                .to_str()
                .ok_or(CoreError::CacheUnavailable)?
                .into(),
            vec![42; 32],
            0,
        )?;
        client.commit(
            fixture_account()?.unlock("PUBLIC-FIXTURE-password-not-for-real-use", &|| true)?,
            0,
        )?;
        client.lock()?;
        assert!(matches!(client.save_cache(0), Err(CoreError::StaleSession)));
        assert!(!directory.path().join("vault.cache").exists());
        assert!(matches!(
            client.restore_cache(0),
            Err(CoreError::StaleSession)
        ));
        Ok(())
    }

    #[test]
    fn queued_login_cannot_start_after_lock_or_logout() -> Result<(), CoreError> {
        let client = VaultClient::new();
        let old = client.session()?.generation;
        client.logout()?;
        // Must reject before constructing any HTTP client/request.
        assert!(matches!(
            client.login(
                "https://example.com".into(),
                "public@example.com".into(),
                "public-not-real".into(),
                None,
                old
            ),
            Err(CoreError::StaleSession)
        ));
        Ok(())
    }

    #[test]
    fn overlapping_operations_fail_without_waiting_or_network() -> Result<(), CoreError> {
        let client = VaultClient::new();
        let _guard = client.operation()?;
        assert!(matches!(
            client.login(
                "https://example.com".into(),
                "public@example.com".into(),
                "public-not-real".into(),
                None,
                0
            ),
            Err(CoreError::Busy)
        ));
        Ok(())
    }

    #[test]
    fn real_session_fields_are_descriptors_until_explicit_read() -> Result<(), CoreError> {
        let client = VaultClient::new();
        let item = vault_core::VaultItem::new(
            vault_core::ItemSummary {
                id: "public-card".into(),
                title: "Public fixture".into(),
                username: String::new(),
                website: String::new(),
                favorite: false,
                kind: vault_core::ItemKind::Card,
                has_passkey: false,
                has_totp: false,
            },
            vec![vault_core::SecretField::new(
                "number".into(),
                "Card number".into(),
                true,
                Zeroizing::new("4111111111111111".into()),
            )],
        );
        client.guarded()?.vault.install(vec![item]);
        let generation = client.session()?.generation;
        let fields = client.fields("public-card".into())?;
        assert_eq!(fields.len(), 1);
        assert!(fields[0].is_secret);
        assert_eq!(
            client.read_field("public-card".into(), "number".into(), generation)?,
            "4111111111111111"
        );
        client.lock()?;
        assert!(matches!(
            client.fields("public-card".into()),
            Err(CoreError::Locked)
        ));
        assert!(matches!(
            client.read_field("public-card".into(), "number".into(), generation),
            Err(CoreError::Locked)
        ));
        Ok(())
    }

    #[test]
    fn ffi_errors_are_structured_and_lock_is_enforced() -> Result<(), CoreError> {
        let client = VaultClient::new();
        assert!(matches!(
            client.search(String::new()),
            Err(CoreError::Locked)
        ));
        let session = client.unlock_demo()?;
        assert_eq!(client.search(String::new())?.len(), 3);
        assert!(matches!(
            client.item("missing".into()),
            Err(CoreError::NotFound)
        ));
        client.lock()?;
        assert!(matches!(
            client.reveal_password("demo-example".into(), session.generation),
            Err(CoreError::Locked)
        ));
        Ok(())
    }

    #[test]
    fn independent_clients_never_share_unlock_state() -> Result<(), CoreError> {
        let app = VaultClient::new();
        let extension = VaultClient::new();
        app.unlock_demo()?;
        assert!(matches!(
            extension.search(String::new()),
            Err(CoreError::Locked)
        ));
        Ok(())
    }

    #[test]
    fn poisoned_core_fails_closed() {
        let client = VaultClient::new();
        let result = std::panic::catch_unwind(|| {
            let Ok(_guard) = client.state.lock() else {
                return;
            };
            panic!("synthetic core failure");
        });
        assert!(result.is_err());
        assert!(matches!(client.unlock_demo(), Err(CoreError::Unavailable)));
        assert!(matches!(
            client.search(String::new()),
            Err(CoreError::Unavailable)
        ));
        assert!(matches!(
            client.reveal_password("demo-example".into(), 0),
            Err(CoreError::Unavailable)
        ));
    }

    #[test]
    fn concurrent_lock_calls_are_serialized() -> Result<(), CoreError> {
        let client = VaultClient::new();
        let workers: Vec<_> = (0..8)
            .map(|_| {
                let client = Arc::clone(&client);
                std::thread::spawn(move || -> Result<(), CoreError> {
                    for _ in 0..50 {
                        client.lock()?;
                    }
                    Ok(())
                })
            })
            .collect();
        for worker in workers {
            worker.join().map_err(|_| CoreError::Unavailable)??;
        }
        assert_eq!(client.session()?.generation, 400);
        assert!(matches!(
            client.search(String::new()),
            Err(CoreError::Locked)
        ));
        Ok(())
    }
}
