//! Read-only password-grant and encrypted sync adapter. No vault mutations.

use reqwest::blocking::{Client, Response};
use serde_json::{json, Value};
use std::{io::Read, time::Duration};
use url::Url;
use vault_core::{
    crypto::{CryptoError, KdfParameters, MasterKey, UserKey},
    ItemKind, ItemSummary, SecretField, VaultItem,
};
use zeroize::Zeroizing;

const MAX_RESPONSE: usize = 32 * 1024 * 1024;

#[derive(Debug, PartialEq, Eq)]
pub enum ApiError {
    InvalidServer,
    InvalidInput,
    Network,
    Rejected,
    AuthenticationFailed,
    SessionExpired,
    RateLimited,
    TwoFactorRequired(Vec<u32>),
    UnsupportedChallenge,
    MalformedResponse,
    Crypto(CryptoError),
    KeyChanged,
    Cancelled,
}

impl From<CryptoError> for ApiError {
    fn from(value: CryptoError) -> Self {
        Self::Crypto(value)
    }
}

#[derive(Clone)]
struct Api {
    base: Url,
    client: Client,
}

#[derive(Clone)]
pub struct LockedAccount {
    email: String,
    kdf: KdfParameters,
    protected_key: String,
    encrypted_snapshot: Value,
    user_key_fingerprint: [u8; 32],
}

#[derive(Clone)]
pub struct LiveSession {
    api: Api,
    access_token: Zeroizing<String>,
    refresh_token: Zeroizing<String>,
    user_key: UserKey,
}

pub struct LoadedVault {
    pub items: Vec<VaultItem>,
    pub account: LockedAccount,
    pub live: Option<LiveSession>,
    pub omitted: u32,
    pub key: UserKey,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct CachedAccount {
    version: u32,
    email: String,
    kdf: KdfParameters,
    protected_key: String,
    encrypted_snapshot: Value,
    user_key_fingerprint: [u8; 32],
}

fn property<'a>(value: &'a Value, name: &str) -> Option<&'a Value> {
    value
        .as_object()?
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value)
}

fn string<'a>(value: &'a Value, name: &str) -> Option<&'a str> {
    property(value, name)?.as_str()
}

fn number(value: &Value, name: &str) -> Option<u32> {
    property(value, name)?
        .as_u64()
        .and_then(|n| n.try_into().ok())
}

fn take_string(value: &mut Value, name: &str) -> Option<Zeroizing<String>> {
    let key = value
        .as_object()?
        .keys()
        .find(|key| key.eq_ignore_ascii_case(name))?
        .clone();
    let removed = value.as_object_mut()?.remove(&key)?;
    match removed {
        Value::String(s) if !s.is_empty() => Some(Zeroizing::new(s)),
        _ => None,
    }
}

impl Api {
    fn new(server: &str) -> Result<Self, ApiError> {
        let mut base = Url::parse(server.trim()).map_err(|_| ApiError::InvalidServer)?;
        if base.scheme() != "https"
            || base.host_str().is_none()
            || !base.username().is_empty()
            || base.password().is_some()
            || base.query().is_some()
            || base.fragment().is_some()
        {
            return Err(ApiError::InvalidServer);
        }
        if !base.path().ends_with('/') {
            base.set_path(&format!("{}/", base.path()));
        }
        Self::with_base(base)
    }

    fn with_base(base: Url) -> Result<Self, ApiError> {
        let client = Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(30))
            .no_proxy()
            .user_agent("Vaultwarden/0.1.0")
            .build()
            .map_err(|_| ApiError::Network)?;
        Ok(Self { base, client })
    }

    fn endpoint(&self, path: &str) -> Result<Url, ApiError> {
        self.base.join(path).map_err(|_| ApiError::InvalidServer)
    }

    fn prelogin(&self, email: &str) -> Result<KdfParameters, ApiError> {
        let response = self
            .client
            .post(self.endpoint("api/accounts/prelogin")?)
            .json(&json!({"email": email}))
            .send()
            .map_err(|_| ApiError::Network)?;
        let value = successful_json(response)?;
        Ok(KdfParameters {
            kind: number(&value, "kdf").ok_or(ApiError::MalformedResponse)?,
            iterations: number(&value, "kdfIterations").ok_or(ApiError::MalformedResponse)?,
            memory_mib: number(&value, "kdfMemory"),
            parallelism: number(&value, "kdfParallelism"),
        })
    }

    fn token(&self, email: &str, hash: &str, code: Option<&str>) -> Result<Value, ApiError> {
        let device = uuid::Uuid::new_v4().to_string();
        let mut form = vec![
            ("grant_type", "password"),
            ("username", email),
            ("password", hash),
            ("scope", "api offline_access"),
            ("client_id", "desktop"),
            ("deviceType", "7"),
            ("deviceIdentifier", &device),
            ("deviceName", "Vaultwarden"),
        ];
        if let Some(code) = code {
            form.extend([
                ("twoFactorProvider", "0"),
                ("twoFactorToken", code),
                ("twoFactorRemember", "0"),
            ]);
        }
        let response = self
            .client
            .post(self.endpoint("identity/connect/token")?)
            .form(&form)
            .send()
            .map_err(|_| ApiError::Network)?;
        let status = response.status();
        if status.as_u16() == 429 {
            return Err(ApiError::RateLimited);
        }
        if status.is_redirection() {
            return Err(ApiError::Rejected);
        }
        let value = bounded_json(response)?;
        if status.is_success() {
            return Ok(value);
        }
        if property(&value, "captchaSiteKey").is_some_and(|v| !v.is_null()) {
            return Err(ApiError::UnsupportedChallenge);
        }
        let mut providers = Vec::new();
        if let Some(array) = property(&value, "twoFactorProviders").and_then(Value::as_array) {
            providers.extend(
                array
                    .iter()
                    .filter_map(Value::as_u64)
                    .filter_map(|n| u32::try_from(n).ok()),
            );
        }
        if let Some(object) = property(&value, "twoFactorProviders2").and_then(Value::as_object) {
            providers.extend(object.keys().filter_map(|key| key.parse::<u32>().ok()));
        }
        providers.sort_unstable();
        providers.dedup();
        if !providers.is_empty() {
            return Err(ApiError::TwoFactorRequired(providers));
        }
        if status.is_client_error() {
            Err(ApiError::AuthenticationFailed)
        } else {
            Err(ApiError::Rejected)
        }
    }

    fn sync(&self, token: &str) -> Result<Value, ApiError> {
        let response = self
            .client
            .get(self.endpoint("api/sync?excludeDomains=true")?)
            .bearer_auth(token)
            .send()
            .map_err(|_| ApiError::Network)?;
        if response.status().as_u16() == 401 {
            // Consume the bounded error body before retrying authentication so
            // connection teardown does not race a subsequent request.
            let _ = bounded_json(response);
            return Err(ApiError::SessionExpired);
        }
        successful_json(response)
    }

    fn refresh(&self, token: &str) -> Result<Value, ApiError> {
        let response = self
            .client
            .post(self.endpoint("identity/connect/token")?)
            .form(&[
                ("grant_type", "refresh_token"),
                ("refresh_token", token),
                ("client_id", "desktop"),
            ])
            .send()
            .map_err(|_| ApiError::Network)?;
        if response.status().is_client_error() {
            return Err(ApiError::SessionExpired);
        }
        successful_json(response)
    }
}

fn bounded_json(response: Response) -> Result<Value, ApiError> {
    if response
        .content_length()
        .is_some_and(|n| n > MAX_RESPONSE as u64)
    {
        return Err(ApiError::MalformedResponse);
    }
    let mut bytes = Zeroizing::new(Vec::new());
    response
        .take((MAX_RESPONSE + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| ApiError::Network)?;
    if bytes.len() > MAX_RESPONSE {
        return Err(ApiError::MalformedResponse);
    }
    serde_json::from_slice(&bytes).map_err(|_| ApiError::MalformedResponse)
}

fn successful_json(response: Response) -> Result<Value, ApiError> {
    let status = response.status();
    if status.as_u16() == 429 {
        return Err(ApiError::RateLimited);
    }
    if !status.is_success() {
        return Err(ApiError::Rejected);
    }
    bounded_json(response)
}

pub fn login(
    server: &str,
    email: &str,
    password: &str,
    code: Option<&str>,
    current: &dyn Fn() -> bool,
) -> Result<LoadedVault, ApiError> {
    login_with_api(Api::new(server)?, email, password, code, current)
}

fn check_current(current: &dyn Fn() -> bool) -> Result<(), ApiError> {
    if current() {
        Ok(())
    } else {
        Err(ApiError::Cancelled)
    }
}

fn login_with_api(
    api: Api,
    email: &str,
    password: &str,
    code: Option<&str>,
    current: &dyn Fn() -> bool,
) -> Result<LoadedVault, ApiError> {
    let email = email.trim().to_lowercase();
    if email.len() > 320
        || !email.contains('@')
        || email.chars().any(char::is_whitespace)
        || password.is_empty()
        || password.len() > 4096
        || code.is_some_and(|code| code.len() > 32)
    {
        return Err(ApiError::InvalidInput);
    }
    check_current(current)?;
    let kdf = api.prelogin(&email)?;
    check_current(current)?;
    let master = MasterKey::derive(password, &email, kdf)?;
    let hash = master.authorization_hash(password);
    check_current(current)?;
    let mut token = api.token(&email, &hash, code)?;
    let access_token =
        take_string(&mut token, "access_token").ok_or(ApiError::MalformedResponse)?;
    let refresh_token = take_string(&mut token, "refresh_token").unwrap_or_default();
    check_current(current)?;
    let snapshot = api.sync(&access_token)?;
    let profile = property(&snapshot, "profile").ok_or(ApiError::MalformedResponse)?;
    if string(profile, "email").is_some_and(|e| e.trim().to_lowercase() != email) {
        return Err(ApiError::MalformedResponse);
    }
    let protected_key = string(profile, "key")
        .or_else(|| string(&token, "Key"))
        .ok_or(ApiError::MalformedResponse)?
        .to_owned();
    let user_key = master.unwrap_user_key(&protected_key)?;
    check_current(current)?;
    let (items, omitted) = decode_items(&snapshot, &user_key)?;
    let account = LockedAccount {
        email,
        kdf,
        protected_key,
        encrypted_snapshot: snapshot,
        user_key_fingerprint: user_key.fingerprint(),
    };
    let live = LiveSession {
        api,
        access_token,
        refresh_token,
        user_key: user_key.clone(),
    };
    Ok(LoadedVault {
        items,
        account,
        live: Some(live),
        omitted,
        key: user_key,
    })
}

impl LockedAccount {
    /// Account metadata is plaintext inside this serialization; it must only be
    /// written after device-layer AEAD encryption. No tokens/passwords/user keys.
    pub fn cache_bytes(&self) -> Result<Zeroizing<Vec<u8>>, ApiError> {
        let cache = CachedAccount {
            version: 1,
            email: self.email.clone(),
            kdf: self.kdf,
            protected_key: self.protected_key.clone(),
            encrypted_snapshot: self.encrypted_snapshot.clone(),
            user_key_fingerprint: self.user_key_fingerprint,
        };
        serde_json::to_vec(&cache)
            .map(Zeroizing::new)
            .map_err(|_| ApiError::MalformedResponse)
    }

    pub fn from_cache(bytes: &[u8]) -> Result<Self, ApiError> {
        if bytes.len() > 64 * 1024 * 1024 {
            return Err(ApiError::MalformedResponse);
        }
        let cache: CachedAccount =
            serde_json::from_slice(bytes).map_err(|_| ApiError::MalformedResponse)?;
        if cache.version != 1
            || cache.email.len() > 320
            || !cache.email.contains('@')
            || cache.email.trim().to_lowercase() != cache.email
            || !cache.protected_key.starts_with("2.")
        {
            return Err(ApiError::MalformedResponse);
        }
        cache.kdf.validate()?;
        let profile =
            property(&cache.encrypted_snapshot, "profile").ok_or(ApiError::MalformedResponse)?;
        if string(profile, "email").is_some_and(|email| email.trim().to_lowercase() != cache.email)
            || string(profile, "key").is_some_and(|key| key != cache.protected_key)
            || property(&cache.encrypted_snapshot, "ciphers")
                .and_then(Value::as_array)
                .is_none_or(|items| items.len() > 20_000)
        {
            return Err(ApiError::MalformedResponse);
        }
        Ok(Self {
            email: cache.email,
            kdf: cache.kdf,
            protected_key: cache.protected_key,
            encrypted_snapshot: cache.encrypted_snapshot,
            user_key_fingerprint: cache.user_key_fingerprint,
        })
    }

    pub fn binding(&self) -> Result<[u8; 32], ApiError> {
        use sha2::Digest;
        let identity = serde_json::to_vec(&(
            "Vaultwarden biometric identity v1",
            &self.email,
            &self.protected_key,
            self.kdf,
            self.user_key_fingerprint,
        ))
        .map_err(|_| ApiError::MalformedResponse)?;
        Ok(sha2::Sha256::digest(identity).into())
    }

    pub fn unlock_with_key(
        &self,
        key: UserKey,
        current: &dyn Fn() -> bool,
    ) -> Result<LoadedVault, ApiError> {
        use subtle::ConstantTimeEq;
        if !bool::from(key.fingerprint().ct_eq(&self.user_key_fingerprint)) {
            return Err(ApiError::Crypto(CryptoError::AuthenticationFailed));
        }
        check_current(current)?;
        let (items, omitted) = decode_items(&self.encrypted_snapshot, &key)?;
        Ok(LoadedVault {
            items,
            account: self.clone(),
            live: None,
            omitted,
            key,
        })
    }
    /// In-memory encrypted snapshot only. No tokens or decrypted user key survive lock.
    pub fn unlock(
        &self,
        password: &str,
        current: &dyn Fn() -> bool,
    ) -> Result<LoadedVault, ApiError> {
        if password.is_empty() || password.len() > 4096 {
            return Err(ApiError::InvalidInput);
        }
        let key = MasterKey::derive(password, &self.email, self.kdf)?
            .unwrap_user_key(&self.protected_key)?;
        self.unlock_with_key(key, current)
    }
}

impl LiveSession {
    pub fn sync(
        mut self,
        account: &LockedAccount,
        current: &dyn Fn() -> bool,
    ) -> Result<LoadedVault, ApiError> {
        check_current(current)?;
        let snapshot = match self.api.sync(&self.access_token) {
            Err(ApiError::SessionExpired) if !self.refresh_token.is_empty() => {
                check_current(current)?;
                let mut tokens = self.api.refresh(&self.refresh_token)?;
                self.access_token =
                    take_string(&mut tokens, "access_token").ok_or(ApiError::MalformedResponse)?;
                if let Some(refresh) = take_string(&mut tokens, "refresh_token") {
                    self.refresh_token = refresh;
                }
                check_current(current)?;
                self.api.sync(&self.access_token)?
            }
            other => other?,
        };
        check_current(current)?;
        let profile = property(&snapshot, "profile").ok_or(ApiError::MalformedResponse)?;
        if string(profile, "key").is_some_and(|key| key != account.protected_key)
            || string(profile, "email")
                .is_some_and(|email| email.trim().to_lowercase() != account.email)
        {
            return Err(ApiError::KeyChanged);
        }
        let (items, omitted) = decode_items(&snapshot, &self.user_key)?;
        let mut account = account.clone();
        account.encrypted_snapshot = snapshot;
        let key = self.user_key.clone();
        Ok(LoadedVault {
            items,
            account,
            live: Some(self),
            omitted,
            key,
        })
    }
}

fn decode_items(snapshot: &Value, user_key: &UserKey) -> Result<(Vec<VaultItem>, u32), ApiError> {
    let ciphers = property(snapshot, "ciphers")
        .and_then(Value::as_array)
        .ok_or(ApiError::MalformedResponse)?;
    if ciphers.len() > 20_000 {
        return Err(ApiError::MalformedResponse);
    }
    let mut items = Vec::new();
    let mut omitted = 0;
    let mut ids = std::collections::HashSet::new();
    for cipher in ciphers {
        // No organization key support, reprompt bypass, deleted-item inclusion,
        // or lossy reinterpretation of unknown item kinds in this first reader.
        if property(cipher, "organizationId").is_some_and(|v| !v.is_null())
            || property(cipher, "deletedDate").is_some_and(|v| !v.is_null())
            || property(cipher, "reprompt").is_some_and(|v| !v.is_null() && v.as_u64() != Some(0))
        {
            omitted += 1;
            continue;
        }
        match decode_item(cipher, user_key) {
            Ok(Some(item)) => {
                let id = string(cipher, "id").ok_or(ApiError::MalformedResponse)?;
                if !ids.insert(id.to_owned()) {
                    return Err(ApiError::MalformedResponse);
                }
                items.push(item);
            }
            Ok(None) | Err(ApiError::Crypto(CryptoError::UnsupportedCipher)) => omitted += 1,
            Err(error) => return Err(error), // Corrupt MACs fail the transaction.
        }
    }
    Ok((items, omitted))
}

fn decode_item(cipher: &Value, user_key: &UserKey) -> Result<Option<VaultItem>, ApiError> {
    let kind = match number(cipher, "type") {
        Some(1) => ItemKind::Login,
        Some(2) => ItemKind::SecureNote,
        Some(3) => ItemKind::Card,
        Some(4) => ItemKind::Identity,
        Some(5) => ItemKind::SshKey,
        _ => return Ok(None),
    };
    let item_key = string(cipher, "key")
        .map(|key| user_key.unwrap_item_key(key))
        .transpose()?;
    let key = item_key.as_ref().unwrap_or(user_key);
    let title = key.decrypt_text(string(cipher, "name").ok_or(ApiError::MalformedResponse)?)?;
    let mut fields = Vec::new();
    let mut username = String::new();
    let mut website = String::new();
    let mut has_passkey = false;
    let mut has_totp = false;
    let mut add = |object: &Value,
                   name: &str,
                   id: &str,
                   label: &str,
                   secret: bool|
     -> Result<Option<String>, ApiError> {
        if let Some(cipher) = string(object, name) {
            let value = key.decrypt_text(cipher)?;
            let summary_value = if !secret {
                Some(value.to_string())
            } else {
                None
            };
            fields.push(SecretField::new(id.into(), label.into(), secret, value));
            Ok(summary_value)
        } else {
            Ok(None)
        }
    };
    match kind {
        ItemKind::Login => {
            let login = property(cipher, "login").ok_or(ApiError::MalformedResponse)?;
            username = add(login, "username", "username", "Username", false)?.unwrap_or_default();
            add(login, "password", "password", "Password", true)?;
            if let Some(uris) = property(login, "uris").and_then(Value::as_array) {
                if uris.len() > 100 {
                    return Err(ApiError::MalformedResponse);
                }
                for (index, uri) in uris.iter().enumerate() {
                    let id = if index == 0 {
                        "website".into()
                    } else {
                        format!("uri:{index}")
                    };
                    let value = add(uri, "uri", &id, "Website", false)?.unwrap_or_default();
                    if index == 0 {
                        website = value;
                    }
                }
            }
            has_passkey = property(login, "fido2Credentials")
                .and_then(Value::as_array)
                .is_some_and(|v| !v.is_empty());
            has_totp = string(login, "totp").is_some(); // Seed is not exposed by this reader.
        }
        ItemKind::SecureNote => {}
        ItemKind::Card => {
            let card = property(cipher, "card").ok_or(ApiError::MalformedResponse)?;
            for (name, label, secret) in [
                ("cardholderName", "Cardholder", false),
                ("brand", "Brand", false),
                ("number", "Card number", true),
                ("expMonth", "Expiry month", false),
                ("expYear", "Expiry year", false),
                ("code", "Security code", true),
            ] {
                add(card, name, name, label, secret)?;
            }
        }
        ItemKind::Identity => {
            let identity = property(cipher, "identity").ok_or(ApiError::MalformedResponse)?;
            for name in [
                "title",
                "firstName",
                "middleName",
                "lastName",
                "address1",
                "address2",
                "address3",
                "city",
                "state",
                "postalCode",
                "country",
                "company",
                "email",
                "phone",
                "ssn",
                "username",
                "passportNumber",
                "licenseNumber",
            ] {
                add(identity, name, name, name, true)?;
            }
        }
        ItemKind::SshKey => {
            let ssh = property(cipher, "sshKey").ok_or(ApiError::MalformedResponse)?;
            add(ssh, "publicKey", "publicKey", "Public key", false)?;
            add(ssh, "privateKey", "privateKey", "Private key", true)?;
            add(
                ssh,
                "keyFingerprint",
                "keyFingerprint",
                "Fingerprint",
                false,
            )?;
        }
    }
    add(cipher, "notes", "notes", "Notes", true)?;
    if let Some(custom) = property(cipher, "fields").and_then(Value::as_array) {
        if custom.len() > 128 {
            return Err(ApiError::MalformedResponse);
        }
        for (index, field) in custom.iter().enumerate() {
            if let Some(value) = string(field, "value") {
                let label = string(field, "name")
                    .map(|name| key.decrypt_text(name))
                    .transpose()?;
                fields.push(SecretField::new(
                    format!("custom:{index}"),
                    label
                        .as_deref()
                        .map(|s| s.as_str())
                        .unwrap_or("Custom field")
                        .into(),
                    true,
                    key.decrypt_text(value)?,
                ));
            }
        }
    }
    let summary = ItemSummary {
        id: string(cipher, "id")
            .ok_or(ApiError::MalformedResponse)?
            .into(),
        title: title.to_string(),
        username,
        website,
        favorite: property(cipher, "favorite")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        kind,
        has_passkey,
        has_totp,
    };
    Ok(Some(VaultItem::new(summary, fields)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    fn fixture() -> Value {
        serde_json::from_str(include_str!("../../../tests/fixtures/read-only.json"))
            .unwrap_or_else(|_| panic!("invalid public fixture"))
    }
    fn text<'a>(value: &'a Value, name: &str) -> &'a str {
        value[name]
            .as_str()
            .unwrap_or_else(|| panic!("missing public fixture field"))
    }
    fn fixture_key() -> Result<UserKey, ApiError> {
        let f = fixture();
        Ok(MasterKey::derive(
            text(&f, "password"),
            text(&f, "email"),
            KdfParameters {
                kind: 0,
                iterations: 10000,
                memory_mib: None,
                parallelism: None,
            },
        )?
        .unwrap_user_key(text(&f["tokens"], "Key"))?)
    }

    #[test]
    fn decrypts_personal_types_per_item_keys_and_omits_protected_records() -> Result<(), ApiError> {
        let (records, omitted) = decode_items(&fixture()["sync"], &fixture_key()?)?;
        assert_eq!(omitted, 3);
        let mut vault = vault_core::Vault::default();
        let session = vault.install(records);
        assert_eq!(vault.search("").map(|v| v.len()), Ok(5));
        assert_eq!(
            vault.read_field("login", "password", session.generation),
            Ok("PUBLIC-fixture-login-password".into())
        );
        assert_eq!(
            vault.read_field("note", "notes", session.generation),
            Ok("PUBLIC fixture secure note".into())
        );
        assert_eq!(
            vault.read_field("card", "number", session.generation),
            Ok("4111111111111111".into())
        );
        assert_eq!(
            vault.read_field("identity", "email", session.generation),
            Ok("person@example.org".into())
        );
        assert!(vault.item("org").is_err());
        assert!(vault.item("reprompt").is_err());
        vault.lock();
        assert!(vault
            .read_field("card", "number", session.generation)
            .is_err());
        Ok(())
    }

    #[test]
    fn corrupt_cipher_fails_entire_snapshot() -> Result<(), ApiError> {
        let mut snapshot = fixture()["sync"].clone();
        let cipher = text(&snapshot["ciphers"][0], "name").to_owned();
        let mut parts: Vec<_> = cipher.split('|').map(str::to_owned).collect();
        parts[2].replace_range(0..1, "A");
        snapshot["ciphers"][0]["name"] = Value::String(parts.join("|"));
        assert!(matches!(
            decode_items(&snapshot, &fixture_key()?),
            Err(ApiError::Crypto(CryptoError::AuthenticationFailed))
        ));
        Ok(())
    }

    #[test]
    fn duplicate_ids_reject_and_unsupported_records_are_counted() -> Result<(), ApiError> {
        let mut snapshot = fixture()["sync"].clone();
        let duplicate = snapshot["ciphers"][0].clone();
        snapshot["ciphers"]
            .as_array_mut()
            .ok_or(ApiError::MalformedResponse)?
            .push(duplicate);
        assert!(matches!(
            decode_items(&snapshot, &fixture_key()?),
            Err(ApiError::MalformedResponse)
        ));
        let mut snapshot = fixture()["sync"].clone();
        snapshot["ciphers"][0]["name"] = json!("0.unsupported");
        let (items, omitted) = decode_items(&snapshot, &fixture_key()?)?;
        assert_eq!(items.len(), 4);
        assert_eq!(omitted, 4);
        Ok(())
    }

    #[test]
    fn server_validation_and_prefixes() -> Result<(), ApiError> {
        for input in [
            "http://example.com",
            "https://user:pass@example.com",
            "https://example.com/?secret=value",
            "https://example.com/#fragment",
            "file:///vault",
        ] {
            assert!(matches!(Api::new(input), Err(ApiError::InvalidServer)));
        }
        let api = Api::new("https://example.com/tenant")?;
        assert_eq!(
            api.endpoint("api/accounts/prelogin")?.as_str(),
            "https://example.com/tenant/api/accounts/prelogin"
        );
        Ok(())
    }

    // Loopback HTTP is only reachable through this private unit-test helper,
    // never through the production HTTPS constructor or FFI.
    fn mock(replies: Vec<(u16, Value)>) -> (Api, thread::JoinHandle<Vec<String>>) {
        let server = tiny_http::Server::http("127.0.0.1:0").unwrap_or_else(|_| panic!("mock bind"));
        let address = server
            .server_addr()
            .to_ip()
            .unwrap_or_else(|| panic!("mock address"));
        let base =
            Url::parse(&format!("http://{address}/tenant/")).unwrap_or_else(|_| panic!("mock URL"));
        let worker = thread::spawn(move || {
            let mut requests = Vec::new();
            for (status, body) in replies {
                let mut request = server
                    .recv_timeout(Duration::from_secs(5))
                    .unwrap_or_else(|_| panic!("mock receive"))
                    .unwrap_or_else(|| panic!("mock timeout"));
                let mut recorded = format!("{} {} HTTP/1.1\r\n", request.method(), request.url());
                for header in request.headers() {
                    recorded.push_str(&format!("{}: {}\r\n", header.field, header.value));
                }
                recorded.push_str("\r\n");
                request
                    .as_reader()
                    .read_to_string(&mut recorded)
                    .unwrap_or_else(|_| panic!("mock body"));
                requests.push(recorded);
                let mut response = tiny_http::Response::from_string(body.to_string())
                    .with_status_code(status)
                    .with_header(
                        tiny_http::Header::from_bytes("Content-Type", "application/json")
                            .unwrap_or_else(|_| panic!("mock header")),
                    );
                if (300..400).contains(&status) {
                    response = response.with_header(
                        tiny_http::Header::from_bytes(
                            "Location",
                            "http://127.0.0.1:1/never-follow",
                        )
                        .unwrap_or_else(|_| panic!("mock location")),
                    );
                }
                request
                    .respond(response)
                    .unwrap_or_else(|_| panic!("mock response"));
            }
            requests
        });
        let api = Api::with_base(base).unwrap_or_else(|_| panic!("mock client"));
        (api, worker)
    }

    #[test]
    fn mock_login_uses_derived_hash_and_encrypted_sync_then_unlocks_without_network(
    ) -> Result<(), ApiError> {
        let f = fixture();
        let (api, worker) = mock(vec![
            (200, f["prelogin"].clone()),
            (200, f["tokens"].clone()),
            (200, f["sync"].clone()),
        ]);
        let loaded = login_with_api(api, text(&f, "email"), text(&f, "password"), None, &|| true)?;
        assert_eq!(loaded.items.len(), 5);
        let requests = worker.join().unwrap_or_else(|_| panic!("mock worker"));
        assert!(requests[0].starts_with("POST /tenant/api/accounts/prelogin "));
        assert!(requests[2].starts_with("GET /tenant/api/sync?excludeDomains=true "));
        let form: std::collections::HashMap<_, _> = url::form_urlencoded::parse(
            requests[1]
                .split("\r\n\r\n")
                .nth(1)
                .unwrap_or("")
                .as_bytes(),
        )
        .collect();
        assert_eq!(
            form.get("password").map(|s| s.as_ref()),
            Some(text(&f, "authorizationHash"))
        );
        assert!(!requests
            .iter()
            .any(|request| request.contains(text(&f, "password"))));
        let unlocked = loaded.account.unlock(text(&f, "password"), &|| true)?;
        assert!(unlocked.live.is_none());
        assert_eq!(unlocked.items.len(), 5);
        assert!(matches!(
            loaded.account.unlock("wrong-public-password", &|| true),
            Err(ApiError::Crypto(CryptoError::AuthenticationFailed))
        ));
        Ok(())
    }

    #[test]
    fn mock_two_factor_challenge_is_structured() -> Result<(), ApiError> {
        let f = fixture();
        let (api, worker) = mock(vec![
            (200, f["prelogin"].clone()),
            (
                400,
                json!({"error":"invalid_grant", "TwoFactorProviders2": {"0": {}, "7": {}}}),
            ),
        ]);
        assert!(
            matches!(login_with_api(api, text(&f, "email"), text(&f, "password"), None, &|| true), Err(ApiError::TwoFactorRequired(v)) if v == vec![0, 7])
        );
        assert_eq!(
            worker
                .join()
                .unwrap_or_else(|_| panic!("mock worker"))
                .len(),
            2
        );
        Ok(())
    }

    #[test]
    fn redirect_is_not_followed_with_a_bearer_token() {
        let (api, worker) = mock(vec![(302, json!({}))]);
        assert!(matches!(
            api.sync("PUBLIC-fixture-token"),
            Err(ApiError::Rejected)
        ));
        assert_eq!(
            worker
                .join()
                .unwrap_or_else(|_| panic!("mock worker"))
                .len(),
            1
        );
    }

    #[test]
    fn authenticator_code_is_sent_only_in_explicit_retry() -> Result<(), ApiError> {
        let f = fixture();
        let (api, worker) = mock(vec![
            (200, f["prelogin"].clone()),
            (200, f["tokens"].clone()),
            (200, f["sync"].clone()),
        ]);
        let _ = login_with_api(
            api,
            text(&f, "email"),
            text(&f, "password"),
            Some("123456"),
            &|| true,
        )?;
        let requests = worker.join().unwrap_or_else(|_| panic!("mock worker"));
        assert!(
            requests[1].contains("twoFactorProvider=0")
                && requests[1].contains("twoFactorToken=123456")
                && requests[1].contains("twoFactorRemember=0")
        );
        Ok(())
    }

    #[test]
    fn mock_refresh_retries_sync_without_a_password() -> Result<(), ApiError> {
        let f = fixture();
        let (api, worker) = mock(vec![
            (401, json!({})),
            (
                200,
                json!({"access_token":"new-public-token", "refresh_token":"new-public-refresh"}),
            ),
            (200, f["sync"].clone()),
        ]);
        let account = LockedAccount {
            email: text(&f, "email").into(),
            kdf: KdfParameters {
                kind: 0,
                iterations: 10000,
                memory_mib: None,
                parallelism: None,
            },
            protected_key: text(&f["tokens"], "Key").into(),
            encrypted_snapshot: f["sync"].clone(),
            user_key_fingerprint: fixture_key()?.fingerprint(),
        };
        let live = LiveSession {
            api,
            access_token: Zeroizing::new("old-public-token".into()),
            refresh_token: Zeroizing::new("old-public-refresh".into()),
            user_key: fixture_key()?,
        };
        assert_eq!(live.sync(&account, &|| true)?.items.len(), 5);
        let requests = worker.join().unwrap_or_else(|_| panic!("mock worker"));
        assert!(requests[1].contains("grant_type=refresh_token"));
        assert!(requests[2].contains("Bearer new-public-token"));
        Ok(())
    }

    #[test]
    fn cancelled_login_stops_before_credentials_request() -> Result<(), ApiError> {
        let f = fixture();
        let (api, worker) = mock(vec![(200, f["prelogin"].clone())]);
        let checks = std::cell::Cell::new(0);
        let current = || {
            checks.set(checks.get() + 1);
            checks.get() == 1
        };
        assert!(matches!(
            login_with_api(api, text(&f, "email"), text(&f, "password"), None, &current),
            Err(ApiError::Cancelled)
        ));
        assert_eq!(
            worker
                .join()
                .unwrap_or_else(|_| panic!("mock worker"))
                .len(),
            1
        );
        Ok(())
    }

    #[test]
    fn cache_roundtrip_never_serializes_tokens_or_user_key_and_checks_identity(
    ) -> Result<(), ApiError> {
        let f = fixture();
        let (api, worker) = mock(vec![
            (200, f["prelogin"].clone()),
            (200, f["tokens"].clone()),
            (200, f["sync"].clone()),
        ]);
        let loaded = login_with_api(api, text(&f, "email"), text(&f, "password"), None, &|| true)?;
        worker.join().unwrap_or_else(|_| panic!("mock worker"));
        let bytes = loaded.account.cache_bytes()?;
        let serialized = std::str::from_utf8(&bytes).map_err(|_| ApiError::MalformedResponse)?;
        assert!(!serialized.contains("PUBLIC-fixture-access-token"));
        assert!(!serialized.contains("PUBLIC-fixture-refresh-token"));
        assert!(!serialized.contains(text(&f, "password")));
        assert!(!serialized.contains(text(&f, "userKey")));
        let restored = LockedAccount::from_cache(&bytes)?;
        assert_eq!(
            restored.unlock(text(&f, "password"), &|| true)?.items.len(),
            5
        );
        assert_eq!(restored.binding()?, loaded.account.binding()?);
        assert!(matches!(
            restored.unlock_with_key(UserKey::from_bytes(Zeroizing::new(vec![0u8; 64]))?, &|| {
                true
            }),
            Err(ApiError::Crypto(CryptoError::AuthenticationFailed))
        ));
        let mut malformed: Value =
            serde_json::from_slice(&bytes).map_err(|_| ApiError::MalformedResponse)?;
        malformed["version"] = json!(999);
        assert!(matches!(
            LockedAccount::from_cache(malformed.to_string().as_bytes()),
            Err(ApiError::MalformedResponse)
        ));
        Ok(())
    }
}
