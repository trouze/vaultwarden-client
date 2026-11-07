//! Vault state, secret field access, and encryption-v1 primitives.

pub mod crypto;

use url::Url;
use zeroize::{Zeroize, Zeroizing};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionState {
    Locked,
    DemoUnlocked,
    Unlocked,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Session {
    pub state: SessionState,
    pub generation: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ItemKind {
    Login,
    SecureNote,
    Card,
    Identity,
    SshKey,
}

#[derive(Clone, Debug, PartialEq, Eq)]
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VaultError {
    Locked,
    NotFound,
    StaleSession,
    InvalidQuery,
    InvalidService,
}

// Deliberately no Debug/Clone: do not accidentally format or duplicate secrets.
pub struct VaultItem {
    summary: ItemSummary,
    fields: Vec<SecretField>,
}

pub struct SecretField {
    pub id: String,
    pub label: String,
    pub is_secret: bool,
    value: Zeroizing<String>,
}

#[derive(Clone)]
pub struct FieldInfo {
    pub id: String,
    pub label: String,
    pub is_secret: bool,
}

impl SecretField {
    pub fn new(id: String, label: String, is_secret: bool, value: Zeroizing<String>) -> Self {
        Self {
            id,
            label,
            is_secret,
            value,
        }
    }
}

impl VaultItem {
    pub fn new(summary: ItemSummary, fields: Vec<SecretField>) -> Self {
        Self { summary, fields }
    }
}

impl Drop for VaultItem {
    fn drop(&mut self) {
        self.summary.title.zeroize();
        self.summary.username.zeroize();
        self.summary.website.zeroize();
    }
}

impl Drop for SecretField {
    fn drop(&mut self) {
        self.label.zeroize();
    }
}

pub struct Vault {
    session: Session,
    items: Vec<VaultItem>,
}

impl Default for Vault {
    fn default() -> Self {
        Self {
            session: Session {
                state: SessionState::Locked,
                generation: 0,
            },
            items: Vec::new(),
        }
    }
}

impl Vault {
    pub fn session(&self) -> Session {
        self.session
    }

    /// Loads public, fictional fixtures, not a user's vault.
    pub fn unlock_demo(&mut self) -> Session {
        self.lock();
        self.items = demo_items();
        self.session.state = SessionState::DemoUnlocked;
        self.session
    }

    pub fn lock(&mut self) -> Session {
        // Dropping Zeroizing values scrubs the Rust-owned password buffers.
        self.items.clear();
        self.session.state = SessionState::Locked;
        self.session.generation = self.session.generation.saturating_add(1);
        self.session
    }

    pub fn install(&mut self, items: Vec<VaultItem>) -> Session {
        self.items = items;
        self.session.state = SessionState::Unlocked;
        self.session
    }

    pub fn fields(&self, id: &str) -> Result<Vec<FieldInfo>, VaultError> {
        self.require_unlocked()?;
        let item = self
            .items
            .iter()
            .find(|item| item.summary.id == id)
            .ok_or(VaultError::NotFound)?;
        Ok(item
            .fields
            .iter()
            .map(|field| FieldInfo {
                id: field.id.clone(),
                label: field.label.clone(),
                is_secret: field.is_secret,
            })
            .collect())
    }

    pub fn read_field(
        &self,
        id: &str,
        field_id: &str,
        expected_generation: u64,
    ) -> Result<String, VaultError> {
        self.require_unlocked()?;
        if expected_generation != self.session.generation {
            return Err(VaultError::StaleSession);
        }
        self.items
            .iter()
            .find(|item| item.summary.id == id)
            .and_then(|item| item.fields.iter().find(|field| field.id == field_id))
            .map(|field| field.value.to_string())
            .ok_or(VaultError::NotFound)
    }

    pub fn search(&self, query: &str) -> Result<Vec<ItemSummary>, VaultError> {
        self.require_unlocked()?;
        if query.len() > 256 {
            return Err(VaultError::InvalidQuery);
        }
        let query = query.trim().to_lowercase();
        let mut results: Vec<_> = self
            .items
            .iter()
            .filter(|item| {
                [
                    &item.summary.title,
                    &item.summary.username,
                    &item.summary.website,
                ]
                .iter()
                .any(|field| field.to_lowercase().contains(&query))
            })
            .map(|item| item.summary.clone())
            .collect();
        results.sort_by(|a, b| a.title.cmp(&b.title));
        Ok(results)
    }

    pub fn item(&self, id: &str) -> Result<ItemSummary, VaultError> {
        self.require_unlocked()?;
        self.items
            .iter()
            .find(|item| item.summary.id == id)
            .map(|item| item.summary.clone())
            .ok_or(VaultError::NotFound)
    }

    pub fn reveal_password(
        &self,
        id: &str,
        expected_generation: u64,
    ) -> Result<String, VaultError> {
        self.read_field(id, "password", expected_generation)
    }

    /// Demo-only exact host matching. Not a production Bitwarden URI policy.
    pub fn match_service(&self, service: &str) -> Result<Vec<ItemSummary>, VaultError> {
        self.require_unlocked()?;
        let host = service_host(service)?;
        Ok(self
            .search("")?
            .into_iter()
            .filter(|item| service_host(&item.website).ok().as_ref() == Some(&host))
            .collect())
    }

    fn require_unlocked(&self) -> Result<(), VaultError> {
        if self.session.state == SessionState::Locked {
            Err(VaultError::Locked)
        } else {
            Ok(())
        }
    }
}

fn service_host(service: &str) -> Result<String, VaultError> {
    if service.len() > 2048 || service.trim() != service || service.is_empty() {
        return Err(VaultError::InvalidService);
    }
    let parsed = if service.contains("://") {
        Url::parse(service)
    } else {
        // A domain identifier must not sneak in a path, user-info, port, etc.
        if service.contains(['/', '\\', '@', ':', '?', '#']) {
            return Err(VaultError::InvalidService);
        }
        Url::parse(&format!("https://{service}"))
    }
    .map_err(|_| VaultError::InvalidService)?;
    if parsed.scheme() != "https"
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.port_or_known_default() != Some(443)
    {
        return Err(VaultError::InvalidService);
    }
    parsed
        .host_str()
        .map(str::to_owned)
        .ok_or(VaultError::InvalidService)
}

fn demo_items() -> Vec<VaultItem> {
    [
        (
            "demo-example",
            "Example account",
            "demo@example.com",
            "https://example.com",
            true,
        ),
        (
            "demo-docs",
            "Documentation",
            "reader@example.org",
            "https://example.org",
            false,
        ),
        (
            "demo-lab",
            "Development lab",
            "developer@example.net",
            "https://example.net",
            true,
        ),
    ]
    .into_iter()
    .map(|(id, title, username, website, favorite)| VaultItem {
        summary: ItemSummary {
            id: id.into(),
            title: title.into(),
            username: username.into(),
            website: website.into(),
            favorite,
            kind: ItemKind::Login,
            has_passkey: false,
            has_totp: false,
        },
        fields: vec![
            SecretField::new(
                "username".into(),
                "Username".into(),
                false,
                Zeroizing::new(username.into()),
            ),
            SecretField::new(
                "website".into(),
                "Website".into(),
                false,
                Zeroizing::new(website.into()),
            ),
            SecretField::new(
                "password".into(),
                "Password".into(),
                true,
                Zeroizing::new("DEMO-ONLY-not-a-real-password".into()),
            ),
        ],
    })
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unlocked() -> Vault {
        let mut vault = Vault::default();
        vault.unlock_demo();
        vault
    }

    #[test]
    fn starts_locked_and_denies_all_reads() {
        let vault = Vault::default();
        assert_eq!(vault.session().state, SessionState::Locked);
        assert_eq!(vault.search(""), Err(VaultError::Locked));
        assert_eq!(vault.item("demo-example"), Err(VaultError::Locked));
        assert_eq!(
            vault.reveal_password("demo-example", 0),
            Err(VaultError::Locked)
        );
        assert_eq!(vault.match_service("example.com"), Err(VaultError::Locked));
    }

    #[test]
    fn demo_unlock_loads_only_fictional_summaries() {
        let vault = unlocked();
        let items = vault.search("");
        assert_eq!(items.as_ref().map(Vec::len), Ok(3));
        assert!(!format!("{items:?}").contains("DEMO-ONLY"));
        assert!(items.is_ok_and(|items| items
            .iter()
            .all(|item| { item.kind == ItemKind::Login && !item.has_passkey && !item.has_totp })));
    }

    #[test]
    fn searches_titles_usernames_and_websites_case_insensitively() {
        let vault = unlocked();
        for query in ["  DOCUMENTATION  ", "reader@", "EXAMPLE.ORG"] {
            let result = vault.search(query);
            assert_eq!(result.as_ref().map(Vec::len), Ok(1));
            assert_eq!(
                result.ok().and_then(|v| v.first().map(|i| i.id.clone())),
                Some("demo-docs".into())
            );
        }
        assert_eq!(vault.search("missing"), Ok(vec![]));
        assert_eq!(
            vault.search(&"x".repeat(257)),
            Err(VaultError::InvalidQuery)
        );
    }

    #[test]
    fn lock_discards_items_and_increments_generation() {
        let mut vault = unlocked();
        let old = vault.session();
        let locked = vault.lock();
        assert!(locked.generation > old.generation);
        assert!(vault.items.is_empty());
        assert_eq!(
            vault.reveal_password("demo-example", old.generation),
            Err(VaultError::Locked)
        );
    }

    #[test]
    fn previous_session_cannot_reveal_after_reunlock() {
        let mut vault = unlocked();
        let old = vault.session();
        vault.unlock_demo();
        assert_eq!(
            vault.reveal_password("demo-example", old.generation),
            Err(VaultError::StaleSession)
        );
        assert_eq!(
            vault.reveal_password("demo-example", vault.session().generation),
            Ok("DEMO-ONLY-not-a-real-password".into())
        );
    }

    #[test]
    fn unknown_items_fail_without_secret_data_in_errors() {
        let vault = unlocked();
        assert_eq!(vault.item("unknown"), Err(VaultError::NotFound));
        assert_eq!(
            vault.reveal_password("unknown", vault.session().generation),
            Err(VaultError::NotFound)
        );
    }

    #[test]
    fn matches_only_exact_https_hosts() {
        let vault = unlocked();
        for service in ["example.com", "EXAMPLE.COM", "https://example.com/login"] {
            assert_eq!(vault.match_service(service).as_ref().map(Vec::len), Ok(1));
        }
        for service in [
            "example.com.evil.test",
            "sub.example.com",
            "evil.test",
            "https://evil.test/example.com",
        ] {
            assert_eq!(vault.match_service(service), Ok(vec![]));
        }
    }

    #[test]
    fn rejects_ambiguous_or_insecure_services() {
        let vault = unlocked();
        for service in [
            "",
            " example.com",
            "http://example.com",
            "https://evil@example.com",
            "https://example.com:8443",
            "example.com/path",
            "example.com@evil.test",
            "file:///example.com",
            "example.com\\evil.test",
        ] {
            assert_eq!(
                vault.match_service(service),
                Err(VaultError::InvalidService),
                "{service}"
            );
        }
    }
}
