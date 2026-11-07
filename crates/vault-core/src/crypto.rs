//! Bitwarden encryption-v1 composition of maintained RustCrypto primitives.
//! Only authenticated type-2 cipher strings are supported. No production writer.

use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
use base64::{engine::general_purpose::STANDARD, Engine};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CryptoError {
    UnsupportedKdf,
    UnsafeKdf,
    InvalidCipher,
    UnsupportedCipher,
    AuthenticationFailed,
    InvalidKey,
    InvalidText,
}

#[derive(Clone, Copy, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KdfParameters {
    pub kind: u32,
    pub iterations: u32,
    pub memory_mib: Option<u32>,
    pub parallelism: Option<u32>,
}

impl KdfParameters {
    pub fn validate(&self) -> Result<(), CryptoError> {
        match self.kind {
            0 if (5_000..=2_000_000).contains(&self.iterations) => Ok(()),
            0 => Err(CryptoError::UnsafeKdf),
            1 => {
                let memory = self.memory_mib.ok_or(CryptoError::UnsafeKdf)?;
                let parallelism = self.parallelism.ok_or(CryptoError::UnsafeKdf)?;
                if !(16..=256).contains(&memory)
                    || !(2..=10).contains(&self.iterations)
                    || !(1..=16).contains(&parallelism)
                    || memory * self.iterations > 1024
                {
                    Err(CryptoError::UnsafeKdf)
                } else {
                    Ok(())
                }
            }
            _ => Err(CryptoError::UnsupportedKdf),
        }
    }
}

pub struct MasterKey(Zeroizing<[u8; 32]>);

#[derive(Clone)]
pub struct UserKey(Zeroizing<Vec<u8>>);

impl MasterKey {
    pub fn derive(password: &str, email: &str, kdf: KdfParameters) -> Result<Self, CryptoError> {
        kdf.validate()?;
        let email = email.trim().to_lowercase();
        let mut output = Zeroizing::new([0u8; 32]);
        match kdf.kind {
            0 => {
                if !(5_000..=2_000_000).contains(&kdf.iterations) {
                    return Err(CryptoError::UnsafeKdf);
                }
                pbkdf2::pbkdf2_hmac::<Sha256>(
                    password.as_bytes(),
                    email.as_bytes(),
                    kdf.iterations,
                    output.as_mut(),
                );
            }
            1 => {
                let memory = kdf.memory_mib.ok_or(CryptoError::UnsafeKdf)?;
                let parallelism = kdf.parallelism.ok_or(CryptoError::UnsafeKdf)?;
                if !(16..=256).contains(&memory)
                    || !(2..=10).contains(&kdf.iterations)
                    || !(1..=16).contains(&parallelism)
                    || memory * kdf.iterations > 1024
                {
                    return Err(CryptoError::UnsafeKdf);
                }
                let salt = Sha256::digest(email.as_bytes());
                let params =
                    argon2::Params::new(memory * 1024, kdf.iterations, parallelism, Some(32))
                        .map_err(|_| CryptoError::UnsafeKdf)?;
                argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params)
                    .hash_password_into(password.as_bytes(), &salt, output.as_mut())
                    .map_err(|_| CryptoError::InvalidKey)?;
            }
            _ => return Err(CryptoError::UnsupportedKdf),
        }
        Ok(Self(output))
    }

    pub fn authorization_hash(&self, password: &str) -> Zeroizing<String> {
        let mut hash = Zeroizing::new([0u8; 32]);
        pbkdf2::pbkdf2_hmac::<Sha256>(self.0.as_ref(), password.as_bytes(), 1, hash.as_mut());
        Zeroizing::new(STANDARD.encode(hash.as_ref()))
    }

    pub fn unwrap_user_key(&self, protected: &str) -> Result<UserKey, CryptoError> {
        let hkdf =
            Hkdf::<Sha256>::from_prk(self.0.as_ref()).map_err(|_| CryptoError::InvalidKey)?;
        let mut stretched = Zeroizing::new(vec![0u8; 64]);
        hkdf.expand(b"enc", &mut stretched[..32])
            .map_err(|_| CryptoError::InvalidKey)?;
        hkdf.expand(b"mac", &mut stretched[32..])
            .map_err(|_| CryptoError::InvalidKey)?;
        let wrapper = UserKey(stretched);
        UserKey::from_bytes(wrapper.decrypt(protected)?)
    }
}

impl UserKey {
    pub fn encoded(&self) -> Zeroizing<Vec<u8>> {
        self.0.clone()
    }

    pub fn fingerprint(&self) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(b"Vaultwarden user-key verification v1\0");
        hash.update(self.0.as_slice());
        hash.finalize().into()
    }
    pub fn from_bytes(bytes: Zeroizing<Vec<u8>>) -> Result<Self, CryptoError> {
        if bytes.len() != 64 {
            return Err(CryptoError::InvalidKey);
        }
        Ok(Self(bytes))
    }

    pub fn unwrap_item_key(&self, protected: &str) -> Result<Self, CryptoError> {
        Self::from_bytes(self.decrypt(protected)?)
    }

    pub fn decrypt_text(&self, cipher: &str) -> Result<Zeroizing<String>, CryptoError> {
        // Keep the original plaintext buffer zeroized even if UTF-8 conversion fails.
        let bytes = self.decrypt(cipher)?;
        let text = std::str::from_utf8(&bytes).map_err(|_| CryptoError::InvalidText)?;
        Ok(Zeroizing::new(text.to_owned()))
    }

    pub fn decrypt(&self, cipher: &str) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        if cipher.len() > 4 * 1024 * 1024 {
            return Err(CryptoError::InvalidCipher);
        }
        let (kind, payload) = cipher.split_once('.').ok_or(CryptoError::InvalidCipher)?;
        if kind != "2" {
            return Err(CryptoError::UnsupportedCipher);
        }
        let mut parts = payload.split('|');
        let iv_part = parts.next().ok_or(CryptoError::InvalidCipher)?;
        let data_part = parts.next().ok_or(CryptoError::InvalidCipher)?;
        let tag_part = parts.next().ok_or(CryptoError::InvalidCipher)?;
        if parts.next().is_some() || iv_part.len() != 24 || tag_part.len() != 44 {
            return Err(CryptoError::InvalidCipher);
        }
        let iv = STANDARD
            .decode(iv_part)
            .map_err(|_| CryptoError::InvalidCipher)?;
        let mut data = Zeroizing::new(
            STANDARD
                .decode(data_part)
                .map_err(|_| CryptoError::InvalidCipher)?,
        );
        let tag = STANDARD
            .decode(tag_part)
            .map_err(|_| CryptoError::InvalidCipher)?;
        if iv.len() != 16 || tag.len() != 32 || data.is_empty() || data.len() % 16 != 0 {
            return Err(CryptoError::InvalidCipher);
        }
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&self.0[32..])
            .map_err(|_| CryptoError::InvalidKey)?;
        mac.update(&iv);
        mac.update(&data);
        // Authenticate before touching CBC/padding; verify_slice is constant-time.
        mac.verify_slice(&tag)
            .map_err(|_| CryptoError::AuthenticationFailed)?;
        let plaintext = cbc::Decryptor::<aes::Aes256>::new_from_slices(&self.0[..32], &iv)
            .map_err(|_| CryptoError::InvalidKey)?
            .decrypt_padded_mut::<Pkcs7>(&mut data)
            .map_err(|_| CryptoError::AuthenticationFailed)?;
        Ok(Zeroizing::new(plaintext.to_vec()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> serde_json::Value {
        serde_json::from_str(include_str!("../../../tests/fixtures/read-only.json"))
            .unwrap_or_else(|_| panic!("invalid public fixture"))
    }

    fn text<'a>(value: &'a serde_json::Value, name: &str) -> &'a str {
        value[name]
            .as_str()
            .unwrap_or_else(|| panic!("missing public fixture field"))
    }

    #[test]
    fn independent_pbkdf_hkdf_and_cipher_known_answers() -> Result<(), CryptoError> {
        let f = fixture();
        let password = text(&f, "password");
        let master = MasterKey::derive(
            password,
            " READER@EXAMPLE.COM ",
            KdfParameters {
                kind: 0,
                iterations: 10000,
                memory_mib: None,
                parallelism: None,
            },
        )?;
        assert_eq!(STANDARD.encode(master.0.as_ref()), text(&f, "masterKey"));
        assert_eq!(
            &*master.authorization_hash(password),
            text(&f, "authorizationHash")
        );
        let key = master.unwrap_user_key(text(&f["tokens"], "Key"))?;
        assert_eq!(STANDARD.encode(key.0.as_slice()), text(&f, "userKey"));
        assert_eq!(
            &*key.decrypt_text(text(&f["sync"]["ciphers"][0]["login"], "password"))?,
            "PUBLIC-fixture-login-password"
        );
        let item_key = key.unwrap_item_key(text(&f["sync"]["ciphers"][1], "key"))?;
        assert_eq!(STANDARD.encode(item_key.0.as_slice()), text(&f, "itemKey"));
        assert_eq!(
            &*item_key.decrypt_text(text(&f["sync"]["ciphers"][1], "notes"))?,
            "PUBLIC fixture secure note"
        );
        Ok(())
    }

    #[test]
    fn independent_argon2id_known_answer() -> Result<(), CryptoError> {
        let f = fixture();
        let password = text(&f, "password");
        let master = MasterKey::derive(
            password,
            text(&f, "email"),
            KdfParameters {
                kind: 1,
                iterations: 2,
                memory_mib: Some(16),
                parallelism: Some(1),
            },
        )?;
        assert_eq!(
            STANDARD.encode(master.0.as_ref()),
            text(&f["argon2"], "masterKey")
        );
        assert_eq!(
            &*master.authorization_hash(password),
            text(&f["argon2"], "authorizationHash")
        );
        Ok(())
    }

    #[test]
    fn authentication_and_resource_bounds_fail_closed() -> Result<(), CryptoError> {
        let f = fixture();
        let master = MasterKey::derive(
            text(&f, "password"),
            text(&f, "email"),
            KdfParameters {
                kind: 0,
                iterations: 10000,
                memory_mib: None,
                parallelism: None,
            },
        )?;
        let key = master.unwrap_user_key(text(&f["tokens"], "Key"))?;
        let cipher = text(&f["sync"]["ciphers"][0], "name");
        let mut parts: Vec<_> = cipher.split('|').map(str::to_owned).collect();
        let mut tag = STANDARD
            .decode(&parts[2])
            .map_err(|_| CryptoError::InvalidCipher)?;
        tag[0] ^= 1;
        parts[2] = STANDARD.encode(tag);
        assert!(matches!(
            key.decrypt(&parts.join("|")),
            Err(CryptoError::AuthenticationFailed)
        ));
        assert!(matches!(
            key.decrypt("0.invalid"),
            Err(CryptoError::UnsupportedCipher)
        ));
        assert!(matches!(
            key.decrypt("2.invalid"),
            Err(CryptoError::InvalidCipher)
        ));
        for kdf in [
            KdfParameters {
                kind: 0,
                iterations: u32::MAX,
                memory_mib: None,
                parallelism: None,
            },
            KdfParameters {
                kind: 1,
                iterations: 10,
                memory_mib: Some(256),
                parallelism: Some(16),
            },
            KdfParameters {
                kind: 1,
                iterations: 2,
                memory_mib: Some(u32::MAX),
                parallelism: Some(1),
            },
        ] {
            assert!(matches!(
                MasterKey::derive("public", "public@example.com", kdf),
                Err(CryptoError::UnsafeKdf)
            ));
        }
        Ok(())
    }
}
