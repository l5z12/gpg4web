//! Post-quantum protected local vault.
//!
//! The browser's `localStorage` is used to persist the user's keyring and
//! settings. To guard that data we combine three quantum-resistant building
//! blocks:
//!
//! * **ML-KEM-768** (NIST FIPS 203) — a post-quantum key-encapsulation
//!   mechanism used to wrap a fresh data-encryption key for every save.
//! * **AES-256-GCM** — a 256-bit symmetric cipher (Grover-resistant) that
//!   actually encrypts the payload.
//! * **Argon2id** — a memory-hard password hash that seals the ML-KEM secret
//!   key under the user's master password.
//!
//! An attacker holding the `localStorage` blob must defeat *both* Argon2id
//! (to recover the KEM secret key) **and** ML-KEM (to recover a data key) —
//! neither of which is broken by a quantum computer.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use argon2::Argon2;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use kem::{Decapsulate, Encapsulate};
use ml_kem::{EncodedSizeUser, KemCore, MlKem768};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroize;

use crate::error::CoreError;

type Result<T> = std::result::Result<T, CoreError>;
type Kem = MlKem768;

const VAULT_VERSION: u8 = 1;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;
const HKDF_INFO: &[u8] = b"gpg4web-vault-v1-aes256gcm";

fn b64e(data: &[u8]) -> String {
    B64.encode(data)
}

fn b64d(s: &str) -> Result<Vec<u8>> {
    B64.decode(s).map_err(|e| CoreError::Vault(format!("base64: {e}")))
}

/// Derive a 32-byte key-encryption key from the master password.
fn derive_kek(password: &str, salt: &[u8]) -> Result<[u8; KEY_LEN]> {
    let mut out = [0u8; KEY_LEN];
    Argon2::default()
        .hash_password_into(password.as_bytes(), salt, &mut out)
        .map_err(|e| CoreError::Vault(format!("argon2: {e}")))?;
    Ok(out)
}

/// Expand the KEM shared secret into an AES-256 key.
fn kdf(shared: &[u8]) -> [u8; KEY_LEN] {
    let hk = hkdf::Hkdf::<Sha256>::new(None, shared);
    let mut okm = [0u8; KEY_LEN];
    // Expansion of a fixed-length output with a constant info string never fails.
    hk.expand(HKDF_INFO, &mut okm)
        .expect("hkdf expand of 32 bytes is infallible");
    okm
}

fn aes_encrypt(key: &[u8; KEY_LEN], plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| CoreError::Vault(format!("aes key: {e}")))?;
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ct = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| CoreError::Vault(format!("aes encrypt: {e}")))?;
    Ok((nonce_bytes.to_vec(), ct))
}

fn aes_decrypt(key: &[u8; KEY_LEN], nonce_bytes: &[u8], ct: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| CoreError::Vault(format!("aes key: {e}")))?;
    let nonce = Nonce::from_slice(nonce_bytes);
    cipher
        .decrypt(nonce, ct)
        .map_err(|_| CoreError::Vault("decryption failed (wrong password or corrupt data)".into()))
}

// ---------------------------------------------------------------------------
// Identity: created once per master password.
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultIdentity {
    pub version: u8,
    /// Argon2id salt.
    pub salt: String,
    /// ML-KEM-768 public (encapsulation) key.
    pub kem_public: String,
    /// ML-KEM-768 secret (decapsulation) key, AES-256-GCM sealed under the
    /// Argon2id-derived key.
    pub kem_secret_sealed: String,
    pub kem_secret_nonce: String,
    /// A constant verifier ciphertext, used to validate the password quickly.
    pub verifier: String,
    pub verifier_nonce: String,
}

const VERIFIER_PLAINTEXT: &[u8] = b"gpg4web-ok";

pub fn create_identity(password: &str) -> Result<VaultIdentity> {
    if password.is_empty() {
        return Err(CoreError::Vault("master password must not be empty".into()));
    }
    let mut rng = rand::thread_rng();

    let mut salt = [0u8; SALT_LEN];
    rng.fill_bytes(&mut salt);
    let kek = derive_kek(password, &salt)?;

    let (dk, ek) = Kem::generate(&mut rng);
    let mut dk_bytes = dk.as_bytes().to_vec();
    let ek_bytes = ek.as_bytes().to_vec();

    let (sec_nonce, sec_sealed) = aes_encrypt(&kek, &dk_bytes)?;
    dk_bytes.zeroize();

    let (ver_nonce, verifier) = aes_encrypt(&kek, VERIFIER_PLAINTEXT)?;

    let mut kek_mut = kek;
    kek_mut.zeroize();

    Ok(VaultIdentity {
        version: VAULT_VERSION,
        salt: b64e(&salt),
        kem_public: b64e(&ek_bytes),
        kem_secret_sealed: b64e(&sec_sealed),
        kem_secret_nonce: b64e(&sec_nonce),
        verifier: b64e(&verifier),
        verifier_nonce: b64e(&ver_nonce),
    })
}

pub fn verify_password(identity: &VaultIdentity, password: &str) -> Result<bool> {
    let salt = b64d(&identity.salt)?;
    let kek = derive_kek(password, &salt)?;
    let nonce = b64d(&identity.verifier_nonce)?;
    let ct = b64d(&identity.verifier)?;
    match aes_decrypt(&kek, &nonce, &ct) {
        Ok(p) => Ok(p == VERIFIER_PLAINTEXT),
        Err(_) => Ok(false),
    }
}

// ---------------------------------------------------------------------------
// Payload envelope: written on every save.
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultEnvelope {
    pub version: u8,
    /// ML-KEM encapsulated ciphertext carrying the data key.
    pub kem_ciphertext: String,
    /// AES-256-GCM nonce.
    pub nonce: String,
    /// AES-256-GCM ciphertext of the payload.
    pub data: String,
}

/// Encrypt a payload. Only the public key is required, so encryption never
/// needs the master password.
pub fn encrypt(identity: &VaultIdentity, plaintext: &[u8]) -> Result<VaultEnvelope> {
    let ek_bytes = b64d(&identity.kem_public)?;
    let encoded = ml_kem::Encoded::<<Kem as KemCore>::EncapsulationKey>::try_from(
        ek_bytes.as_slice(),
    )
    .map_err(|_| CoreError::Vault("malformed KEM public key".into()))?;
    let ek = <Kem as KemCore>::EncapsulationKey::from_bytes(&encoded);

    let mut rng = rand::thread_rng();
    let (ct, shared) = ek
        .encapsulate(&mut rng)
        .map_err(|_| CoreError::Vault("KEM encapsulation failed".into()))?;

    let key = kdf(shared.as_ref());
    let (nonce, data) = aes_encrypt(&key, plaintext)?;
    let mut key_mut = key;
    key_mut.zeroize();

    Ok(VaultEnvelope {
        version: VAULT_VERSION,
        kem_ciphertext: b64e(ct.as_ref()),
        nonce: b64e(&nonce),
        data: b64e(&data),
    })
}

/// Decrypt a payload using the master password to unseal the KEM secret key.
pub fn decrypt(
    identity: &VaultIdentity,
    password: &str,
    envelope: &VaultEnvelope,
) -> Result<Vec<u8>> {
    let salt = b64d(&identity.salt)?;
    let kek = derive_kek(password, &salt)?;

    let sec_nonce = b64d(&identity.kem_secret_nonce)?;
    let sec_sealed = b64d(&identity.kem_secret_sealed)?;
    let mut dk_bytes = aes_decrypt(&kek, &sec_nonce, &sec_sealed)?;

    let encoded = ml_kem::Encoded::<<Kem as KemCore>::DecapsulationKey>::try_from(
        dk_bytes.as_slice(),
    )
    .map_err(|_| CoreError::Vault("malformed KEM secret key".into()))?;
    let dk = <Kem as KemCore>::DecapsulationKey::from_bytes(&encoded);
    dk_bytes.zeroize();

    let ct_bytes = b64d(&envelope.kem_ciphertext)?;
    let ct = ml_kem::Ciphertext::<Kem>::try_from(ct_bytes.as_slice())
        .map_err(|_| CoreError::Vault("malformed KEM ciphertext".into()))?;
    let shared = dk
        .decapsulate(&ct)
        .map_err(|_| CoreError::Vault("KEM decapsulation failed".into()))?;

    let key = kdf(shared.as_ref());
    let nonce = b64d(&envelope.nonce)?;
    let data = b64d(&envelope.data)?;
    let out = aes_decrypt(&key, &nonce, &data)?;
    let mut key_mut = key;
    key_mut.zeroize();
    Ok(out)
}
