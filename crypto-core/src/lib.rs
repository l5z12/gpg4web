//! gpg4web-core — OpenPGP + post-quantum vault crypto, compiled to WebAssembly.
//!
//! All cryptography executes inside the browser sandbox. No key material,
//! passphrase, or plaintext ever crosses the WASM boundary except as an
//! explicit return value to the calling JavaScript.

mod error;
mod pgp;
mod vault;

use serde_wasm_bindgen::{from_value, to_value};
use wasm_bindgen::prelude::*;

use error::CoreError;

#[wasm_bindgen(start)]
pub fn start() {
    console_error_panic_hook::set_once();
}

/// Library + crypto backend version string, surfaced in the UI's About page.
#[wasm_bindgen]
pub fn version() -> String {
    format!("gpg4web-core {} (rPGP {})", env!("CARGO_PKG_VERSION"), pgp::PGP_VERSION)
}

// ---------------------------------------------------------------------------
// OpenPGP bindings
// ---------------------------------------------------------------------------

#[wasm_bindgen]
pub fn generate_key(options: JsValue) -> Result<JsValue, JsValue> {
    let opts: pgp::GenerateOptions = from_value(options).map_err(CoreError::from)?;
    let key = pgp::generate_key(opts)?;
    Ok(to_value(&key).map_err(CoreError::from)?)
}

#[wasm_bindgen]
pub fn inspect_key(armored: String) -> Result<JsValue, JsValue> {
    let info = pgp::inspect_key(&armored)?;
    Ok(to_value(&info).map_err(CoreError::from)?)
}

#[wasm_bindgen]
pub fn extract_public_key(secret_armored: String) -> Result<String, JsValue> {
    Ok(pgp::extract_public_key(&secret_armored)?)
}

/// Encrypt text to one or more recipients, optionally signing.
///
/// `recipients` is an array of armored public keys. `sign_secret` /
/// `sign_passphrase` are optional; pass `undefined`/`null` to skip signing.
#[wasm_bindgen]
pub fn encrypt(
    plaintext: String,
    recipients: JsValue,
    sign_secret: Option<String>,
    sign_passphrase: Option<String>,
    armor: bool,
) -> Result<String, JsValue> {
    let recipient_keys: Vec<String> = from_value(recipients).map_err(CoreError::from)?;
    let pass = sign_passphrase.unwrap_or_default();
    let sign_with = sign_secret.as_deref().map(|s| (s, pass.as_str()));
    Ok(pgp::encrypt(
        plaintext.as_bytes(),
        &recipient_keys,
        sign_with,
        armor,
    )?)
}

#[wasm_bindgen]
pub fn decrypt(
    ciphertext: String,
    secret_armored: String,
    passphrase: String,
    verify_with: JsValue,
) -> Result<JsValue, JsValue> {
    let verifiers: Vec<String> = from_value(verify_with).map_err(CoreError::from)?;
    let result = pgp::decrypt(&ciphertext, &secret_armored, &passphrase, &verifiers)?;
    Ok(to_value(&result).map_err(CoreError::from)?)
}

#[wasm_bindgen]
pub fn sign_detached(
    data: String,
    secret_armored: String,
    passphrase: String,
) -> Result<String, JsValue> {
    Ok(pgp::sign_detached(data.as_bytes(), &secret_armored, &passphrase)?)
}

#[wasm_bindgen]
pub fn verify_detached(
    data: String,
    signature_armored: String,
    public_armored: String,
) -> Result<bool, JsValue> {
    Ok(pgp::verify_detached(
        data.as_bytes(),
        &signature_armored,
        &public_armored,
    )?)
}

#[wasm_bindgen]
pub fn sign_cleartext(
    text: String,
    secret_armored: String,
    passphrase: String,
) -> Result<String, JsValue> {
    Ok(pgp::sign_cleartext(&text, &secret_armored, &passphrase)?)
}

#[wasm_bindgen]
pub fn verify_cleartext(
    armored: String,
    public_armored: String,
) -> Result<JsValue, JsValue> {
    let result = pgp::verify_cleartext(&armored, &public_armored)?;
    Ok(to_value(&result).map_err(CoreError::from)?)
}

// ---------------------------------------------------------------------------
// File (binary) operations
// ---------------------------------------------------------------------------

/// Encrypt arbitrary bytes (a file) to one or more recipients, optionally
/// signing. Returns binary OpenPGP, or ASCII-armored bytes when `armor`.
#[wasm_bindgen]
pub fn encrypt_file(
    data: &[u8],
    recipients: JsValue,
    sign_secret: Option<String>,
    sign_passphrase: Option<String>,
    armor: bool,
) -> Result<Vec<u8>, JsValue> {
    let recipient_keys: Vec<String> = from_value(recipients).map_err(CoreError::from)?;
    let pass = sign_passphrase.unwrap_or_default();
    let sign_with = sign_secret.as_deref().map(|s| (s, pass.as_str()));
    Ok(pgp::encrypt_bytes(data, &recipient_keys, sign_with, armor)?)
}

/// Decrypt a file (binary or armored OpenPGP) to its original bytes.
#[wasm_bindgen]
pub fn decrypt_file(
    data: &[u8],
    secret_armored: String,
    passphrase: String,
) -> Result<Vec<u8>, JsValue> {
    Ok(pgp::decrypt_bytes(data, &secret_armored, &passphrase)?)
}

/// Produce a detached ASCII-armored signature over a file's bytes.
#[wasm_bindgen]
pub fn sign_file_detached(
    data: &[u8],
    secret_armored: String,
    passphrase: String,
) -> Result<String, JsValue> {
    Ok(pgp::sign_detached(data, &secret_armored, &passphrase)?)
}

/// Verify a detached signature against a file's bytes.
#[wasm_bindgen]
pub fn verify_file_detached(
    data: &[u8],
    signature_armored: String,
    public_armored: String,
) -> Result<bool, JsValue> {
    Ok(pgp::verify_detached(data, &signature_armored, &public_armored)?)
}

// ---------------------------------------------------------------------------
// Post-quantum vault bindings
// ---------------------------------------------------------------------------

#[wasm_bindgen]
pub fn vault_create(password: String) -> Result<JsValue, JsValue> {
    let identity = vault::create_identity(&password)?;
    Ok(to_value(&identity).map_err(CoreError::from)?)
}

#[wasm_bindgen]
pub fn vault_verify_password(identity: JsValue, password: String) -> Result<bool, JsValue> {
    let id: vault::VaultIdentity = from_value(identity).map_err(CoreError::from)?;
    Ok(vault::verify_password(&id, &password)?)
}

#[wasm_bindgen]
pub fn vault_encrypt(identity: JsValue, plaintext: String) -> Result<JsValue, JsValue> {
    let id: vault::VaultIdentity = from_value(identity).map_err(CoreError::from)?;
    let envelope = vault::encrypt(&id, plaintext.as_bytes())?;
    Ok(to_value(&envelope).map_err(CoreError::from)?)
}

#[wasm_bindgen]
pub fn vault_decrypt(
    identity: JsValue,
    password: String,
    envelope: JsValue,
) -> Result<String, JsValue> {
    let id: vault::VaultIdentity = from_value(identity).map_err(CoreError::from)?;
    let env: vault::VaultEnvelope = from_value(envelope).map_err(CoreError::from)?;
    let bytes = vault::decrypt(&id, &password, &env)?;
    String::from_utf8(bytes).map_err(|e| CoreError::Vault(format!("utf8: {e}")).into())
}

/// Unseal the per-session decapsulation key (base64) from the master password.
/// The caller keeps this in memory instead of the password, so subsequent
/// envelope decryption never needs the plaintext password again.
#[wasm_bindgen]
pub fn vault_unseal(identity: JsValue, password: String) -> Result<String, JsValue> {
    let id: vault::VaultIdentity = from_value(identity).map_err(CoreError::from)?;
    Ok(vault::unseal(&id, &password)?)
}

/// Decrypt a payload with a previously-unsealed session key (from vault_unseal).
#[wasm_bindgen]
pub fn vault_decrypt_with_key(
    session_key: String,
    envelope: JsValue,
) -> Result<String, JsValue> {
    let env: vault::VaultEnvelope = from_value(envelope).map_err(CoreError::from)?;
    let bytes = vault::decrypt_with_key(&session_key, &env)?;
    String::from_utf8(bytes).map_err(|e| CoreError::Vault(format!("utf8: {e}")).into())
}
