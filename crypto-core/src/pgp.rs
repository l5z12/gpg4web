//! High-level OpenPGP operations backed by rPGP.
//!
//! Everything here is pure Rust and compiles to WebAssembly, so all
//! cryptography runs locally in the browser — no key material ever leaves
//! the device.

use std::io::Cursor;

use std::time::Duration;

use chrono::Utc;
use pgp::composed::{
    ArmorOptions, CleartextSignedMessage, Deserializable, KeyType, Message, MessageBuilder,
    SecretKeyParamsBuilder, SignedPublicKey, SignedSecretKey, StandaloneSignature,
    SubkeyParamsBuilder,
};
use pgp::crypto::ecc_curve::ECCCurve;
use pgp::crypto::hash::HashAlgorithm;
use pgp::crypto::sym::SymmetricKeyAlgorithm;
use pgp::packet::SignatureConfig;
use pgp::packet::{SignatureType, Subpacket, SubpacketData};
use pgp::types::{
    CompressionAlgorithm, KeyDetails as _, KeyVersion, Password, PublicKeyTrait,
};
use serde::{Deserialize, Serialize};
use smallvec::smallvec;

use crate::error::CoreError;

type Result<T> = std::result::Result<T, CoreError>;

/// Version of the underlying rPGP OpenPGP implementation.
pub const PGP_VERSION: &str = "0.16";

fn rng() -> impl rand::Rng + rand::CryptoRng {
    rand::thread_rng()
}

// ---------------------------------------------------------------------------
// Data transfer objects (serialized to/from JS)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GenerateOptions {
    /// User id, e.g. "Alice <alice@example.com>".
    pub user_id: String,
    /// Algorithm preset: curve25519 | ed25519 | rsa2048 | rsa3072 | rsa4096
    /// | nistp256 | nistp384 | nistp521.
    pub algorithm: String,
    /// Passphrase that locks the secret key. Empty means unprotected.
    #[serde(default)]
    pub passphrase: String,
    /// Optional expiration in days (0 / absent = never expires).
    #[serde(default)]
    pub expire_days: u32,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GeneratedKey {
    pub fingerprint: String,
    pub key_id: String,
    pub public_key: String,
    pub secret_key: String,
    pub algorithm: String,
    pub user_ids: Vec<String>,
    pub created_at: i64,
    pub expires_at: Option<i64>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SubkeyInfo {
    pub key_id: String,
    pub fingerprint: String,
    pub algorithm: String,
    pub can_encrypt: bool,
    pub can_sign: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyInfo {
    pub fingerprint: String,
    pub key_id: String,
    pub algorithm: String,
    pub user_ids: Vec<String>,
    pub created_at: i64,
    pub expires_at: Option<i64>,
    pub is_secret: bool,
    pub can_encrypt: bool,
    pub can_sign: bool,
    pub bit_strength: Option<u32>,
    pub subkeys: Vec<SubkeyInfo>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SignatureCheck {
    pub key_id: String,
    pub fingerprint: Option<String>,
    pub valid: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DecryptResult {
    pub data: String,
    /// true when the payload was decrypted (vs. only verified).
    pub was_encrypted: bool,
    pub signatures: Vec<SignatureCheck>,
    /// Set when decryption succeeds but a contained signature failed.
    pub filename: Option<String>,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn armor_opts() -> ArmorOptions<'static> {
    None.into()
}

fn fmt_fingerprint(fp: &pgp::types::Fingerprint) -> String {
    let bytes = fp.as_bytes();
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02X}", b));
    }
    s
}

fn fmt_key_id(id: &pgp::types::KeyId) -> String {
    let mut s = String::new();
    for b in id.as_ref() {
        s.push_str(&format!("{:02X}", b));
    }
    s
}

fn parse_public(armored: &str) -> Result<SignedPublicKey> {
    let (key, _) = SignedPublicKey::from_string(armored)
        .map_err(|e| CoreError::Pgp(format!("invalid public key: {e}")))?;
    Ok(key)
}

fn parse_secret(armored: &str) -> Result<SignedSecretKey> {
    let (key, _) = SignedSecretKey::from_string(armored)
        .map_err(|e| CoreError::Pgp(format!("invalid secret key: {e}")))?;
    Ok(key)
}

fn user_id_strings(details: &pgp::composed::SignedKeyDetails) -> Vec<String> {
    details
        .users
        .iter()
        .map(|u| String::from_utf8_lossy(u.id.id()).to_string())
        .collect()
}

fn algorithm_name(alg: pgp::crypto::public_key::PublicKeyAlgorithm) -> String {
    format!("{:?}", alg)
}

/// Whether a component key can encrypt, including the draft PQC KEM algorithms
/// that rPGP's built-in `is_encryption_key` does not yet classify.
fn can_encrypt_alg(k: &impl PublicKeyTrait) -> bool {
    use pgp::crypto::public_key::PublicKeyAlgorithm as A;
    k.is_encryption_key() || matches!(k.algorithm(), A::MlKem768X25519 | A::MlKem1024X448)
}

/// Whether a component key can sign, including the draft PQC signature schemes.
fn can_sign_alg(k: &impl PublicKeyTrait) -> bool {
    use pgp::crypto::public_key::PublicKeyAlgorithm as A;
    k.is_signing_key()
        || matches!(
            k.algorithm(),
            A::MlDsa65Ed25519
                | A::MlDsa87Ed448
                | A::SlhDsaShake128s
                | A::SlhDsaShake128f
                | A::SlhDsaShake256s
        )
}

// ---------------------------------------------------------------------------
// Key generation
// ---------------------------------------------------------------------------

/// Map a preset string into (primary key type, encryption subkey type).
fn key_types(algorithm: &str) -> Result<(KeyType, KeyType, bool)> {
    // bool = primary is a signing key (true) vs. RSA-style sign+encrypt primary
    let pair = match algorithm.to_ascii_lowercase().as_str() {
        // v4, broadly compatible with GnuPG 2.2+
        "curve25519" | "" => (KeyType::Ed25519Legacy, KeyType::ECDH(ECCCurve::Curve25519), true),
        // modern v6 keys (RFC 9580)
        "ed25519" => (KeyType::Ed25519, KeyType::X25519, true),
        "rsa2048" => (KeyType::Rsa(2048), KeyType::Rsa(2048), false),
        "rsa3072" => (KeyType::Rsa(3072), KeyType::Rsa(3072), false),
        "rsa4096" => (KeyType::Rsa(4096), KeyType::Rsa(4096), false),
        "nistp256" => (KeyType::ECDSA(ECCCurve::P256), KeyType::ECDH(ECCCurve::P256), true),
        "nistp384" => (KeyType::ECDSA(ECCCurve::P384), KeyType::ECDH(ECCCurve::P384), true),
        "nistp521" => (KeyType::ECDSA(ECCCurve::P521), KeyType::ECDH(ECCCurve::P521), true),
        // Post-quantum (IETF draft) hybrid keys: ML-DSA/SLH-DSA signing primary
        // paired with an ML-KEM encryption subkey.
        "pqc" | "mldsa65-mlkem768" => {
            (KeyType::MlDsa65Ed25519, KeyType::MlKem768X25519, true)
        }
        "mldsa87-mlkem1024" => (KeyType::MlDsa87Ed448, KeyType::MlKem1024X448, true),
        "slhdsa128s-mlkem768" => {
            (KeyType::SlhDsaShake128s, KeyType::MlKem768X25519, true)
        }
        other => return Err(CoreError::Pgp(format!("unknown algorithm: {other}"))),
    };
    Ok(pair)
}

pub fn generate_key(opts: GenerateOptions) -> Result<GeneratedKey> {
    let (primary_type, subkey_type, _signing_primary) = key_types(&opts.algorithm)?;
    // Modern Ed25519 and all post-quantum (draft) keys are emitted as v6 keys
    // per RFC 9580 / the IETF PQC draft; the rest stay v4 for GnuPG 2.2
    // compatibility.
    let version = match opts.algorithm.to_ascii_lowercase().as_str() {
        "ed25519" | "pqc" | "mldsa65-mlkem768" | "mldsa87-mlkem1024"
        | "slhdsa128s-mlkem768" => KeyVersion::V6,
        _ => KeyVersion::V4,
    };

    let passphrase = if opts.passphrase.is_empty() {
        None
    } else {
        Some(opts.passphrase.clone())
    };

    let mut builder = SecretKeyParamsBuilder::default();
    builder
        .version(version)
        .key_type(primary_type)
        .can_certify(true)
        .can_sign(true)
        .can_encrypt(false)
        .primary_user_id(opts.user_id.clone())
        .preferred_symmetric_algorithms(smallvec![
            SymmetricKeyAlgorithm::AES256,
            SymmetricKeyAlgorithm::AES192,
            SymmetricKeyAlgorithm::AES128,
        ])
        .preferred_hash_algorithms(smallvec![
            HashAlgorithm::Sha512,
            HashAlgorithm::Sha384,
            HashAlgorithm::Sha256,
        ])
        .preferred_compression_algorithms(smallvec![
            CompressionAlgorithm::ZLIB,
            CompressionAlgorithm::ZIP,
        ]);

    if opts.expire_days > 0 {
        builder.expiration(Some(Duration::from_secs(opts.expire_days as u64 * 86_400)));
    }
    if let Some(ref pw) = passphrase {
        builder.passphrase(Some(pw.clone()));
    }

    let mut subkey_builder = SubkeyParamsBuilder::default();
    subkey_builder
        .version(version)
        .key_type(subkey_type)
        .can_encrypt(true)
        .can_sign(false);
    if let Some(ref pw) = passphrase {
        subkey_builder.passphrase(Some(pw.clone()));
    }
    let subkey = subkey_builder
        .build()
        .map_err(|e| CoreError::Pgp(format!("subkey params: {e}")))?;
    builder.subkey(subkey);

    let params = builder
        .build()
        .map_err(|e| CoreError::Pgp(format!("key params: {e}")))?;

    let secret = params
        .generate(rng())
        .map_err(|e| CoreError::Pgp(format!("generation failed: {e}")))?;

    let pw = passphrase
        .clone()
        .map(Password::from)
        .unwrap_or_else(Password::empty);

    let signed_secret = secret
        .sign(rng(), &pw)
        .map_err(|e| CoreError::Pgp(format!("self-sign failed: {e}")))?;

    let signed_public = signed_secret.signed_public_key();

    let public_key = signed_public
        .to_armored_string(armor_opts())
        .map_err(|e| CoreError::Pgp(format!("armor public: {e}")))?;
    let secret_key = signed_secret
        .to_armored_string(armor_opts())
        .map_err(|e| CoreError::Pgp(format!("armor secret: {e}")))?;

    let expires_at = signed_public.expires_at().map(|d| d.timestamp());

    Ok(GeneratedKey {
        fingerprint: fmt_fingerprint(&signed_public.fingerprint()),
        key_id: fmt_key_id(&signed_public.key_id()),
        public_key,
        secret_key,
        algorithm: opts.algorithm,
        user_ids: user_id_strings(&signed_public.details),
        created_at: signed_public.primary_key.created_at().timestamp(),
        expires_at,
    })
}

// ---------------------------------------------------------------------------
// Key inspection
// ---------------------------------------------------------------------------

pub fn inspect_key(armored: &str) -> Result<KeyInfo> {
    // Try secret first; fall back to public.
    if let Ok(sec) = SignedSecretKey::from_string(armored) {
        let key = sec.0;
        return Ok(key_info_from_secret(&key));
    }
    let pub_key = parse_public(armored)?;
    Ok(key_info_from_public(&pub_key))
}

fn key_info_from_public(key: &SignedPublicKey) -> KeyInfo {
    let subkeys = key
        .public_subkeys
        .iter()
        .map(|sk| SubkeyInfo {
            key_id: fmt_key_id(&sk.key.key_id()),
            fingerprint: fmt_fingerprint(&sk.key.fingerprint()),
            algorithm: algorithm_name(sk.key.algorithm()),
            can_encrypt: can_encrypt_alg(&sk.key),
            can_sign: can_sign_alg(&sk.key),
        })
        .collect();

    let can_encrypt = can_encrypt_alg(&key.primary_key)
        || key.public_subkeys.iter().any(|s| can_encrypt_alg(&s.key));
    let can_sign = can_sign_alg(&key.primary_key)
        || key.public_subkeys.iter().any(|s| can_sign_alg(&s.key));

    KeyInfo {
        fingerprint: fmt_fingerprint(&key.fingerprint()),
        key_id: fmt_key_id(&key.key_id()),
        algorithm: algorithm_name(key.primary_key.algorithm()),
        user_ids: user_id_strings(&key.details),
        created_at: key.primary_key.created_at().timestamp(),
        expires_at: key.expires_at().map(|d| d.timestamp()),
        is_secret: false,
        can_encrypt,
        can_sign,
        bit_strength: None,
        subkeys,
    }
}

fn key_info_from_secret(key: &SignedSecretKey) -> KeyInfo {
    let pub_view = key.signed_public_key();
    let mut info = key_info_from_public(&pub_view);
    info.is_secret = true;
    info
}

// ---------------------------------------------------------------------------
// Encryption
// ---------------------------------------------------------------------------

/// Encrypt `plaintext` to one or more recipients, optionally signing with a
/// secret key. Output is ASCII-armored when `armor` is true.
pub fn encrypt(
    plaintext: &[u8],
    recipient_keys: &[String],
    sign_with: Option<(&str, &str)>, // (armored secret, passphrase)
    armor: bool,
) -> Result<String> {
    if recipient_keys.is_empty() {
        return Err(CoreError::Pgp("no recipients provided".into()));
    }

    let recipients: Vec<SignedPublicKey> = recipient_keys
        .iter()
        .map(|k| parse_public(k))
        .collect::<Result<_>>()?;

    let mut builder = MessageBuilder::from_bytes("", plaintext.to_vec())
        .seipd_v1(rng(), SymmetricKeyAlgorithm::AES256);
    builder.compression(CompressionAlgorithm::ZLIB);

    let mut found_target = false;
    for rcpt in &recipients {
        // Prefer encryption-capable subkeys; fall back to the primary key.
        let mut used_subkey = false;
        for sub in &rcpt.public_subkeys {
            if can_encrypt_alg(&sub.key) {
                builder
                    .encrypt_to_key(rng(), &sub.key)
                    .map_err(|e| CoreError::Pgp(format!("encrypt_to_key: {e}")))?;
                used_subkey = true;
                found_target = true;
            }
        }
        if !used_subkey && can_encrypt_alg(&rcpt.primary_key) {
            builder
                .encrypt_to_key(rng(), &rcpt.primary_key)
                .map_err(|e| CoreError::Pgp(format!("encrypt_to_key: {e}")))?;
            found_target = true;
        }
    }
    if !found_target {
        return Err(CoreError::Pgp(
            "no encryption-capable key among recipients".into(),
        ));
    }

    // Optional signing. The secret key must outlive the builder.
    let secret_key;
    if let Some((sec_armored, pass)) = sign_with {
        secret_key = parse_secret(sec_armored)?;
        let pw = Password::from(pass.to_string());
        builder.sign(&secret_key.primary_key, pw, HashAlgorithm::Sha256);
    }

    if armor {
        builder
            .to_armored_string(rng(), armor_opts())
            .map_err(|e| CoreError::Pgp(format!("armor message: {e}")))
    } else {
        let bytes = builder
            .to_vec(rng())
            .map_err(|e| CoreError::Pgp(format!("serialize message: {e}")))?;
        Ok(base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            bytes,
        ))
    }
}

// ---------------------------------------------------------------------------
// Decryption + verification
// ---------------------------------------------------------------------------

pub fn decrypt(
    ciphertext: &str,
    secret_armored: &str,
    passphrase: &str,
    verify_with: &[String],
) -> Result<DecryptResult> {
    let secret = parse_secret(secret_armored)?;
    let pw = Password::from(passphrase.to_string());

    let (message, _headers) = Message::from_string(ciphertext)
        .map_err(|e| CoreError::Pgp(format!("parse message: {e}")))?;

    let was_encrypted = message.is_encrypted();

    let mut message = if was_encrypted {
        message
            .decrypt(&pw, &secret)
            .map_err(|e| CoreError::Pgp(format!("decrypt failed: {e}")))?
    } else {
        message
    };

    // Decompress if needed so we can reach the literal data.
    while message.is_compressed() {
        message = message
            .decompress()
            .map_err(|e| CoreError::Pgp(format!("decompress: {e}")))?;
    }

    let filename = message
        .literal_data_header()
        .map(|h| String::from_utf8_lossy(h.file_name().as_ref()).to_string())
        .filter(|s| !s.is_empty());

    let data = message
        .as_data_vec()
        .map_err(|e| CoreError::Pgp(format!("read data: {e}")))?;

    // Verify signatures against any supplied public keys.
    let mut signatures = Vec::new();
    if !verify_with.is_empty() && message.is_signed() {
        let verifiers: Vec<SignedPublicKey> = verify_with
            .iter()
            .map(|k| parse_public(k))
            .collect::<Result<_>>()?;
        for v in &verifiers {
            let valid = message.verify(&v.primary_key).is_ok();
            signatures.push(SignatureCheck {
                key_id: fmt_key_id(&v.key_id()),
                fingerprint: Some(fmt_fingerprint(&v.fingerprint())),
                valid,
            });
        }
    }

    Ok(DecryptResult {
        data: String::from_utf8_lossy(&data).to_string(),
        was_encrypted,
        signatures,
        filename,
    })
}

// ---------------------------------------------------------------------------
// Detached & cleartext signatures
// ---------------------------------------------------------------------------

pub fn sign_detached(data: &[u8], secret_armored: &str, passphrase: &str) -> Result<String> {
    let secret = parse_secret(secret_armored)?;
    let pw = Password::from(passphrase.to_string());
    let key = &secret.primary_key;

    let mut config = SignatureConfig::from_key(rng(), key, SignatureType::Binary)
        .map_err(|e| CoreError::Pgp(format!("sig config: {e}")))?;
    config.hashed_subpackets = vec![
        Subpacket::regular(SubpacketData::IssuerFingerprint(key.fingerprint()))
            .map_err(|e| CoreError::Pgp(e.to_string()))?,
        Subpacket::regular(SubpacketData::SignatureCreationTime(Utc::now()))
            .map_err(|e| CoreError::Pgp(e.to_string()))?,
    ];
    if key.version() <= KeyVersion::V4 {
        config.unhashed_subpackets = vec![Subpacket::regular(SubpacketData::Issuer(key.key_id()))
            .map_err(|e| CoreError::Pgp(e.to_string()))?];
    }

    let sig = config
        .sign(key, &pw, Cursor::new(data.to_vec()))
        .map_err(|e| CoreError::Pgp(format!("sign: {e}")))?;

    StandaloneSignature::new(sig)
        .to_armored_string(armor_opts())
        .map_err(|e| CoreError::Pgp(format!("armor sig: {e}")))
}

pub fn verify_detached(data: &[u8], signature_armored: &str, public_armored: &str) -> Result<bool> {
    let pub_key = parse_public(public_armored)?;
    let (sig, _) = StandaloneSignature::from_string(signature_armored)
        .map_err(|e| CoreError::Pgp(format!("parse signature: {e}")))?;

    // Try the primary key and every subkey.
    if sig.verify(&pub_key.primary_key, data).is_ok() {
        return Ok(true);
    }
    for sub in &pub_key.public_subkeys {
        if sig.verify(&sub.key, data).is_ok() {
            return Ok(true);
        }
    }
    Ok(false)
}

pub fn sign_cleartext(text: &str, secret_armored: &str, passphrase: &str) -> Result<String> {
    let secret = parse_secret(secret_armored)?;
    let pw = Password::from(passphrase.to_string());
    let msg = CleartextSignedMessage::sign(rng(), text, &secret.primary_key, &pw)
        .map_err(|e| CoreError::Pgp(format!("clearsign: {e}")))?;
    msg.to_armored_string(armor_opts())
        .map_err(|e| CoreError::Pgp(format!("armor clearsign: {e}")))
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CleartextResult {
    pub text: String,
    pub valid: bool,
}

pub fn verify_cleartext(armored: &str, public_armored: &str) -> Result<CleartextResult> {
    let pub_key = parse_public(public_armored)?;
    let (msg, _) = CleartextSignedMessage::from_string(armored)
        .map_err(|e| CoreError::Pgp(format!("parse clearsign: {e}")))?;
    let valid = msg.verify(&pub_key.primary_key).is_ok();
    Ok(CleartextResult {
        text: msg.text().to_string(),
        valid,
    })
}

// ---------------------------------------------------------------------------
// Convert / re-armor a key (e.g. extract public part from a secret key)
// ---------------------------------------------------------------------------

pub fn extract_public_key(secret_armored: &str) -> Result<String> {
    let secret = parse_secret(secret_armored)?;
    secret
        .signed_public_key()
        .to_armored_string(armor_opts())
        .map_err(|e| CoreError::Pgp(format!("armor public: {e}")))
}
