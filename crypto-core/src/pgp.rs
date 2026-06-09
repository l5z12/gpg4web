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
use pgp::packet::{Signature, SignatureType, Subpacket, SubpacketData};
use pgp::types::{
    CompressionAlgorithm, EcdsaPublicParams, KeyDetails as _, KeyVersion, Password,
    PublicKeyTrait, PublicParams, StringToKey,
};
use rsa::traits::PublicKeyParts as _;
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
    /// GnuPG-style algorithm token for the primary key (e.g. "ed25519",
    /// "cv25519", "rsa3072", "nistp256"), when one applies.
    pub curve: Option<String>,
    /// Key strength in bits, as GnuPG reports it (255 for Curve25519/Ed25519).
    pub bit_strength: Option<u32>,
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
    pub curve: Option<String>,
    pub bit_strength: Option<u32>,
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
    /// Whole-key capabilities (primary or any subkey can do it).
    pub can_encrypt: bool,
    pub can_sign: bool,
    /// The primary key's *own* capabilities (its key-flag subpackets) — these
    /// drive the usage column on the `pub`/`sec` line, distinct from the
    /// whole-key flags above.
    pub primary_can_encrypt: bool,
    pub primary_can_sign: bool,
    pub bit_strength: Option<u32>,
    /// GnuPG-style algorithm token for the primary key.
    pub curve: Option<String>,
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

/// Key strength in bits, the way GnuPG reports it (255 for Curve25519/Ed25519,
/// the modulus length for RSA, the field size for NIST curves).
fn key_bits(k: &impl PublicKeyTrait) -> Option<u32> {
    match k.public_params() {
        PublicParams::RSA(p) => Some(p.key.n().bits() as u32),
        PublicParams::DSA(_) => None,
        PublicParams::Elgamal(_) => None,
        PublicParams::ECDSA(p) => Some(ecdsa_curve(p).nbits() as u32),
        PublicParams::ECDH(p) => Some(p.curve().nbits() as u32),
        PublicParams::EdDSALegacy(_) | PublicParams::Ed25519(_) | PublicParams::X25519(_) => {
            Some(255)
        }
        PublicParams::Ed448(_) => Some(456),
        PublicParams::X448(_) => Some(448),
        _ => None,
    }
}

fn ecdsa_curve(p: &EcdsaPublicParams) -> ECCCurve {
    match p {
        EcdsaPublicParams::P256 { .. } => ECCCurve::P256,
        EcdsaPublicParams::P384 { .. } => ECCCurve::P384,
        EcdsaPublicParams::P521 { .. } => ECCCurve::P521,
        EcdsaPublicParams::Secp256k1 { .. } => ECCCurve::Secp256k1,
        EcdsaPublicParams::Unsupported { curve, .. } => curve.clone(),
    }
}

/// GnuPG-style algorithm token for ECC keys (cv25519/ed25519/nistp256/…), or
/// None for non-ECC algorithms (RSA/DSA/PQC), where the algorithm name + bits
/// carry the information instead.
fn key_curve(k: &impl PublicKeyTrait) -> Option<String> {
    let curve = match k.public_params() {
        PublicParams::ECDSA(p) => ecdsa_curve(p),
        PublicParams::ECDH(p) => p.curve(),
        PublicParams::EdDSALegacy(_) | PublicParams::Ed25519(_) => ECCCurve::Ed25519,
        PublicParams::X25519(_) => ECCCurve::Curve25519,
        PublicParams::Ed448(_) => return Some("ed448".into()),
        PublicParams::X448(_) => return Some("cv448".into()),
        _ => return None,
    };
    Some(curve.alias().unwrap_or_else(|| curve.name()).to_string())
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
        curve: key_curve(&signed_public.primary_key),
        bit_strength: key_bits(&signed_public.primary_key),
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

/// Resolve (can_sign, can_encrypt) from the key-flag subpackets carried by a
/// component key's self-signatures, falling back to the algorithm when no key
/// flags are present (so the listing matches GnuPG's usage column exactly).
fn usage_from_sigs<'a>(
    sigs: impl Iterator<Item = &'a Signature>,
    fallback: (bool, bool),
) -> (bool, bool) {
    let mut sign = false;
    let mut enc = false;
    let mut found = false;
    for sig in sigs {
        let f = sig.key_flags();
        if f.sign() || f.certify() || f.encrypt_comms() || f.encrypt_storage() || f.authentication()
        {
            found = true;
            if f.sign() {
                sign = true;
            }
            if f.encrypt_comms() || f.encrypt_storage() {
                enc = true;
            }
        }
    }
    if found {
        (sign, enc)
    } else {
        fallback
    }
}

fn key_info_from_public(key: &SignedPublicKey) -> KeyInfo {
    let subkeys: Vec<SubkeyInfo> = key
        .public_subkeys
        .iter()
        .map(|sk| {
            let (s_sign, s_enc) = usage_from_sigs(
                sk.signatures.iter(),
                (can_sign_alg(&sk.key), can_encrypt_alg(&sk.key)),
            );
            SubkeyInfo {
                key_id: fmt_key_id(&sk.key.key_id()),
                fingerprint: fmt_fingerprint(&sk.key.fingerprint()),
                algorithm: algorithm_name(sk.key.algorithm()),
                curve: key_curve(&sk.key),
                bit_strength: key_bits(&sk.key),
                can_encrypt: s_enc,
                can_sign: s_sign,
            }
        })
        .collect();

    let (p_sign, p_enc) = usage_from_sigs(
        key.details
            .users
            .iter()
            .flat_map(|u| u.signatures.iter())
            .chain(key.details.direct_signatures.iter()),
        (can_sign_alg(&key.primary_key), can_encrypt_alg(&key.primary_key)),
    );
    let can_encrypt = p_enc || subkeys.iter().any(|s| s.can_encrypt);
    let can_sign = p_sign || subkeys.iter().any(|s| s.can_sign);

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
        primary_can_encrypt: p_enc,
        primary_can_sign: p_sign,
        bit_strength: key_bits(&key.primary_key),
        curve: key_curve(&key.primary_key),
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
/// Encrypt to one or more recipients, returning the raw message bytes
/// (ASCII-armored UTF-8 when `armor`, otherwise binary OpenPGP). Used directly
/// for file encryption.
pub fn encrypt_bytes(
    plaintext: &[u8],
    recipient_keys: &[String],
    sign_with: Option<(&str, &str)>, // (armored secret, passphrase)
    armor: bool,
) -> Result<Vec<u8>> {
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
        let s = builder
            .to_armored_string(rng(), armor_opts())
            .map_err(|e| CoreError::Pgp(format!("armor message: {e}")))?;
        Ok(s.into_bytes())
    } else {
        builder
            .to_vec(rng())
            .map_err(|e| CoreError::Pgp(format!("serialize message: {e}")))
    }
}

pub fn encrypt(
    plaintext: &[u8],
    recipient_keys: &[String],
    sign_with: Option<(&str, &str)>, // (armored secret, passphrase)
    armor: bool,
) -> Result<String> {
    let bytes = encrypt_bytes(plaintext, recipient_keys, sign_with, armor)?;
    if armor {
        String::from_utf8(bytes).map_err(|e| CoreError::Pgp(format!("utf8: {e}")))
    } else {
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

/// Decrypt (and decompress) a message, returning the literal data bytes.
fn read_message_data(
    mut message: Message<'_>,
    pw: &Password,
    secret: &SignedSecretKey,
) -> Result<Vec<u8>> {
    if message.is_encrypted() {
        message = message
            .decrypt(pw, secret)
            .map_err(|e| CoreError::Pgp(format!("decrypt failed: {e}")))?;
    }
    while message.is_compressed() {
        message = message
            .decompress()
            .map_err(|e| CoreError::Pgp(format!("decompress: {e}")))?;
    }
    message
        .as_data_vec()
        .map_err(|e| CoreError::Pgp(format!("read data: {e}")))
}

/// Decrypt a binary or ASCII-armored OpenPGP message to raw bytes. Used for
/// file decryption (auto-detects armor).
pub fn decrypt_bytes(ciphertext: &[u8], secret_armored: &str, passphrase: &str) -> Result<Vec<u8>> {
    let secret = parse_secret(secret_armored)?;
    let pw = Password::from(passphrase.to_string());

    if ciphertext.starts_with(b"-----BEGIN") {
        let s = std::str::from_utf8(ciphertext)
            .map_err(|e| CoreError::Pgp(format!("utf8: {e}")))?;
        let (message, _) =
            Message::from_string(s).map_err(|e| CoreError::Pgp(format!("parse message: {e}")))?;
        read_message_data(message, &pw, &secret)
    } else {
        let message = Message::from_bytes(Cursor::new(ciphertext.to_vec()))
            .map_err(|e| CoreError::Pgp(format!("parse message: {e}")))?;
        read_message_data(message, &pw, &secret)
    }
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

// ---------------------------------------------------------------------------
// Symmetric (passphrase-only) encryption — `gpg -c`
// ---------------------------------------------------------------------------

/// Encrypt bytes with a passphrase only (no public key): an SKESK + SEIPD
/// message, AES-256, the way `gpg --symmetric` produces one.
pub fn encrypt_symmetric_bytes(plaintext: &[u8], passphrase: &str, armor: bool) -> Result<Vec<u8>> {
    let mut builder = MessageBuilder::from_bytes("", plaintext.to_vec())
        .seipd_v1(rng(), SymmetricKeyAlgorithm::AES256);
    builder.compression(CompressionAlgorithm::ZLIB);
    let s2k = StringToKey::new_default(rng());
    let pw = Password::from(passphrase.to_string());
    builder
        .encrypt_with_password(s2k, &pw)
        .map_err(|e| CoreError::Pgp(format!("symmetric encrypt: {e}")))?;
    if armor {
        builder
            .to_armored_string(rng(), armor_opts())
            .map(String::into_bytes)
            .map_err(|e| CoreError::Pgp(format!("armor message: {e}")))
    } else {
        builder
            .to_vec(rng())
            .map_err(|e| CoreError::Pgp(format!("serialize message: {e}")))
    }
}

/// Decrypt a passphrase-encrypted (symmetric) message to its bytes.
pub fn decrypt_symmetric_bytes(ciphertext: &[u8], passphrase: &str) -> Result<Vec<u8>> {
    let pw = Password::from(passphrase.to_string());
    let message = if ciphertext.starts_with(b"-----BEGIN") {
        let s = std::str::from_utf8(ciphertext)
            .map_err(|e| CoreError::Pgp(format!("utf8: {e}")))?;
        let (m, _) =
            Message::from_string(s).map_err(|e| CoreError::Pgp(format!("parse message: {e}")))?;
        m
    } else {
        Message::from_bytes(Cursor::new(ciphertext.to_vec()))
            .map_err(|e| CoreError::Pgp(format!("parse message: {e}")))?
    };
    let mut message = message
        .decrypt_with_password(&pw)
        .map_err(|e| CoreError::Pgp(format!("decrypt failed: {e}")))?;
    while message.is_compressed() {
        message = message
            .decompress()
            .map_err(|e| CoreError::Pgp(format!("decompress: {e}")))?;
    }
    message
        .as_data_vec()
        .map_err(|e| CoreError::Pgp(format!("read data: {e}")))
}

// ---------------------------------------------------------------------------
// Signature metadata (for faithful `gpg --verify` reporting)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SignatureInfo {
    /// 16-hex issuer key id, if the signature carries one.
    pub key_id: Option<String>,
    /// Full issuer fingerprint, if present (v4+ signatures embed it).
    pub fingerprint: Option<String>,
    /// Signature creation time (unix seconds).
    pub created: Option<i64>,
    /// OpenPGP public-key algorithm id.
    pub pub_algo: u8,
    /// OpenPGP hash algorithm id.
    pub hash_algo: u8,
    /// Signature class (type) byte.
    pub sig_class: u8,
}

fn sig_info(sig: &Signature) -> SignatureInfo {
    let fpr = sig
        .issuer_fingerprint()
        .first()
        .map(|f| fmt_fingerprint(f));
    let key_id = sig
        .issuer()
        .first()
        .map(|k| fmt_key_id(k))
        .or_else(|| {
            fpr.as_ref()
                .map(|f| f[f.len().saturating_sub(16)..].to_string())
        });
    SignatureInfo {
        key_id,
        fingerprint: fpr,
        created: sig.created().map(|d| d.timestamp()),
        pub_algo: sig.config().map(|c| u8::from(c.pub_alg)).unwrap_or(0),
        hash_algo: sig.hash_alg().map(u8::from).unwrap_or(0),
        sig_class: sig.typ().map(u8::from).unwrap_or(0),
    }
}

/// Metadata of the first signature in a cleartext-signed message.
pub fn cleartext_signature_info(armored: &str) -> Result<SignatureInfo> {
    let (msg, _) = CleartextSignedMessage::from_string(armored)
        .map_err(|e| CoreError::Pgp(format!("parse clearsign: {e}")))?;
    let sig = msg
        .signatures()
        .first()
        .ok_or_else(|| CoreError::Pgp("no signature in message".into()))?;
    Ok(sig_info(&sig.signature))
}

/// Metadata of a detached/standalone signature.
pub fn detached_signature_info(signature_armored: &str) -> Result<SignatureInfo> {
    let (sig, _) = StandaloneSignature::from_string(signature_armored)
        .map_err(|e| CoreError::Pgp(format!("parse signature: {e}")))?;
    Ok(sig_info(&sig.signature))
}
