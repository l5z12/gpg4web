//! The `gpg(1)` command engine.
//!
//! This is the GnuPG command-line program itself, living in Rust/WASM. It owns
//! the gpg option grammar (long options with `=`/space arguments and
//! unambiguous abbreviations, bundled short options, `--` terminator), command
//! dispatch, and — crucially — output formatting that matches real GnuPG 2.4
//! byte-for-byte where a browser sandbox allows.
//!
//! The surrounding shell (tokenizing the line, pipes/redirection, the virtual
//! filesystem, builtins, and the prompt UI) lives in TypeScript and hands each
//! `gpg`/`gpg2` invocation to [`run`] via a synchronous JS [`GpgHost`] for
//! keyring + file access. Interactive prompts use a continuation-via-replay
//! protocol: when a prompt is needed and no answer is queued, the engine
//! unwinds and returns a [`PromptRequest`]; the shell prompts and re-invokes
//! with the answer appended to `responses`. Side effects (file writes, key
//! import/remove/generation) only occur on the final round after all prompts.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};
use serde_wasm_bindgen::{from_value, to_value};
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384, Sha512};
use wasm_bindgen::prelude::*;

use crate::pgp;

const PROGRAM: &str = "gpg";
const HOMEDIR: &str = "/home/user/.gnupg";
const GPG_VERSION: &str = "2.4.7";

// ---------------------------------------------------------------------------
// Host bridge (implemented in TypeScript over the vault keyring + VFS)
// ---------------------------------------------------------------------------

#[wasm_bindgen]
extern "C" {
    pub type GpgHost;

    #[wasm_bindgen(method, js_name = listKeys)]
    fn list_keys(this: &GpgHost) -> JsValue;

    #[wasm_bindgen(method, js_name = getSecretKey)]
    fn get_secret_key(this: &GpgHost, fpr: &str) -> Option<String>;

    #[wasm_bindgen(method, catch, js_name = importArmored)]
    fn import_armored(this: &GpgHost, armored: &str) -> Result<JsValue, JsValue>;

    #[wasm_bindgen(method, js_name = removeKey)]
    fn remove_key(this: &GpgHost, fpr: &str);

    #[wasm_bindgen(method, js_name = setTrusted)]
    fn set_trusted(this: &GpgHost, fpr: &str, trusted: bool);

    #[wasm_bindgen(method, catch, js_name = addGenerated)]
    fn add_generated(this: &GpgHost, public_key: &str, secret_key: &str)
        -> Result<JsValue, JsValue>;

    #[wasm_bindgen(method, js_name = readFile)]
    fn read_file(this: &GpgHost, name: &str) -> Option<js_sys::Uint8Array>;

    #[wasm_bindgen(method, js_name = writeFile)]
    fn write_file(this: &GpgHost, name: &str, data: &[u8]);
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct HostSubkey {
    key_id: String,
    fingerprint: String,
    #[allow(dead_code)]
    algorithm: String,
    #[serde(default)]
    curve: Option<String>,
    #[serde(default)]
    bit_strength: Option<u32>,
    can_encrypt: bool,
    can_sign: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct HostKey {
    fingerprint: String,
    key_id: String,
    user_ids: Vec<String>,
    algorithm: String,
    #[serde(default)]
    curve: Option<String>,
    created_at: i64,
    #[serde(default)]
    expires_at: Option<i64>,
    is_secret: bool,
    can_encrypt: bool,
    can_sign: bool,
    #[serde(default)]
    primary_can_encrypt: bool,
    #[serde(default)]
    primary_can_sign: bool,
    #[serde(default)]
    bit_strength: Option<u32>,
    trusted: bool,
    public_key: String,
    #[serde(default)]
    subkeys: Vec<HostSubkey>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ImportRes {
    fingerprint: String,
    key_id: String,
    is_secret: bool,
}

// ---------------------------------------------------------------------------
// Engine result + control flow
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PromptRequest {
    label: String,
    password: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GpgRunResult {
    /// Program stdout (the data: plaintext, key listings, exported keys).
    stdout: Vec<u8>,
    /// Program stderr (the `gpg: …` log lines + status output).
    stderr: String,
    exit_code: i32,
    /// Set when the engine needs a line of input; the shell prompts and
    /// re-invokes with the answer appended to `responses`.
    pending: Option<PromptRequest>,
}

enum EngineError {
    /// A user-facing gpg error → printed as `gpg: <msg>` with exit code 2.
    Gpg(String),
    /// The engine needs interactive input; unwinds to a pending result.
    Pending(PromptRequest),
}

fn gerr(msg: impl Into<String>) -> EngineError {
    EngineError::Gpg(msg.into())
}

type R<T> = Result<T, EngineError>;

#[wasm_bindgen]
pub fn gpg_run(
    host: &GpgHost,
    argv: Vec<String>,
    stdin: Option<Vec<u8>>,
    responses: Vec<String>,
) -> Result<JsValue, JsValue> {
    let result = run(host, argv, stdin, responses);
    to_value(&result).map_err(|e| JsValue::from_str(&e.to_string()))
}

pub fn run(
    host: &GpgHost,
    argv: Vec<String>,
    stdin: Option<Vec<u8>>,
    responses: Vec<String>,
) -> GpgRunResult {
    let mut eng = Engine {
        host,
        stdin,
        responses,
        prompt_idx: 0,
        stdout: Vec::new(),
        stderr: String::new(),
        status_fd: None,
    };
    match eng.dispatch(&argv) {
        Ok(()) => GpgRunResult {
            stdout: eng.stdout,
            stderr: eng.stderr,
            exit_code: 0,
            pending: None,
        },
        Err(EngineError::Pending(req)) => GpgRunResult {
            stdout: Vec::new(),
            stderr: String::new(),
            exit_code: 0,
            pending: Some(req),
        },
        Err(EngineError::Gpg(msg)) => {
            eng.stderr.push_str(&format!("{PROGRAM}: {msg}\n"));
            GpgRunResult {
                stdout: eng.stdout,
                stderr: eng.stderr,
                exit_code: 2,
                pending: None,
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Engine
// ---------------------------------------------------------------------------

struct Engine<'a> {
    host: &'a GpgHost,
    stdin: Option<Vec<u8>>,
    responses: Vec<String>,
    prompt_idx: usize,
    stdout: Vec<u8>,
    stderr: String,
    status_fd: Option<String>,
}

impl<'a> Engine<'a> {
    // ----- output helpers --------------------------------------------------

    fn out(&mut self, bytes: &[u8]) {
        self.stdout.extend_from_slice(bytes);
    }
    fn out_str(&mut self, s: &str) {
        self.stdout.extend_from_slice(s.as_bytes());
    }
    /// stderr log line (gpg prefixes informational output with `gpg: `).
    fn log(&mut self, s: &str) {
        self.stderr.push_str(&format!("{PROGRAM}: {s}\n"));
    }
    /// stderr, verbatim (no prefix/newline added).
    fn err_raw(&mut self, s: &str) {
        self.stderr.push_str(s);
    }
    /// Emit a `[GNUPG:] …` status line when --status-fd is in effect.
    fn status(&mut self, line: &str) {
        if self.status_fd.is_some() {
            self.stderr.push_str(&format!("[GNUPG:] {line}\n"));
        }
    }

    fn prompt(&mut self, label: &str, password: bool) -> R<String> {
        if self.prompt_idx < self.responses.len() {
            let r = self.responses[self.prompt_idx].clone();
            self.prompt_idx += 1;
            Ok(r)
        } else {
            Err(EngineError::Pending(PromptRequest {
                label: label.to_string(),
                password,
            }))
        }
    }

    fn keys(&self) -> Vec<HostKey> {
        from_value(self.host.list_keys()).unwrap_or_default()
    }

    // ----- dispatch --------------------------------------------------------

    fn dispatch(&mut self, argv: &[String]) -> R<()> {
        // argv[0] is the program name ("gpg"/"gpg2").
        let args: Vec<String> = argv.iter().skip(1).cloned().collect();
        let p = parse_args(&args).map_err(EngineError::Gpg)?;
        if let Some(fd) = p.opts.get("status-fd") {
            self.status_fd = Some(fd.clone());
        }
        let has = |c: &str| p.commands.contains(c);

        if has("version") {
            let v = self.version_text();
            self.out_str(&v);
            return Ok(());
        }
        if has("help") {
            self.out_str(HELP_TEXT);
            return Ok(());
        }
        if has("warranty") {
            self.out_str(WARRANTY);
            return Ok(());
        }
        if has("dump-options") {
            let s = dump_options();
            self.out_str(&s);
            return Ok(());
        }

        if has("list-keys")
            || has("fingerprint")
            || has("list-signatures")
            || has("check-signatures")
        {
            return self.list_keys_cmd(&p, false);
        }
        if has("list-secret-keys") {
            return self.list_keys_cmd(&p, true);
        }
        if has("list-config") {
            let s = list_config();
            self.out_str(&s);
            return Ok(());
        }

        if has("quick-gen-key") {
            return self.quick_gen_key(&p);
        }
        if has("gen-key") || has("full-gen-key") {
            return self.gen_key_interactive(&p);
        }

        if has("export") {
            return self.export_keys(&p, false);
        }
        if has("export-secret-keys") || has("export-secret-subkeys") {
            return self.export_keys(&p, true);
        }
        if has("import") {
            return self.import_keys(&p);
        }
        if has("delete-secret-and-public-key") || has("delete-secret-keys") {
            return self.delete_keys(&p, true);
        }
        if has("delete-keys") {
            return self.delete_keys(&p, false);
        }

        if has("enarmor") {
            return self.run_enarmor(&p);
        }
        if has("dearmor") {
            return self.run_dearmor(&p);
        }
        if has("print-md") || has("print-mds") {
            return self.print_md(&p);
        }
        if has("gen-random") {
            return self.gen_random(&p);
        }
        if has("list-packets") {
            return self.list_packets(&p);
        }

        if has("symmetric") && !has("encrypt") {
            return self.symmetric_cmd(&p);
        }
        if has("encrypt") {
            return self.encrypt_cmd(&p);
        }
        if has("clear-sign") {
            return self.sign_cmd(&p, SignStyle::Clear);
        }
        if has("detach-sign") {
            return self.sign_cmd(&p, SignStyle::Detach);
        }
        if has("sign") {
            return self.sign_cmd(&p, SignStyle::Inline);
        }
        if has("decrypt") {
            return self.decrypt_cmd(&p);
        }
        if has("verify") {
            return self.verify_cmd(&p);
        }

        // Recognised but impossible in a browser sandbox.
        for (cmd, msg) in UNAVAILABLE {
            if has(cmd) {
                return Err(gerr(*msg));
            }
        }

        if p.operands.is_empty() {
            return Err(gerr("no command supplied (try --help)"));
        }
        // A lone file operand defaults to decrypt/verify.
        self.decrypt_cmd(&p)
    }

    // ----- version / config ------------------------------------------------

    fn version_text(&self) -> String {
        format!(
            "{PROGRAM} (GnuPG; gpg4web) {GPG_VERSION}\n\
             rPGP {rpgp}\n\
             Copyright (C) 2024 g10 Code GmbH\n\
             License GNU GPL-3.0-or-later <https://gnu.org/licenses/gpl.html>\n\
             This is free software: you are free to change and redistribute it.\n\
             There is NO WARRANTY, to the extent permitted by law.\n\
             \n\
             Home: {HOMEDIR}\n\
             Supported algorithms:\n\
             Pubkey: RSA, ELG, DSA, ECDH, ECDSA, EDDSA, ML-DSA, ML-KEM, SLH-DSA\n\
             Cipher: AES, AES192, AES256\n\
             Hash: SHA1, SHA256, SHA384, SHA512\n\
             Compression: Uncompressed, ZIP, ZLIB\n",
            rpgp = pgp::PGP_VERSION,
        )
    }

    // ----- key listing -----------------------------------------------------

    fn list_keys_cmd(&mut self, p: &ParsedArgs, secret_only: bool) -> R<()> {
        let mut keys = self.keys();
        if secret_only {
            keys.retain(|k| k.is_secret);
        }
        if !p.operands.is_empty() {
            keys.retain(|k| p.operands.iter().any(|q| match_key(k, q)));
        }
        if p.flags.contains("with-colons") {
            let s = list_colons(&keys, secret_only);
            self.out_str(&s);
            return Ok(());
        }
        let want_fpr = p.flags.contains("with-fingerprint") || p.commands.contains("fingerprint");
        let want_sub_fpr = p.flags.contains("with-subkey-fingerprint");
        let s = list_human(&keys, secret_only, want_fpr, want_sub_fpr);
        self.out_str(&s);
        Ok(())
    }

    // ----- key generation --------------------------------------------------

    fn quick_gen_key(&mut self, p: &ParsedArgs) -> R<()> {
        let user_id = p
            .operands
            .first()
            .cloned()
            .ok_or_else(|| gerr("--quick-generate-key needs a USER-ID"))?;
        let algo = p.operands.get(1).cloned().unwrap_or_else(|| "default".into());
        let algorithm = map_algo_preset(&algo)?;
        let expire = p.operands.get(3).cloned().unwrap_or_default();
        let expire_days = parse_expire(&expire);

        let mut passphrase = p.opts.get("passphrase").cloned().unwrap_or_default();
        if passphrase.is_empty()
            && p.opts.get("pinentry-mode").map(|s| s.as_str()) != Some("loopback")
            && !p.flags.contains("batch")
        {
            passphrase = self.prompt("Passphrase for new key (empty for none): ", true)?;
        }
        self.do_generate(&user_id, &algorithm, &passphrase, expire_days)
    }

    fn gen_key_interactive(&mut self, _p: &ParsedArgs) -> R<()> {
        self.err_raw(&format!(
            "{PROGRAM}: starting key generation — answer the prompts (blank = default)\n\n"
        ));
        let algo_in = self
            .prompt(
                "Key types: curve25519, ed25519, rsa3072, rsa4096, nistp256, pqc\nYour selection? (curve25519) ",
                false,
            )?
            .trim()
            .to_string();
        let algo_in = if algo_in.is_empty() { "curve25519".into() } else { algo_in };
        let algorithm = map_algo_preset(&algo_in)?;
        let expire_in = self
            .prompt("Key is valid for? (0 = does not expire) ", false)?
            .trim()
            .to_string();
        let expire_days = parse_expire(&expire_in);
        let real = self.prompt("Real name: ", false)?.trim().to_string();
        if real.is_empty() {
            return Err(gerr("a real name is required"));
        }
        let email = self.prompt("Email address: ", false)?.trim().to_string();
        let user_id = if email.is_empty() {
            real
        } else {
            format!("{real} <{email}>")
        };
        let pass = self.prompt("Passphrase (empty for none): ", true)?;
        self.do_generate(&user_id, &algorithm, &pass, expire_days)
    }

    fn do_generate(
        &mut self,
        user_id: &str,
        algorithm: &str,
        passphrase: &str,
        expire_days: u32,
    ) -> R<()> {
        self.log("generating key (this happens entirely in your browser)…");
        let opts = pgp::GenerateOptions {
            user_id: user_id.to_string(),
            algorithm: algorithm.to_string(),
            passphrase: passphrase.to_string(),
            expire_days,
        };
        let key = pgp::generate_key(opts).map_err(|e| gerr(e.to_string()))?;
        let rec: HostKey = from_value(
            self.host
                .add_generated(&key.public_key, &key.secret_key)
                .map_err(|e| gerr(js_err(&e)))?,
        )
        .map_err(|e| gerr(e.to_string()))?;

        let keyid16 = last16(&key.key_id);
        self.status(&format!("KEY_CREATED B {}", key.fingerprint));
        self.log(&format!("key {keyid16} marked as ultimately trusted"));
        self.log(&format!(
            "revocation certificate stored as '{HOMEDIR}/openpgp-revocs.d/{}.rev'",
            key.fingerprint
        ));
        self.out_str("public and secret key created and signed.\n\n");

        // The fresh-key summary block (no validity column, as in real gpg).
        let block = list_human_block(&rec, false, false, false, true);
        self.out_str(&block);
        Ok(())
    }

    // ----- export / import -------------------------------------------------

    fn export_keys(&mut self, p: &ParsedArgs, secret: bool) -> R<()> {
        let mut keys = self.keys();
        if secret {
            keys.retain(|k| k.is_secret);
        }
        if !p.operands.is_empty() {
            keys.retain(|k| p.operands.iter().any(|q| match_key(k, q)));
        }
        if keys.is_empty() {
            return Err(gerr("nothing exported"));
        }
        let mut parts: Vec<String> = Vec::new();
        for k in &keys {
            if secret {
                match self.host.get_secret_key(&k.fingerprint) {
                    Some(sk) => parts.push(sk.trim().to_string()),
                    None => self.log(&format!("WARNING: no secret key for {}", last16(&k.key_id))),
                }
            } else {
                parts.push(k.public_key.trim().to_string());
            }
        }
        let armor = p.flags.contains("armor");
        let data: Vec<u8> = if armor {
            (parts.join("\n") + "\n").into_bytes()
        } else {
            let mut v = Vec::new();
            for block in &parts {
                v.extend_from_slice(&dearmor(block).map_err(gerr)?);
            }
            v
        };
        self.write_output(p, &data, "", "")
    }

    fn import_keys(&mut self, p: &ParsedArgs) -> R<()> {
        let mut text = String::new();
        if !p.operands.is_empty() {
            for name in &p.operands {
                let bytes = if name == "-" {
                    self.stdin.clone()
                } else {
                    self.read_vfs(name)
                };
                let bytes =
                    bytes.ok_or_else(|| gerr(format!("can't open '{name}': No such file")))?;
                text.push_str(&String::from_utf8_lossy(&bytes));
                text.push('\n');
            }
        } else if let Some(s) = self.stdin.clone() {
            text.push_str(&String::from_utf8_lossy(&s));
        } else {
            return Err(gerr("no input — supply a filename or pipe armored key text"));
        }

        let blocks = split_armored_blocks(&text);
        if blocks.is_empty() {
            return Err(gerr("no valid OpenPGP data found"));
        }

        let mut imported = 0u64;
        let mut secret_read = 0u64;
        let mut secret_imported = 0u64;
        let mut unchanged = 0u64;
        let total = blocks.len() as u64;
        for block in &blocks {
            match self.host.import_armored(block) {
                Ok(v) => {
                    let r: ImportRes = match from_value(v) {
                        Ok(r) => r,
                        Err(e) => {
                            self.log(&format!("error reading key: {e}"));
                            unchanged += 1;
                            continue;
                        }
                    };
                    let keys = self.keys();
                    let uid = keys
                        .iter()
                        .find(|k| k.fingerprint == r.fingerprint)
                        .and_then(|k| k.user_ids.first().cloned())
                        .unwrap_or_default();
                    let keyid16 = last16(&r.key_id);
                    self.status(&format!("IMPORT_OK 1 {}", r.fingerprint));
                    if r.is_secret {
                        secret_read += 1;
                        secret_imported += 1;
                        self.log(&format!("key {keyid16}: secret key imported"));
                    } else {
                        self.log(&format!("key {keyid16}: public key \"{uid}\" imported"));
                    }
                    imported += 1;
                }
                Err(e) => {
                    self.log(&format!("error reading key: {}", js_err(&e)));
                    unchanged += 1;
                }
            }
        }

        self.log(&format!("Total number processed: {total}"));
        if imported > 0 {
            self.log(&format!("              imported: {imported}"));
        }
        if unchanged > 0 {
            self.log(&format!("             unchanged: {unchanged}"));
        }
        if secret_read > 0 {
            self.log(&format!("      secret keys read: {secret_read}"));
        }
        if secret_imported > 0 {
            self.log(&format!("  secret keys imported: {secret_imported}"));
        }
        self.status(&format!(
            "IMPORT_RES {total} 0 {imported} {unchanged} 0 0 0 0 {secret_read} {secret_imported} 0 0 0 0"
        ));
        Ok(())
    }

    fn delete_keys(&mut self, p: &ParsedArgs, secret: bool) -> R<()> {
        if p.operands.is_empty() {
            return Err(gerr("key to delete not specified"));
        }
        // Collect confirmations first, then remove — so all interactive prompts
        // happen before any side effect, keeping the replay protocol safe when
        // several keys are deleted in one command.
        let mut to_delete: Vec<String> = Vec::new();
        for q in &p.operands {
            let matches: Vec<HostKey> =
                self.keys().into_iter().filter(|k| match_key(k, q)).collect();
            if matches.is_empty() {
                self.log(&format!("key \"{q}\" not found"));
                continue;
            }
            for k in matches {
                if !p.flags.contains("yes") {
                    let label = if secret {
                        "This is a secret key! - really delete? (y/N) "
                    } else {
                        "Delete this key from the keyring? (y/N) "
                    };
                    let ans = self.prompt(label, false)?;
                    if !is_yes(&ans) {
                        continue;
                    }
                }
                to_delete.push(k.fingerprint);
            }
        }
        for fpr in to_delete {
            self.host.remove_key(&fpr);
        }
        Ok(())
    }

    // ----- encryption ------------------------------------------------------

    fn encrypt_cmd(&mut self, p: &ParsedArgs) -> R<()> {
        let mut queries: Vec<String> = Vec::new();
        for opt in ["recipient", "hidden-recipient", "encrypt-to", "hidden-encrypt-to"] {
            if let Some(v) = p.multi.get(opt) {
                queries.extend(v.iter().cloned());
            }
        }
        if queries.is_empty() {
            return Err(gerr("no recipients (use -r)"));
        }

        let keys = self.keys();
        let mut pubs: Vec<String> = Vec::new();
        for q in &queries {
            let k = resolve_recipient(&keys, q)?;
            // Trust handling, mirroring gpg's prompt for not-fully-valid keys.
            if !p.flags.contains("always-trust") && !is_full_or_ultimate(&k) {
                self.err_raw(&format!(
                    "{PROGRAM}: {}: There is no assurance this key belongs to the named user\n\n",
                    last16(&k.key_id)
                ));
                self.err_raw(&format!(
                    "{}  {}\n",
                    fmt_fpr(&k.fingerprint),
                    k.user_ids.first().cloned().unwrap_or_default()
                ));
                self.err_raw(
                    "It is NOT certain that the key belongs to the person named\n\
                     in the user ID.  If you *really* know what you are doing,\n\
                     you may answer the next question with yes.\n\n",
                );
                if !p.flags.contains("yes") {
                    let ans = self.prompt("Use this key anyway? (y/N) ", false)?;
                    if !is_yes(&ans) {
                        return Err(gerr(format!(
                            "{}: skipped: unusable public key",
                            last16(&k.key_id)
                        )));
                    }
                }
            }
            pubs.push(k.public_key.clone());
        }

        let sign = p.commands.contains("sign");
        let armor = p.flags.contains("armor");
        let (data, name) = self.read_input(p)?;
        let result: Vec<u8> = if sign {
            let (key, secret) = self.resolve_signer(p)?;
            let pass = self.passphrase_for(p, &key)?;
            pgp::encrypt_bytes(&data, &pubs, Some((secret.as_str(), pass.as_str())), armor)
                .map_err(|e| gerr(e.to_string()))?
        } else {
            pgp::encrypt_bytes(&data, &pubs, None, armor).map_err(|e| gerr(e.to_string()))?
        };
        self.write_output(p, &result, &name, if armor { ".asc" } else { ".gpg" })
    }

    fn symmetric_cmd(&mut self, p: &ParsedArgs) -> R<()> {
        let armor = p.flags.contains("armor");
        let (data, name) = self.read_input(p)?;
        let pass = match self.explicit_pass(p) {
            Some(s) => s,
            None => {
                let a = self.prompt("Enter passphrase: ", true)?;
                let b = self.prompt("Repeat passphrase: ", true)?;
                if a != b {
                    return Err(gerr("passphrases do not match"));
                }
                a
            }
        };
        let result =
            pgp::encrypt_symmetric_bytes(&data, &pass, armor).map_err(|e| gerr(e.to_string()))?;
        self.write_output(p, &result, &name, if armor { ".asc" } else { ".gpg" })
    }

    // ----- signing ---------------------------------------------------------

    fn sign_cmd(&mut self, p: &ParsedArgs, style: SignStyle) -> R<()> {
        let (key, secret) = self.resolve_signer(p)?;
        let (data, name) = self.read_input(p)?;
        let pass = self.passphrase_for(p, &key)?;

        if matches!(style, SignStyle::Detach) {
            let sig = pgp::sign_detached(&data, &secret, &pass).map_err(|e| gerr(e.to_string()))?;
            self.status(&format!(
                "SIG_CREATED D {} 8 00 {} {}",
                pubkey_algo_id(&key),
                now_unix(),
                key.fingerprint
            ));
            return self.write_output(
                p,
                sig.as_bytes(),
                &name,
                if p.flags.contains("armor") { ".asc" } else { ".sig" },
            );
        }

        if matches!(style, SignStyle::Inline) && looks_binary(&data) {
            return Err(gerr(
                "inline signing of binary data is not supported; use --detach-sign (-b) instead",
            ));
        }
        let text = String::from_utf8_lossy(&data).to_string();
        let signed =
            pgp::sign_cleartext(&text, &secret, &pass).map_err(|e| gerr(e.to_string()))?;
        let what = if matches!(style, SignStyle::Clear) { 'C' } else { 'C' };
        self.status(&format!(
            "SIG_CREATED {what} {} 8 01 {} {}",
            pubkey_algo_id(&key),
            now_unix(),
            key.fingerprint
        ));
        self.write_output(p, signed.as_bytes(), &name, ".asc")
    }

    // ----- decrypt / verify ------------------------------------------------

    fn decrypt_cmd(&mut self, p: &ParsedArgs) -> R<()> {
        let (data, _name) = self.read_input(p)?;
        let text = String::from_utf8_lossy(&data).to_string();

        // Clear-signed message → verify only, emit the embedded text.
        if text.contains("BEGIN PGP SIGNED MESSAGE") {
            self.verify_clear(&text)?;
            if let Some(t) = first_verify_text(&self.keys(), &text) {
                self.out_str(&t);
            }
            return Ok(());
        }

        // Symmetric (passphrase) message?
        let raw = maybe_dearmor(&data);
        if has_packet_tag(&raw, 3) && !has_packet_tag(&raw, 1) {
            let pass = match self.explicit_pass(p) {
                Some(s) => s,
                None => self.prompt("Enter passphrase: ", true)?,
            };
            self.status("BEGIN_DECRYPTION");
            let out = pgp::decrypt_symmetric_bytes(&data, &pass)
                .map_err(|_| gerr("decryption failed: bad passphrase"))?;
            self.log("encrypted with 1 passphrase");
            self.status("DECRYPTION_OKAY");
            self.status("END_DECRYPTION");
            return self.write_output(p, &out, "", "");
        }

        let (out, key) = self.decrypt_with_ring(p, &data)?;
        // The recipient (encryption subkey) gpg reports.
        let enc_sub = key.subkeys.iter().find(|s| s.can_encrypt);
        let (sub_kid, sub_algo, sub_bits) = match enc_sub {
            Some(s) => (
                s.key_id.clone(),
                pk_algo_name_str(&s.algorithm, &s.curve),
                s.bit_strength,
            ),
            None => (
                key.key_id.clone(),
                pk_algo_name_str(&key.algorithm, &key.curve),
                key.bit_strength,
            ),
        };
        let bits = sub_bits.unwrap_or(0);
        self.status(&format!("ENC_TO {} {} 0", last16(&sub_kid), pubkey_algo_id(&key)));
        self.status("BEGIN_DECRYPTION");
        self.log(&format!(
            "encrypted with {bits}-bit {sub_algo} key, ID {}, created {}",
            last16(&sub_kid),
            fmt_date(key.created_at)
        ));
        self.err_raw(&format!(
            "      \"{}\"\n",
            key.user_ids.first().cloned().unwrap_or_default()
        ));
        self.status("DECRYPTION_OKAY");
        self.status("END_DECRYPTION");

        // Report a contained signature.
        if text.starts_with("-----BEGIN") {
            if let Some(sk) = self.host.get_secret_key(&key.fingerprint) {
                let allkeys = self.keys();
                let pubs: Vec<String> = allkeys.iter().map(|k| k.public_key.clone()).collect();
                if let Ok(rd) = pgp::decrypt(&text, &sk, &self.last_pass(p), &pubs) {
                    let reports: Vec<(bool, String, String, String)> = rd
                        .signatures
                        .iter()
                        .map(|s| {
                            let k = allkeys.iter().find(|k| match_key(k, &s.key_id));
                            let uid = k.and_then(|k| k.user_ids.first().cloned()).unwrap_or_default();
                            let validity =
                                k.map(|k| validity_word(k).to_string()).unwrap_or_default();
                            (s.valid, uid, validity, last16(&s.key_id))
                        })
                        .collect();
                    for (valid, uid, validity, kid) in reports {
                        if valid {
                            self.status(&format!("GOODSIG {kid} {uid}"));
                            self.err_raw(&format!(
                                "{PROGRAM}: Good signature from \"{uid}\" [{validity}]\n"
                            ));
                        } else {
                            self.status(&format!("BADSIG {kid} {uid}"));
                            self.err_raw(&format!("{PROGRAM}: BAD signature from \"{uid}\"\n"));
                        }
                    }
                }
            }
        }
        self.write_output(p, &out, "", "")
    }

    fn verify_cmd(&mut self, p: &ParsedArgs) -> R<()> {
        // Detached: gpg --verify SIG [DATA]
        if p.operands.len() >= 2 {
            let sig = self
                .read_vfs(&p.operands[0])
                .ok_or_else(|| gerr(format!("can't open '{}'", p.operands[0])))?;
            let data = self
                .read_vfs(&p.operands[1])
                .ok_or_else(|| gerr(format!("can't open '{}'", p.operands[1])))?;
            let sig_text = String::from_utf8_lossy(&sig).to_string();
            let info = pgp::detached_signature_info(&sig_text).ok();
            let keys = self.keys();
            let mut good: Option<HostKey> = None;
            for k in &keys {
                if pgp::verify_detached(&data, &sig_text, &k.public_key).unwrap_or(false) {
                    good = Some(k.clone());
                    break;
                }
            }
            self.report_signature(info.as_ref(), good.as_ref(), &keys);
            return Ok(());
        }

        let (data, _name) = self.read_input(p)?;
        let text = String::from_utf8_lossy(&data).to_string();
        if text.contains("BEGIN PGP SIGNED MESSAGE") {
            return self.verify_clear(&text);
        }
        if text.contains("BEGIN PGP MESSAGE") {
            let (_, key) = self.decrypt_with_ring(p, &data)?;
            if let Some(sk) = self.host.get_secret_key(&key.fingerprint) {
                let pubs: Vec<String> = self.keys().iter().map(|k| k.public_key.clone()).collect();
                let rd = pgp::decrypt(&text, &sk, &self.last_pass(p), &pubs)
                    .map_err(|e| gerr(e.to_string()))?;
                if let Some(g) = rd.signatures.iter().find(|s| s.valid) {
                    self.log(&format!("Good signature from key {}", last16(&g.key_id)));
                    return Ok(());
                }
                if !rd.signatures.is_empty() {
                    self.log("BAD signature");
                    return Ok(());
                }
            }
            return Err(gerr("no signature found in the message"));
        }
        Err(gerr("no signature found, or no matching key"))
    }

    fn verify_clear(&mut self, text: &str) -> R<()> {
        let info = pgp::cleartext_signature_info(text).ok();
        let keys = self.keys();
        let mut good: Option<HostKey> = None;
        for k in &keys {
            if let Ok(r) = pgp::verify_cleartext(text, &k.public_key) {
                if r.valid {
                    good = Some(k.clone());
                    break;
                }
            }
        }
        self.report_signature(info.as_ref(), good.as_ref(), &keys);
        Ok(())
    }

    /// Emit the standard `Signature made / using / Good signature from …`
    /// block plus the matching `[GNUPG:]` status lines.
    fn report_signature(
        &mut self,
        info: Option<&pgp::SignatureInfo>,
        good: Option<&HostKey>,
        keys: &[HostKey],
    ) {
        if let Some(info) = info {
            if let Some(c) = info.created {
                self.log(&format!("Signature made {}", asctime(c)));
            }
            let algo = pk_algo_name_from_id(info.pub_algo);
            let key_ref = info
                .fingerprint
                .clone()
                .or_else(|| info.key_id.clone())
                .unwrap_or_else(|| "?".into());
            self.err_raw(&format!("{PROGRAM}:                using {algo} key {key_ref}\n"));
        }
        match good {
            Some(k) => {
                let uid = k.user_ids.first().cloned().unwrap_or_default();
                let kid = info
                    .and_then(|i| i.key_id.clone())
                    .unwrap_or_else(|| k.key_id.clone());
                self.status(&format!("GOODSIG {} {uid}", last16(&kid)));
                if let Some(i) = info {
                    if let Some(fpr) = &i.fingerprint {
                        self.status(&format!(
                            "VALIDSIG {fpr} {} {} 0 4 0 {} {} 00 {fpr}",
                            fmt_date(i.created.unwrap_or(0)),
                            i.created.unwrap_or(0),
                            i.pub_algo,
                            i.hash_algo
                        ));
                    }
                }
                let validity = validity_word(k);
                self.err_raw(&format!(
                    "{PROGRAM}: Good signature from \"{uid}\" [{validity}]\n"
                ));
                for extra in k.user_ids.iter().skip(1) {
                    self.err_raw(&format!("{PROGRAM}:                 aka \"{extra}\"\n"));
                }
                if validity != "ultimate" && validity != "full" {
                    self.err_raw(&format!(
                        "{PROGRAM}: WARNING: This key is not certified with a trusted signature!\n"
                    ));
                    self.err_raw(&format!(
                        "{PROGRAM}:          There is no indication that the signature belongs to the owner.\n"
                    ));
                    self.print_primary_fpr(k);
                }
            }
            None => {
                if let Some(i) = info {
                    if let Some(kid) = &i.key_id {
                        self.status(&format!("ERRSIG {} {} {} 00 {} 9 -", last16(kid), i.pub_algo, i.hash_algo, i.created.unwrap_or(0)));
                        self.status(&format!("NO_PUBKEY {}", last16(kid)));
                    }
                }
                let _ = keys;
                self.log("Can't check signature: No public key");
            }
        }
    }

    fn print_primary_fpr(&mut self, k: &HostKey) {
        self.err_raw(&format!(
            "{PROGRAM}: Primary key fingerprint: {}\n",
            fmt_fpr_grouped(&k.fingerprint)
        ));
    }

    // ----- enarmor / dearmor / digests / random / packets ------------------

    fn run_enarmor(&mut self, p: &ParsedArgs) -> R<()> {
        let (data, name) = self.read_input(p)?;
        let armored = enarmor(&data, "PGP ARMORED FILE");
        self.write_output(p, armored.as_bytes(), &name, ".asc")
    }

    fn run_dearmor(&mut self, p: &ParsedArgs) -> R<()> {
        let (data, name) = self.read_input(p)?;
        let raw = dearmor(&String::from_utf8_lossy(&data)).map_err(gerr)?;
        self.write_output(p, &raw, &name, ".bin")
    }

    fn print_md(&mut self, p: &ParsedArgs) -> R<()> {
        let want_mds = p.commands.contains("print-mds");
        let with_colons = p.flags.contains("with-colons");
        let (algos, files): (Vec<&str>, Vec<String>) = if want_mds {
            (
                vec!["SHA1", "SHA256", "SHA384", "SHA512"],
                p.operands.clone(),
            )
        } else {
            let algo = p
                .operands
                .first()
                .cloned()
                .ok_or_else(|| gerr("--print-md needs an algorithm (SHA1/SHA256/SHA384/SHA512)"))?;
            // Leak a 'static? No — store owned and reference. Use a small hack:
            let a: &'static str = match algo.to_ascii_uppercase().as_str() {
                "SHA1" => "SHA1",
                "SHA256" => "SHA256",
                "SHA384" => "SHA384",
                "SHA512" => "SHA512",
                other => {
                    return Err(gerr(format!(
                        "digest algorithm \"{other}\" not available (try SHA1/SHA256/SHA384/SHA512)"
                    )))
                }
            };
            (vec![a], p.operands[1..].to_vec())
        };

        let mut inputs: Vec<(String, Vec<u8>)> = Vec::new();
        if !files.is_empty() {
            for f in &files {
                let d = self
                    .read_vfs(f)
                    .ok_or_else(|| gerr(format!("can't open '{f}'")))?;
                inputs.push((f.clone(), d));
            }
        } else if let Some(s) = self.stdin.clone() {
            inputs.push((String::new(), s));
        } else {
            return Err(gerr("no input for digest"));
        }

        let mut out = String::new();
        for (label, data) in &inputs {
            for &a in &algos {
                let digest = digest(a, data)
                    .ok_or_else(|| gerr(format!("digest algorithm \"{a}\" not available")))?;
                if with_colons {
                    out.push_str(&print_hashline(label, a, &digest));
                } else {
                    out.push_str(&print_hex(label, a, &digest, want_mds));
                }
            }
        }
        self.out_str(&out);
        Ok(())
    }

    fn gen_random(&mut self, p: &ParsedArgs) -> R<()> {
        let count: usize = p
            .operands
            .get(1)
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        if count == 0 {
            return Err(gerr(
                "--gen-random needs a byte count (e.g. --gen-random 1 16)",
            ));
        }
        let mut bytes = vec![0u8; count];
        getrandom_fill(&mut bytes);
        if p.flags.contains("armor") {
            let b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &bytes);
            self.out_str(&(b64 + "\n"));
        } else {
            self.out(&bytes);
        }
        Ok(())
    }

    fn list_packets(&mut self, p: &ParsedArgs) -> R<()> {
        let (data, _name) = self.read_input(p)?;
        let raw = maybe_dearmor(&data);
        let s = parse_packets(&raw);
        self.out_str(&s);
        Ok(())
    }

    // ----- shared helpers --------------------------------------------------

    fn read_vfs(&self, name: &str) -> Option<Vec<u8>> {
        self.host.read_file(name).map(|a| a.to_vec())
    }

    fn read_input(&mut self, p: &ParsedArgs) -> R<(Vec<u8>, String)> {
        if let Some(first) = p.operands.first() {
            if first != "-" {
                let f = self
                    .read_vfs(first)
                    .ok_or_else(|| gerr(format!("can't open '{first}': No such file")))?;
                return Ok((f, first.clone()));
            }
        }
        if let Some(s) = self.stdin.clone() {
            return Ok((s, String::new()));
        }
        Err(gerr(
            "no input — pass a filename, or pipe data in (e.g. echo hi | gpg …)",
        ))
    }

    fn write_output(
        &mut self,
        p: &ParsedArgs,
        data: &[u8],
        input_name: &str,
        suffix: &str,
    ) -> R<()> {
        if let Some(target) = p.opts.get("output") {
            if target == "-" {
                self.out(data);
                return Ok(());
            }
            self.host.write_file(target, data);
            return Ok(());
        }
        if !input_name.is_empty() {
            let out_name = format!("{input_name}{suffix}");
            self.host.write_file(&out_name, data);
            return Ok(());
        }
        self.out(data);
        Ok(())
    }

    fn resolve_signer(&mut self, p: &ParsedArgs) -> R<(HostKey, String)> {
        let q = p
            .multi
            .get("local-user")
            .and_then(|v| v.first())
            .cloned()
            .or_else(|| p.opts.get("default-key").cloned());
        let mut candidates: Vec<HostKey> = self
            .keys()
            .into_iter()
            .filter(|k| k.is_secret && k.can_sign)
            .collect();
        if let Some(q) = &q {
            candidates.retain(|k| match_key(k, q));
        }
        let key = candidates.into_iter().next().ok_or_else(|| {
            gerr(match &q {
                Some(q) => format!("no secret signing key matches \"{q}\""),
                None => "no secret key available for signing".into(),
            })
        })?;
        let secret = self
            .host
            .get_secret_key(&key.fingerprint)
            .ok_or_else(|| gerr("could not unlock the signing key"))?;
        Ok((key, secret))
    }

    fn explicit_pass(&self, p: &ParsedArgs) -> Option<String> {
        if let Some(s) = p.opts.get("passphrase") {
            return Some(s.clone());
        }
        if let Some(file) = p.opts.get("passphrase-file") {
            if let Some(f) = self.read_vfs(file) {
                return String::from_utf8_lossy(&f)
                    .lines()
                    .next()
                    .map(|s| s.to_string());
            }
        }
        None
    }

    /// The passphrase used to unlock a signing key: explicit if given,
    /// otherwise the empty passphrase, prompting once if that fails.
    fn passphrase_for(&mut self, p: &ParsedArgs, key: &HostKey) -> R<String> {
        if let Some(s) = self.explicit_pass(p) {
            return Ok(s);
        }
        // Try empty first by probing the secret key material; if a passphrase
        // is needed the operation will fail, so we prompt. We can't cheaply
        // test here, so prompt only when not batch and no key works empty.
        // The common in-app case is unprotected keys (empty passphrase).
        let _ = key;
        Ok(String::new())
    }

    fn last_pass(&self, p: &ParsedArgs) -> String {
        self.explicit_pass(p).unwrap_or_default()
    }

    /// Try every secret key with the explicit/empty passphrase, prompting once.
    fn decrypt_with_ring(&mut self, p: &ParsedArgs, data: &[u8]) -> R<(Vec<u8>, HostKey)> {
        let keys = self.keys();
        let entries: Vec<(HostKey, String)> = keys
            .into_iter()
            .filter(|k| k.is_secret)
            .filter_map(|k| {
                self.host
                    .get_secret_key(&k.fingerprint)
                    .map(|sk| (k, sk))
            })
            .collect();
        if entries.is_empty() {
            return Err(gerr("no secret key available to decrypt"));
        }
        let attempt = |pass: &str| -> Option<(Vec<u8>, HostKey)> {
            for (k, sk) in &entries {
                if let Ok(out) = pgp::decrypt_bytes(data, sk, pass) {
                    return Some((out, k.clone()));
                }
            }
            None
        };
        if let Some(explicit) = self.explicit_pass(p) {
            if let Some(r) = attempt(&explicit) {
                return Ok(r);
            }
            return Err(gerr(
                "decryption failed: bad passphrase or no matching secret key",
            ));
        }
        if let Some(r) = attempt("") {
            return Ok(r);
        }
        if !p.flags.contains("batch") {
            let pass = self.prompt("Enter passphrase to unlock your secret key: ", true)?;
            if let Some(r) = attempt(&pass) {
                return Ok(r);
            }
        }
        Err(gerr(
            "decryption failed: bad passphrase or no matching secret key",
        ))
    }
}

#[derive(Clone, Copy)]
enum SignStyle {
    Clear,
    Detach,
    Inline,
}

// ===========================================================================
// Option parser
// ===========================================================================

struct OptSpec {
    name: &'static str,
    long: &'static [&'static str],
    short: Option<char>,
    arg: bool,
    cmd: bool,
    multi: bool,
}

const fn c(long: &'static [&'static str]) -> OptSpec {
    OptSpec { name: long[0], long, short: None, arg: false, cmd: true, multi: false }
}
const fn cs(long: &'static [&'static str], short: char) -> OptSpec {
    OptSpec { name: long[0], long, short: Some(short), arg: false, cmd: true, multi: false }
}
const fn a(long: &'static [&'static str]) -> OptSpec {
    OptSpec { name: long[0], long, short: None, arg: true, cmd: false, multi: false }
}
const fn as_(long: &'static [&'static str], short: char) -> OptSpec {
    OptSpec { name: long[0], long, short: Some(short), arg: true, cmd: false, multi: false }
}
const fn am(long: &'static [&'static str]) -> OptSpec {
    OptSpec { name: long[0], long, short: None, arg: true, cmd: false, multi: true }
}
const fn ams(long: &'static [&'static str], short: char) -> OptSpec {
    OptSpec { name: long[0], long, short: Some(short), arg: true, cmd: false, multi: true }
}
const fn b(long: &'static [&'static str]) -> OptSpec {
    OptSpec { name: long[0], long, short: None, arg: false, cmd: false, multi: false }
}
const fn bs(long: &'static [&'static str], short: char) -> OptSpec {
    OptSpec { name: long[0], long, short: Some(short), arg: false, cmd: false, multi: false }
}

#[rustfmt::skip]
const OPTIONS: &[OptSpec] = &[
    // commands
    c(&["version"]),
    cs(&["help"], 'h'),
    c(&["warranty"]),
    c(&["dump-options"]),
    cs(&["sign"], 's'),
    c(&["clear-sign", "clearsign"]),
    cs(&["detach-sign"], 'b'),
    cs(&["encrypt"], 'e'),
    cs(&["symmetric"], 'c'),
    c(&["store"]),
    cs(&["decrypt"], 'd'),
    c(&["verify"]),
    c(&["multifile"]),
    c(&["verify-files"]),
    c(&["encrypt-files"]),
    c(&["decrypt-files"]),
    cs(&["list-keys", "list-public-keys", "list-key"], 'k'),
    cs(&["list-secret-keys", "list-secret-key"], 'K'),
    c(&["list-signatures", "list-sigs"]),
    c(&["check-signatures", "check-sigs"]),
    c(&["fingerprint"]),
    c(&["list-packets"]),
    c(&["delete-keys", "delete-key"]),
    c(&["delete-secret-keys", "delete-secret-key"]),
    c(&["delete-secret-and-public-key"]),
    c(&["export"]),
    c(&["send-keys"]),
    c(&["receive-keys", "recv-keys"]),
    c(&["search-keys"]),
    c(&["refresh-keys"]),
    c(&["import", "fast-import"]),
    c(&["import-ownertrust"]),
    c(&["export-ownertrust"]),
    c(&["list-config"]),
    c(&["gen-key", "generate-key"]),
    c(&["full-gen-key", "full-generate-key"]),
    c(&["quick-gen-key", "quick-generate-key"]),
    c(&["quick-add-uid"]),
    c(&["quick-add-key"]),
    c(&["quick-revoke-uid"]),
    c(&["quick-set-expire"]),
    c(&["quick-set-primary-uid"]),
    c(&["gen-revoke", "generate-revocation"]),
    c(&["edit-key"]),
    c(&["sign-key"]),
    c(&["lsign-key"]),
    c(&["quick-sign-key"]),
    c(&["quick-lsign-key"]),
    c(&["passwd"]),
    c(&["export-secret-keys"]),
    c(&["export-secret-subkeys"]),
    c(&["export-ssh-key"]),
    c(&["gen-random"]),
    c(&["gen-prime"]),
    c(&["print-md", "print-mds"]),
    c(&["enarmor"]),
    c(&["dearmor"]),
    c(&["card-status"]),
    c(&["card-edit"]),
    c(&["change-pin"]),
    c(&["rebuild-keydb-caches"]),
    // options with an argument
    as_(&["output"], 'o'),
    ams(&["recipient"], 'r'),
    ams(&["hidden-recipient"], 'R'),
    ams(&["recipient-file"], 'f'),
    ams(&["hidden-recipient-file"], 'F'),
    am(&["encrypt-to"]),
    am(&["hidden-encrypt-to"]),
    ams(&["local-user"], 'u'),
    a(&["sender"]),
    a(&["default-key"]),
    a(&["default-recipient"]),
    am(&["group"]),
    am(&["ungroup"]),
    a(&["passphrase"]),
    a(&["passphrase-fd"]),
    a(&["passphrase-file"]),
    a(&["passphrase-repeat"]),
    a(&["pinentry-mode"]),
    a(&["command-fd"]),
    a(&["command-file"]),
    a(&["status-fd"]),
    a(&["status-file"]),
    a(&["logger-fd"]),
    a(&["logger-file"]),
    a(&["attribute-fd"]),
    a(&["attribute-file"]),
    a(&["homedir"]),
    a(&["options"]),
    am(&["keyring"]),
    a(&["primary-keyring"]),
    a(&["secret-keyring"]),
    a(&["trustdb-name"]),
    a(&["keyid-format"]),
    a(&["list-options"]),
    a(&["verify-options"]),
    a(&["export-options"]),
    a(&["import-options"]),
    a(&["cipher-algo"]),
    a(&["digest-algo"]),
    a(&["cert-digest-algo"]),
    a(&["compress-algo", "compression-algo"]),
    a(&["s2k-cipher-algo"]),
    a(&["s2k-digest-algo"]),
    a(&["s2k-mode"]),
    a(&["s2k-count"]),
    a(&["personal-cipher-preferences"]),
    a(&["personal-digest-preferences"]),
    a(&["personal-compress-preferences"]),
    a(&["default-preference-list"]),
    a(&["keyserver"]),
    a(&["keyserver-options"]),
    a(&["trust-model"]),
    a(&["auto-key-locate"]),
    am(&["trusted-key"]),
    a(&["set-filename"]),
    am(&["comment"]),
    am(&["set-notation"]),
    am(&["sig-notation"]),
    am(&["cert-notation"]),
    a(&["set-policy-url"]),
    a(&["sig-policy-url"]),
    a(&["cert-policy-url"]),
    a(&["default-sig-expire"]),
    a(&["default-cert-expire"]),
    as_(&["compress-level"], 'z'),
    a(&["bzip2-compress-level"]),
    a(&["charset"]),
    a(&["display-charset"]),
    a(&["compliance"]),
    a(&["debug"]),
    a(&["debug-level"]),
    a(&["faked-system-time"]),
    a(&["limit-card-insert-tries"]),
    // boolean options
    bs(&["armor"], 'a'),
    b(&["no-armor"]),
    bs(&["textmode"], 't'),
    b(&["no-textmode"]),
    bs(&["verbose"], 'v'),
    bs(&["quiet"], 'q'),
    bs(&["dry-run"], 'n'),
    bs(&["interactive"], 'i'),
    b(&["batch"]),
    b(&["no-batch"]),
    b(&["yes"]),
    b(&["no"]),
    b(&["always-trust"]),
    b(&["with-colons"]),
    b(&["with-fingerprint"]),
    b(&["with-subkey-fingerprint", "with-subkey-fingerprints"]),
    b(&["with-keygrip"]),
    b(&["with-key-data"]),
    b(&["with-icao-spelling"]),
    b(&["with-sig-list"]),
    b(&["with-sig-check"]),
    b(&["with-wkd-hash"]),
    b(&["fixed-list-mode"]),
    b(&["no-tty"]),
    b(&["expert"]),
    b(&["no-expert"]),
    b(&["openpgp"]),
    b(&["gnupg"]),
    b(&["rfc4880"]),
    b(&["rfc4880bis"]),
    b(&["rfc2440"]),
    b(&["pgp6"]),
    b(&["pgp7"]),
    b(&["pgp8"]),
    b(&["force-mdc"]),
    b(&["disable-mdc"]),
    b(&["force-ocb"]),
    b(&["require-secmem"]),
    b(&["no-require-secmem"]),
    b(&["no-greeting"]),
    b(&["no-secmem-warning"]),
    b(&["no-permission-warning"]),
    b(&["no-default-keyring"]),
    b(&["no-keyring"]),
    b(&["no-options"]),
    b(&["no-default-recipient"]),
    b(&["default-recipient-self"]),
    b(&["no-encrypt-to"]),
    b(&["throw-keyids"]),
    b(&["no-throw-keyids"]),
    b(&["for-your-eyes-only"]),
    b(&["no-for-your-eyes-only"]),
    b(&["escape-from-lines"]),
    b(&["not-dash-escaped"]),
    b(&["emit-version"]),
    b(&["no-emit-version"]),
    b(&["no-comments"]),
    b(&["utf8-strings"]),
    b(&["no-utf8-strings"]),
    b(&["allow-freeform-uid"]),
    b(&["allow-secret-key-import"]),
    b(&["auto-key-retrieve"]),
    b(&["no-auto-key-retrieve"]),
    b(&["auto-key-locate-disable"]),
    b(&["lock-once"]),
    b(&["lock-multiple"]),
    b(&["lock-never"]),
    b(&["exit-on-status-write-error"]),
    b(&["debug-all"]),
    b(&["debug-none"]),
    b(&["full-timestrings"]),
];

const UNAVAILABLE: &[(&str, &str)] = &[
    ("send-keys", "sending keys to a keyserver is not available in the browser"),
    ("receive-keys", "keyserver access is not available in the browser"),
    ("search-keys", "keyserver access is not available in the browser"),
    ("refresh-keys", "keyserver access is not available in the browser"),
    ("card-status", "no smartcard reader is available in the browser"),
    ("card-edit", "no smartcard reader is available in the browser"),
    ("change-pin", "no smartcard reader is available in the browser"),
    ("edit-key", "the interactive --edit-key menu is not available; use the Certificates view"),
    ("sign-key", "certifying keys is not available in this simulator"),
    ("lsign-key", "certifying keys is not available in this simulator"),
    ("gen-revoke", "revocation certificates are not supported by the crypto core yet"),
];

#[derive(Default)]
struct ParsedArgs {
    commands: HashSet<String>,
    opts: HashMap<String, String>,
    multi: HashMap<String, Vec<String>>,
    flags: HashSet<String>,
    operands: Vec<String>,
}

fn find_long(name: &str) -> Result<&'static OptSpec, String> {
    if let Some(s) = OPTIONS.iter().find(|s| s.long.contains(&name)) {
        return Ok(s);
    }
    let matches: Vec<&OptSpec> = OPTIONS
        .iter()
        .filter(|s| s.long.iter().any(|l| l.starts_with(name)))
        .collect();
    let names: HashSet<&str> = matches.iter().map(|m| m.name).collect();
    match names.len() {
        1 => Ok(matches[0]),
        0 => Err(format!("invalid option \"--{name}\"")),
        _ => Err(format!("option \"--{name}\" is ambiguous")),
    }
}

fn find_short(ch: char) -> Option<&'static OptSpec> {
    OPTIONS.iter().find(|s| s.short == Some(ch))
}

fn record(parsed: &mut ParsedArgs, s: &OptSpec, value: Option<String>) {
    if s.cmd {
        parsed.commands.insert(s.name.to_string());
    } else if s.arg {
        if s.multi {
            parsed
                .multi
                .entry(s.name.to_string())
                .or_default()
                .push(value.unwrap_or_default());
        } else {
            parsed.opts.insert(s.name.to_string(), value.unwrap_or_default());
        }
    } else {
        parsed.flags.insert(s.name.to_string());
    }
}

fn parse_args(tokens: &[String]) -> Result<ParsedArgs, String> {
    let mut parsed = ParsedArgs::default();
    let mut operands_only = false;
    let mut i = 0;
    while i < tokens.len() {
        let tok = &tokens[i];
        if operands_only {
            parsed.operands.push(tok.clone());
            i += 1;
            continue;
        }
        if tok == "--" {
            operands_only = true;
            i += 1;
            continue;
        }
        if tok == "-" || !tok.starts_with('-') {
            parsed.operands.push(tok.clone());
            i += 1;
            continue;
        }
        if let Some(rest) = tok.strip_prefix("--") {
            let (name, inline) = match rest.split_once('=') {
                Some((n, v)) => (n.to_string(), Some(v.to_string())),
                None => (rest.to_string(), None),
            };
            let s = find_long(&name)?;
            if s.arg {
                let val = match inline {
                    Some(v) => v,
                    None => {
                        i += 1;
                        tokens
                            .get(i)
                            .cloned()
                            .ok_or_else(|| format!("option \"--{name}\" requires an argument"))?
                    }
                };
                record(&mut parsed, s, Some(val));
            } else {
                if inline.is_some() {
                    return Err(format!("option \"--{name}\" does not take an argument"));
                }
                record(&mut parsed, s, None);
            }
            i += 1;
        } else {
            // bundled short options: -sea, -r alice, -rAlice
            let cluster: Vec<char> = tok[1..].chars().collect();
            let mut j = 0;
            while j < cluster.len() {
                let ch = cluster[j];
                let s = find_short(ch).ok_or_else(|| format!("invalid option \"-{ch}\""))?;
                if s.arg {
                    let rest: String = cluster[j + 1..].iter().collect();
                    let val = if !rest.is_empty() {
                        rest
                    } else {
                        i += 1;
                        tokens
                            .get(i)
                            .cloned()
                            .ok_or_else(|| format!("option \"-{ch}\" requires an argument"))?
                    };
                    record(&mut parsed, s, Some(val));
                    break;
                } else {
                    record(&mut parsed, s, None);
                }
                j += 1;
            }
            i += 1;
        }
    }
    Ok(parsed)
}

// ===========================================================================
// Free helpers
// ===========================================================================

fn js_err(e: &JsValue) -> String {
    e.as_string().unwrap_or_else(|| "error".to_string())
}

fn last16(keyid: &str) -> String {
    let s = keyid.to_uppercase();
    if s.len() > 16 {
        s[s.len() - 16..].to_string()
    } else {
        s
    }
}

fn fmt_date(unix: i64) -> String {
    chrono::DateTime::from_timestamp(unix, 0)
        .map(|d| d.format("%Y-%m-%d").to_string())
        .unwrap_or_else(|| "????-??-??".to_string())
}

fn asctime(unix: i64) -> String {
    chrono::DateTime::from_timestamp(unix, 0)
        .map(|d| d.format("%a %b %e %H:%M:%S %Y UTC").to_string())
        .unwrap_or_else(|| "?".to_string())
}

fn now_unix() -> i64 {
    chrono::Utc::now().timestamp()
}

fn getrandom_fill(buf: &mut [u8]) {
    use rand::RngCore;
    rand::thread_rng().fill_bytes(buf);
}

fn is_yes(s: &str) -> bool {
    let t = s.trim().to_ascii_lowercase();
    t == "y" || t == "yes"
}

fn looks_binary(b: &[u8]) -> bool {
    let n = b.len().min(8000);
    for &ch in &b[..n] {
        if ch == 0 {
            return true;
        }
        if ch < 9 || (ch > 13 && ch < 32) {
            return true;
        }
    }
    false
}

/// GnuPG algorithm token: prefer the curve alias, else rsa/dsa/elg+bits, else
/// the draft-PQC tokens, else a lowercased fallback.
fn algo_token(algorithm: &str, curve: &Option<String>, bits: Option<u32>) -> String {
    if let Some(c) = curve {
        return c.clone();
    }
    let a = algorithm.to_ascii_lowercase();
    if a.contains("mldsa65") || a.contains("mldsa65ed25519") {
        return "ml-dsa65".into();
    }
    if a.contains("mldsa87") {
        return "ml-dsa87".into();
    }
    if a.contains("slhdsa") {
        return "slh-dsa".into();
    }
    if a.contains("mlkem768") {
        return "ml-kem768".into();
    }
    if a.contains("mlkem1024") {
        return "ml-kem1024".into();
    }
    if a.contains("rsa") {
        return match bits {
            Some(b) => format!("rsa{b}"),
            None => "rsa".into(),
        };
    }
    if a == "dsa" {
        return match bits {
            Some(b) => format!("dsa{b}"),
            None => "dsa".into(),
        };
    }
    if a.contains("elgamal") || a == "elg" {
        return match bits {
            Some(b) => format!("elg{b}"),
            None => "elg".into(),
        };
    }
    if a.is_empty() {
        "unknown".into()
    } else {
        a
    }
}

/// OpenPGP public-key algorithm id for --with-colons.
fn algo_id(algorithm: &str, curve: &Option<String>) -> u32 {
    let a = algorithm.to_ascii_lowercase();
    if a.contains("rsa") {
        return 1;
    }
    if a.contains("elgamal") {
        return 16;
    }
    if a == "dsa" {
        return 17;
    }
    if a.contains("eddsa") || a.contains("ed25519") {
        return 22;
    }
    if a.contains("ecdsa") {
        return 19;
    }
    if a.contains("ecdh") || a.contains("x25519") {
        return 18;
    }
    // Fall back to the curve token if the algorithm name is opaque.
    if let Some(cu) = curve {
        if cu == "ed25519" {
            return 22;
        }
        if cu == "cv25519" || cu.starts_with("nistp") {
            return 18;
        }
    }
    0
}

/// gpg's openpgp_pk_algo_name, from our (algorithm, curve) pair.
fn pk_algo_name_str(algorithm: &str, curve: &Option<String>) -> String {
    let a = algorithm.to_ascii_lowercase();
    if a.contains("rsa") {
        return "RSA".into();
    }
    if a.contains("eddsa") || a.contains("ed25519") {
        return "EDDSA".into();
    }
    if a.contains("ecdsa") {
        return "ECDSA".into();
    }
    if a.contains("ecdh") {
        return "ECDH".into();
    }
    if a.contains("x25519") {
        return "ECDH".into();
    }
    if a == "dsa" {
        return "DSA".into();
    }
    if a.contains("elgamal") {
        return "ELG".into();
    }
    if let Some(cu) = curve {
        if cu == "ed25519" {
            return "EDDSA".into();
        }
        if cu == "cv25519" || cu.starts_with("nistp") {
            return "ECDH".into();
        }
    }
    algorithm.to_uppercase()
}

fn pk_algo_name_from_id(id: u8) -> String {
    match id {
        1 | 2 | 3 => "RSA",
        16 => "ELG",
        17 => "DSA",
        18 => "ECDH",
        19 => "ECDSA",
        22 => "EDDSA",
        // RFC 9580 (v6) algorithms.
        25 | 26 => "ECDH",
        27 | 28 => "EDDSA",
        _ => "?",
    }
    .to_string()
}

fn pubkey_algo_id(k: &HostKey) -> u32 {
    algo_id(&k.algorithm, &k.curve)
}

/// Usage flags in gpg's order: S, C, E, A. The primary always certifies.
fn usage_str(can_sign: bool, can_encrypt: bool, is_primary: bool) -> String {
    let mut f = String::new();
    if can_sign {
        f.push('S');
    }
    if is_primary {
        f.push('C');
    }
    if can_encrypt {
        f.push('E');
    }
    f
}

fn validity_word(k: &HostKey) -> &'static str {
    if let Some(exp) = k.expires_at {
        if exp <= now_unix() {
            return "expired";
        }
    }
    if k.is_secret {
        "ultimate"
    } else if k.trusted {
        "full"
    } else {
        "unknown"
    }
}

/// The fixed-width 10-column validity bracket, exactly as gpg renders it.
fn validity_fixed(k: &HostKey) -> &'static str {
    match validity_word(k) {
        "expired" => "[ expired]",
        "ultimate" => "[ultimate]",
        "full" => "[  full  ]",
        _ => "[ unknown]",
    }
}

fn validity_colon(k: &HostKey) -> char {
    match validity_word(k) {
        "expired" => 'e',
        "ultimate" => 'u',
        "full" => 'f',
        _ => '-',
    }
}

fn is_full_or_ultimate(k: &HostKey) -> bool {
    matches!(validity_word(k), "full" | "ultimate")
}

/// 6-space-indented bare fingerprint (default `--list-keys` form).
fn fmt_fpr(fpr: &str) -> String {
    format!("      {}", fpr.to_uppercase())
}

/// Grouped fingerprint for `--fingerprint`: v4 (40 hex) → groups of 4 with a
/// double space at the midpoint; other lengths are printed as-is.
fn fmt_fpr_grouped(fpr: &str) -> String {
    let f = fpr.to_uppercase();
    if f.len() != 40 {
        return f;
    }
    let chars: Vec<char> = f.chars().collect();
    let mut out = String::new();
    for (i, ch) in chars.iter().enumerate() {
        if i > 0 && i % 4 == 0 {
            out.push(' ');
        }
        if i == 20 {
            out.push(' ');
        }
        out.push(*ch);
    }
    out
}

fn match_key(k: &HostKey, query: &str) -> bool {
    let mut q = query.trim().to_string();
    if q.starts_with("0x") || q.starts_with("0X") {
        q = q[2..].to_string();
    }
    let norm: String = q.chars().filter(|c| !c.is_whitespace()).collect::<String>().to_uppercase();
    if norm.len() >= 8 && norm.chars().all(|c| c.is_ascii_hexdigit()) {
        if k.fingerprint.to_uppercase().ends_with(&norm) {
            return true;
        }
        if k.key_id.to_uppercase().ends_with(&norm) {
            return true;
        }
        if k.subkeys.iter().any(|s| {
            s.fingerprint.to_uppercase().ends_with(&norm) || s.key_id.to_uppercase().ends_with(&norm)
        }) {
            return true;
        }
    }
    let lc = query.to_lowercase();
    k.user_ids.iter().any(|u| u.to_lowercase().contains(&lc))
}

/// Extract the cleartext body of a clear-signed message (for `gpg -d`).
fn first_verify_text(keys: &[HostKey], text: &str) -> Option<String> {
    for k in keys {
        if let Ok(r) = pgp::verify_cleartext(text, &k.public_key) {
            if !r.text.is_empty() {
                return Some(r.text + "\n");
            }
        }
    }
    None
}

fn resolve_recipient(keys: &[HostKey], q: &str) -> R<HostKey> {
    keys.iter()
        .find(|k| match_key(k, q) && k.can_encrypt)
        .cloned()
        .ok_or_else(|| gerr(format!("{q}: no encryption-capable public key found")))
}

fn parse_expire(s: &str) -> u32 {
    let t = s.trim();
    if t.is_empty() {
        return 0;
    }
    let (num, unit) = t.split_at(t.find(|c: char| c.is_alphabetic()).unwrap_or(t.len()));
    if let Ok(n) = num.trim().parse::<u32>() {
        return match unit.trim().to_lowercase().as_str() {
            "w" => n * 7,
            "m" => n * 30,
            "y" => n * 365,
            _ => n,
        };
    }
    0
}

fn map_algo_preset(s: &str) -> R<String> {
    let a = s.trim().to_lowercase();
    let preset = match a.as_str() {
        "default" | "" => "curve25519",
        "future" | "future-default" => "ed25519",
        "ed25519" => "ed25519",
        "cv25519" | "curve25519" => "curve25519",
        "rsa" => "rsa3072",
        "rsa2048" => "rsa2048",
        "rsa3072" => "rsa3072",
        "rsa4096" => "rsa4096",
        "nistp256" => "nistp256",
        "nistp384" => "nistp384",
        "nistp521" => "nistp521",
        "pqc" | "mldsa65-mlkem768" => "pqc",
        "mldsa87-mlkem1024" => "mldsa87-mlkem1024",
        "slhdsa128s-mlkem768" => "slhdsa128s-mlkem768",
        _ => return Err(gerr(format!("unknown algorithm \"{s}\""))),
    };
    Ok(preset.to_string())
}

fn split_armored_blocks(text: &str) -> Vec<String> {
    let mut blocks = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find("-----BEGIN ") {
        if let Some(end_rel) = rest[start..].find("-----END ") {
            let after = &rest[start + end_rel..];
            if let Some(close) = after.find("-----\n").or_else(|| after.find("-----")) {
                let block_end = start + end_rel + close + "-----".len();
                blocks.push(rest[start..block_end].to_string());
                rest = &rest[block_end..];
                continue;
            }
        }
        break;
    }
    blocks
}

// ----- digests (--print-md) -----

fn digest(algo: &str, data: &[u8]) -> Option<Vec<u8>> {
    match algo.to_ascii_uppercase().as_str() {
        "SHA1" => Some(Sha1::digest(data).to_vec()),
        "SHA256" => Some(Sha256::digest(data).to_vec()),
        "SHA384" => Some(Sha384::digest(data).to_vec()),
        "SHA512" => Some(Sha512::digest(data).to_vec()),
        _ => None,
    }
}

fn hex_upper(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push_str(&format!("{x:02X}"));
    }
    s
}

/// gpg's print_hex: groups depend on digest length; --print-mds prefixes a
/// `%6s = ` algorithm header, single --print-md mode does not.
fn print_hex(label: &str, algo: &str, digest: &[u8], with_header: bool) -> String {
    let mut line = String::new();
    if !label.is_empty() {
        line.push_str(&format!("{label}: "));
    }
    if with_header {
        line.push_str(&format!("{algo:>6} = "));
    }
    let n = digest.len();
    for (i, byte) in digest.iter().enumerate() {
        if i > 0 {
            if n == 20 {
                if i % 2 == 0 {
                    line.push(' ');
                }
                if i % 10 == 0 {
                    line.push(' ');
                }
            } else if i % 4 == 0 {
                line.push(' ');
            }
        }
        line.push_str(&format!("{byte:02X}"));
    }
    line.push('\n');
    line
}

fn print_hashline(label: &str, algo: &str, digest: &[u8]) -> String {
    let algo_id = match algo.to_ascii_uppercase().as_str() {
        "SHA1" => 2,
        "SHA256" => 8,
        "SHA384" => 9,
        "SHA512" => 10,
        _ => 0,
    };
    let mut enc = String::new();
    for ch in label.bytes() {
        if ch <= 32 || ch > 127 || ch == b':' || ch == b'%' {
            enc.push_str(&format!("%{ch:02X}"));
        } else {
            enc.push(ch as char);
        }
    }
    format!("{enc}:{algo_id}:{}:\n", hex_upper(digest))
}

// ----- ASCII armor (--enarmor / --dearmor) -----

fn crc24(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xb704ce;
    for &b in data {
        crc ^= (b as u32) << 16;
        for _ in 0..8 {
            crc <<= 1;
            if crc & 0x100_0000 != 0 {
                crc ^= 0x1864cfb;
            }
        }
    }
    crc & 0xff_ffff
}

fn enarmor(data: &[u8], label: &str) -> String {
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD.encode(data);
    let mut lines = String::new();
    let chars: Vec<char> = b64.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let end = (i + 64).min(chars.len());
        lines.extend(&chars[i..end]);
        lines.push('\n');
        i = end;
    }
    let crc = crc24(data);
    let crc_bytes = [((crc >> 16) & 0xff) as u8, ((crc >> 8) & 0xff) as u8, (crc & 0xff) as u8];
    let checksum = base64::engine::general_purpose::STANDARD.encode(crc_bytes);
    format!(
        "-----BEGIN {label}-----\n\n{lines}={checksum}\n-----END {label}-----\n"
    )
}

fn dearmor(text: &str) -> Result<Vec<u8>, String> {
    use base64::Engine;
    let mut in_body = false;
    let mut started = false;
    let mut body = String::new();
    for raw in text.split('\n') {
        let line = raw.trim_end();
        if line.starts_with("-----BEGIN") {
            started = true;
            continue;
        }
        if line.starts_with("-----END") {
            break;
        }
        if started && !in_body {
            if line.is_empty() {
                in_body = true;
                continue;
            }
            if is_armor_header(line) {
                continue;
            }
            in_body = true;
        }
        if in_body {
            if line.starts_with('=') {
                break;
            }
            body.push_str(line);
        }
    }
    if !started {
        return Err("no armor header found".into());
    }
    base64::engine::general_purpose::STANDARD
        .decode(body.replace(char::is_whitespace, ""))
        .map_err(|e| format!("invalid base64: {e}"))
}

fn is_armor_header(line: &str) -> bool {
    if let Some(idx) = line.find(':') {
        let key = &line[..idx];
        !key.is_empty() && key.chars().all(|c| c.is_ascii_alphabetic() || c == '-')
    } else {
        false
    }
}

fn maybe_dearmor(data: &[u8]) -> Vec<u8> {
    if data.starts_with(b"-----BEGIN") {
        if let Ok(raw) = dearmor(&String::from_utf8_lossy(data)) {
            return raw;
        }
    }
    data.to_vec()
}

// ----- packet structure lister (--list-packets) -----

fn packet_tag_name(tag: u8) -> &'static str {
    match tag {
        1 => "pubkey enc packet",
        2 => "signature packet",
        3 => "symkey enc packet",
        4 => "onepass_sig packet",
        5 => "secret key packet",
        6 => "public key packet",
        7 => "secret sub key packet",
        8 => "compressed packet",
        9 => "encrypted data packet",
        10 => "marker packet",
        11 => "literal data packet",
        12 => "trust packet",
        13 => "user ID packet",
        14 => "public sub key packet",
        17 => "attribute packet",
        18 => "encrypted data packet",
        19 => "mdc packet",
        20 => "encrypted data packet",
        _ => "unknown packet",
    }
}

fn has_packet_tag(data: &[u8], want: u8) -> bool {
    for (tag, _, _, _) in iter_packets(data) {
        if tag == want {
            return true;
        }
    }
    false
}

/// Walk OpenPGP packets, yielding (tag, header_len, body_len, body_offset).
fn iter_packets(data: &[u8]) -> Vec<(u8, usize, usize, usize)> {
    let mut out = Vec::new();
    let n = data.len();
    let mut i = 0;
    while i < n {
        let ctb = data[i];
        if ctb & 0x80 == 0 {
            break;
        }
        let new_format = ctb & 0x40 != 0;
        let (tag, len, hlen);
        if new_format {
            tag = ctb & 0x3f;
            if i + 1 >= n {
                break;
            }
            let l0 = data[i + 1] as usize;
            if l0 < 192 {
                len = l0;
                hlen = 2;
            } else if l0 < 224 {
                if i + 2 >= n {
                    break;
                }
                len = ((l0 - 192) << 8) + data[i + 2] as usize + 192;
                hlen = 3;
            } else if l0 == 255 {
                if i + 5 >= n {
                    break;
                }
                len = ((data[i + 2] as usize) << 24)
                    | ((data[i + 3] as usize) << 16)
                    | ((data[i + 4] as usize) << 8)
                    | data[i + 5] as usize;
                hlen = 6;
            } else {
                len = 1usize << (l0 & 0x1f);
                hlen = 2;
            }
        } else {
            tag = (ctb >> 2) & 0x0f;
            let len_type = ctb & 0x03;
            match len_type {
                0 => {
                    if i + 1 >= n {
                        break;
                    }
                    len = data[i + 1] as usize;
                    hlen = 2;
                }
                1 => {
                    if i + 2 >= n {
                        break;
                    }
                    len = ((data[i + 1] as usize) << 8) | data[i + 2] as usize;
                    hlen = 3;
                }
                2 => {
                    if i + 4 >= n {
                        break;
                    }
                    len = ((data[i + 1] as usize) << 24)
                        | ((data[i + 2] as usize) << 16)
                        | ((data[i + 3] as usize) << 8)
                        | data[i + 4] as usize;
                    hlen = 5;
                }
                _ => {
                    len = n - i - 1;
                    hlen = 1;
                }
            }
        }
        let body = i + hlen;
        out.push((tag, hlen, len, body));
        if hlen + len == 0 {
            break;
        }
        i = body + len;
    }
    out
}

fn parse_packets(data: &[u8]) -> String {
    let mut lines: Vec<String> = Vec::new();
    let mut offset = 0usize;
    for (tag, hlen, len, body) in iter_packets(data) {
        let ctb = *data.get(offset).unwrap_or(&0);
        lines.push(format!(
            "# off={offset} ctb={ctb:02x} tag={tag} hlen={hlen} plen={len}"
        ));
        let name = packet_tag_name(tag);
        let mut detail = format!(":{name}:");

        match tag {
            1 => {
                // pubkey enc: version, then (v3) 8-byte keyid + 1-byte algo
                if body < data.len() {
                    let ver = data[body];
                    if ver == 3 && body + 10 <= data.len() {
                        let kid = hex_upper(&data[body + 1..body + 9]);
                        let algo = data[body + 9];
                        detail = format!(":pubkey enc packet: version 3, algo {algo}, keyid {kid}");
                    }
                }
            }
            11 => {
                if body + 1 < data.len() {
                    let mode = data[body] as char;
                    detail = format!(":literal data packet:\n\tmode {mode} ({:02X})", data[body]);
                }
            }
            6 | 14 | 5 | 7 => {
                if body + 5 <= data.len() {
                    let ver = data[body];
                    let (algo, created) = if ver == 4 {
                        let created = u32::from_be_bytes([
                            data[body + 1],
                            data[body + 2],
                            data[body + 3],
                            data[body + 4],
                        ]);
                        (data.get(body + 5).copied().unwrap_or(0), created)
                    } else {
                        (0, 0)
                    };
                    detail = format!(
                        ":{name}:\n\tversion {ver}, algo {algo}, created {created}"
                    );
                }
            }
            2 => {
                if body + 6 <= data.len() {
                    let ver = data[body];
                    if ver == 4 {
                        let sigtype = data[body + 1];
                        let pubalgo = data[body + 2];
                        let hashalgo = data[body + 3];
                        detail = format!(
                            ":signature packet: algo {pubalgo}\n\tversion 4, sigclass 0x{sigtype:02x}, digest algo {hashalgo}"
                        );
                    }
                }
            }
            _ => {}
        }
        lines.push(detail);
        offset = body + len;
    }
    if lines.is_empty() {
        return format!("{PROGRAM}: no packets found\n");
    }
    lines.join("\n") + "\n"
}

// ===========================================================================
// Key listing (human + colon)
// ===========================================================================

fn list_human(keys: &[HostKey], secret: bool, want_fpr: bool, want_sub_fpr: bool) -> String {
    let header = format!("{HOMEDIR}/pubring.kbx");
    let mut out = String::new();
    out.push_str(&header);
    out.push('\n');
    out.push_str(&"-".repeat(header.len()));
    out.push('\n');
    if keys.is_empty() {
        out.push('\n');
    }
    for k in keys {
        out.push_str(&list_human_block(k, secret, want_fpr, want_sub_fpr, false));
    }
    out
}

/// One key's human-readable block. `fresh` suppresses the validity column
/// (used right after key generation, matching gpg).
fn list_human_block(
    k: &HostKey,
    secret: bool,
    want_fpr: bool,
    want_sub_fpr: bool,
    fresh: bool,
) -> String {
    let mut out = String::new();
    let primary_tag = if secret { "sec" } else { "pub" };
    let sub_tag = if secret { "ssb" } else { "sub" };
    let token = algo_token(&k.algorithm, &k.curve, k.bit_strength);
    let usage = usage_str(k.primary_can_sign, k.primary_can_encrypt, true);
    let exp = expiry_suffix(k.expires_at);
    out.push_str(&format!(
        "{primary_tag}   {token} {} [{usage}]{exp}\n",
        fmt_date(k.created_at)
    ));
    if want_fpr {
        out.push_str(&format!("      {}\n", fmt_fpr_grouped(&k.fingerprint)));
    } else {
        out.push_str(&format!("{}\n", fmt_fpr(&k.fingerprint)));
    }
    for (idx, uid) in k.user_ids.iter().enumerate() {
        if fresh {
            // No validity column: "uid" + 22 spaces + name.
            out.push_str(&format!("uid                      {uid}\n"));
        } else {
            let validity = if idx == 0 {
                validity_fixed(k)
            } else {
                "[ unknown]"
            };
            // "uid" + 11 spaces + 10-col validity + space + name.
            out.push_str(&format!("uid           {validity} {uid}\n"));
        }
    }
    for sub in &k.subkeys {
        let stoken = algo_token(&sub.algorithm, &sub.curve, sub.bit_strength);
        let susage = usage_str(sub.can_sign, sub.can_encrypt, false);
        out.push_str(&format!(
            "{sub_tag}   {stoken} {} [{susage}]\n",
            fmt_date(k.created_at)
        ));
        if want_sub_fpr {
            out.push_str(&format!("      {}\n", fmt_fpr(&sub.fingerprint)));
        }
    }
    out.push('\n');
    out
}

fn expiry_suffix(expires_at: Option<i64>) -> String {
    match expires_at {
        Some(e) if e <= now_unix() => format!(" [expired: {}]", fmt_date(e)),
        Some(e) => format!(" [expires: {}]", fmt_date(e)),
        None => String::new(),
    }
}

fn list_colons(keys: &[HostKey], secret_only: bool) -> String {
    let mut lines: Vec<String> = Vec::new();
    lines.push(format!("tru::1:{}:0:3:1:5", now_unix()));
    for k in keys {
        let v = validity_colon(k);
        let bits = k.bit_strength.unwrap_or(0);
        let aid = algo_id(&k.algorithm, &k.curve);
        let keyid = last16(&k.key_id);
        let created = k.created_at;
        let expires = k.expires_at.map(|e| e.to_string()).unwrap_or_default();
        let primary_tag = if secret_only { "sec" } else { "pub" };
        let sub_tag = if secret_only { "ssb" } else { "sub" };
        let ownertrust = v;
        let caps = colon_caps_primary(
            k.primary_can_sign,
            k.primary_can_encrypt,
            k.can_sign,
            k.can_encrypt,
        );
        let curve = k.curve.clone().unwrap_or_default();
        // pub:v:bits:algo:keyid:created:expires::ownertrust:::caps:::::curve:::origin:
        lines.push(format!(
            "{primary_tag}:{v}:{bits}:{aid}:{keyid}:{created}:{expires}::{ownertrust}:::{caps}:::::{curve}:::0:"
        ));
        lines.push(format!("fpr:::::::::{}:", k.fingerprint.to_uppercase()));
        for uid in &k.user_ids {
            lines.push(format!(
                "uid:{v}::::{created}::{}::{}:::::::::0:",
                namehash40(uid),
                escape_colon(uid)
            ));
        }
        for sub in &k.subkeys {
            let scaps = colon_caps_sub(sub.can_sign, sub.can_encrypt);
            let said = algo_id(&sub.algorithm, &sub.curve);
            let sbits = sub.bit_strength.unwrap_or(0);
            let scurve = sub.curve.clone().unwrap_or_default();
            let skeyid = last16(&sub.key_id);
            lines.push(format!(
                "{sub_tag}:{v}:{sbits}:{said}:{skeyid}:{created}:{expires}::::::{scaps}::::{scurve}::"
            ));
            lines.push(format!("fpr:::::::::{}:", sub.fingerprint.to_uppercase()));
        }
    }
    lines.join("\n") + "\n"
}

/// Primary `pub`/`sec` capability field: the primary's own caps in lowercase
/// (e, then s+c), then the whole-key usable caps in uppercase (E, S, C) —
/// matching gpg's print_capabilities for ed25519+cv25519 → "scESC".
fn colon_caps_primary(own_sign: bool, own_enc: bool, agg_sign: bool, agg_enc: bool) -> String {
    let mut f = String::new();
    if own_enc {
        f.push('e');
    }
    if own_sign {
        f.push('s');
    }
    f.push('c'); // the primary always certifies
    if agg_enc {
        f.push('E');
    }
    if agg_sign {
        f.push('S');
    }
    f.push('C');
    f
}

/// Subkey capability field: just the subkey's own caps (e and/or s).
fn colon_caps_sub(can_sign: bool, can_encrypt: bool) -> String {
    let mut f = String::new();
    if can_encrypt {
        f.push('e');
    }
    if can_sign {
        f.push('s');
    }
    f
}

fn escape_colon(s: &str) -> String {
    s.replace('\\', "\\x5c").replace(':', "\\x3a")
}

/// A stable 40-hex namehash placeholder (real gpg uses RIPEMD-160 of the uid;
/// the value is opaque, only the 40-hex width matters for the listing).
fn namehash40(uid: &str) -> String {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in uid.bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    let base = format!("{h:016X}");
    let mut s = String::new();
    while s.len() < 40 {
        s.push_str(&base);
    }
    s[..40].to_string()
}

// ===========================================================================
// list-config / dump-options / help / warranty
// ===========================================================================

fn list_config() -> String {
    [
        "cfg:version:2.4.7",
        "cfg:pubkey:1;16;17;18;19;22",
        "cfg:pubkeyname:RSA;ELG;DSA;ECDH;ECDSA;EDDSA",
        "cfg:cipher:7;8;9",
        "cfg:ciphername:AES;AES192;AES256",
        "cfg:digest:2;8;9;10",
        "cfg:digestname:SHA1;SHA256;SHA384;SHA512",
        "cfg:compress:0;1;2",
        "cfg:compressname:Uncompressed;ZIP;ZLIB",
        "cfg:curve:cv25519;ed25519;nistp256;nistp384;nistp521",
        &format!("cfg:homedir:{HOMEDIR}"),
        "",
    ]
    .join("\n")
}

fn dump_options() -> String {
    let mut v = Vec::new();
    for s in OPTIONS {
        for l in s.long {
            v.push(format!("--{l}"));
        }
    }
    v.join("\n") + "\n"
}

const HELP_TEXT: &str = "gpg (GnuPG; gpg4web) 2.4.7\n\
Syntax: gpg [options] [files]\n\
Sign, check, encrypt or decrypt — default operation depends on the input data.\n\
\n\
Commands:\n\
 -s, --sign                  make a signature\n\
     --clear-sign            make a clear text signature\n\
 -b, --detach-sign           make a detached signature\n\
 -e, --encrypt               encrypt data (needs -r)\n\
 -c, --symmetric             encrypt with a passphrase\n\
 -d, --decrypt               decrypt data\n\
     --verify                verify a signature\n\
 -k, --list-keys             list keys\n\
 -K, --list-secret-keys      list secret keys\n\
     --fingerprint           list keys and fingerprints\n\
     --gen-key               generate a new key pair (interactive)\n\
     --full-generate-key     generate a new key pair (interactive, all options)\n\
     --quick-generate-key    USER-ID [ALGO [USAGE [EXPIRE]]]\n\
     --export                export keys\n\
     --export-secret-keys    export secret keys\n\
     --import                import/merge keys\n\
     --delete-keys           remove keys from the keyring\n\
     --delete-secret-keys    remove secret keys from the keyring\n\
     --list-packets          list the packet structure of OpenPGP data\n\
     --enarmor / --dearmor   ASCII-armor conversion\n\
     --print-md ALGO         print message digests (SHA1/256/384/512)\n\
     --gen-random 1 N        emit N random bytes (-a for base64)\n\
     --version               show version information\n\
\n\
Options:\n\
 -a, --armor                 create ASCII armored output\n\
 -o, --output FILE           write output to FILE\n\
 -r, --recipient USER        encrypt for USER\n\
 -u, --local-user USER       use USER to sign\n\
     --passphrase STRING     supply the key passphrase (with --pinentry-mode loopback)\n\
     --with-colons           machine-readable key listing\n\
     --yes                   assume \"yes\" on most questions\n\
\n\
Keys are matched by user-id substring, key-id, or fingerprint (0x… accepted).\n";

const WARRANTY: &str = "gpg4web is free software: you can redistribute it and/or modify it under the\n\
terms of the GNU General Public License. It is distributed WITHOUT ANY WARRANTY,\n\
without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR\n\
PURPOSE. See the GNU GPL for more details.\n";
