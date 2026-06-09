# gpg4web

**GNU Privacy Guard that runs in your browser.**

A full OpenPGP client built with **Rust + WebAssembly** and a **Vue 3**
front-end. All cryptography runs locally in the browser — no key material,
passphrase, or plaintext ever leaves your device. The keyring is persisted in
`localStorage` behind a **post-quantum** encryption envelope. The UI is modeled
after KDE's [Kleopatra](https://apps.kde.org/kleopatra/) and works on both
desktop and mobile.

---

## Features

### OpenPGP (via [rPGP](https://github.com/rpgp/rpgp))
- **Key generation**: Curve25519/EdDSA (v4, GnuPG-compatible), Ed25519+X25519
  (v6), RSA 2048/3072/4096, NIST P-256/P-384/P-521.
- 🛡 **Post-quantum OpenPGP keys** (IETF `draft-pqc`): ML-DSA-65 + ML-KEM-768,
  ML-DSA-87 + ML-KEM-1024, SLH-DSA-128s + ML-KEM-768.
- **Encrypt / decrypt** to one or many recipients, with optional signing.
- **Signatures**: inline, detached, and cleartext — sign and verify.
- **Key management**: import/export armored keys, inspect fingerprints,
  user IDs, subkeys, capabilities and expiry; owner-trust flags.
- **`.gnupg` home export**: download a portable ZIP that the real `gpg` binary
  can import to reconstruct `~/.gnupg`.

### Post-quantum vault
Your keyring and settings live in `localStorage`, sealed with a quantum-resistant
envelope:

| Layer | Algorithm | Role |
|-------|-----------|------|
| KEM   | **ML-KEM-768** (NIST FIPS 203) | wraps a fresh data key on every save |
| Cipher| **AES-256-GCM** | encrypts the payload |
| KDF   | **Argon2id** | seals the KEM secret key under your master password |

An attacker holding the storage blob must defeat **both** Argon2id and ML-KEM —
neither is broken by a quantum computer.

### UX
- Kleopatra-style layout: certificate list, notepad, sign/verify, settings.
- **`gpg` CLI** (the **Console** view): a terminal whose `gpg(1)` engine —
  option parsing, command dispatch and output formatting — runs **inside the
  Rust/WASM core**, so it reproduces real GnuPG 2.4 output (key listings,
  `--with-colons` records, `gpg: …` log lines, signature-verification blocks,
  import statistics) closely. The TypeScript layer is only the shell:
  tokenizing, pipes (`|`) and redirection (`>`, `>>`, `<`) over a per-session
  virtual filesystem, and the interactive prompts. Speaks the full command
  grammar — long/short options, `--opt=value`, unambiguous abbreviations,
  bundled flags (`-sea`), `--` terminator. Runs `--gen-key`/
  `--quick-generate-key`, `--list-keys` (incl. `--with-colons`/`--fingerprint`),
  `--encrypt`/`--decrypt`, `--symmetric` (`-c`), `--sign`/`--clear-sign`/
  `--detach-sign`/`--verify`, `--import`/`--export`, `--delete-keys`,
  `--enarmor`/`--dearmor`, `--print-md`, `--gen-random`, `--list-packets`, and
  more — all against your unlocked keyring, locally. Features that a browser
  sandbox can't provide (keyservers, smartcards, the interactive `--edit-key`
  menu) are recognised and reported honestly.
- Responsive — desktop and mobile.
- Hash-routed and fully static: host it from any path with no server.

---

## Architecture

```
gpg4web/
├── crypto-core/          # Rust crate compiled to WASM (the only place crypto happens)
│   ├── src/lib.rs        #   wasm-bindgen exports
│   ├── src/pgp.rs        #   OpenPGP operations (rPGP)
│   ├── src/gpgcli.rs     #   the gpg(1) engine: parsing, dispatch, gpg-faithful formatting
│   └── src/vault.rs      #   ML-KEM + AES-GCM + Argon2id vault
└── web/                  # Vue 3 + Vite front-end
    ├── src/crypto/       #   typed wrapper around the WASM module (incl. gpgRun)
    ├── src/stores/       #   Pinia vault store (lock/unlock + persistence)
    ├── src/lib/          #   .gnupg export, zip writer, toasts, gpg terminal shell
    ├── src/views/        #   Certificates, Notepad, Sign/Verify, Console, Settings, About
    └── src/wasm/         #   generated WASM artifacts (built by `bun run wasm`, gitignored)
```

---

## Development

Prerequisites: **[Bun](https://bun.sh) 1.1+**, **Rust** with the
`wasm32-unknown-unknown` target, and
[`wasm-pack`](https://rustwasm.github.io/wasm-pack/).

```bash
rustup target add wasm32-unknown-unknown
cargo install wasm-pack

cd web
bun install
bun run wasm      # compile the Rust core into web/src/wasm (+ d.ts fixup)
bun run dev       # start the Vite dev server
```

Build for production:

```bash
cd web
bun run build     # prebuild compiles the WASM, then type-check + bundle into web/dist
bun run preview   # serve the production build locally
```

The Rust→WASM core under `web/src/wasm/` is **generated, not committed**.
`bun run build` regenerates it automatically via the `prebuild` hook, so a Rust
toolchain + `wasm-pack` are required to build. For `bun run dev`, run
`bun run wasm` once first (re-run it after changing `crypto-core/`).

## Deploying to Cloudflare Pages

The repo ships a ready-made build script. In your Cloudflare Pages project:

| Setting | Value |
|---------|-------|
| **Build command** | `bash cloudflare-build.sh` |
| **Build output directory** | `web/dist` |
| **Root directory** | `/` (default) |

`cloudflare-build.sh` installs Bun and the Rust + `wasm-pack` toolchain, then
runs `bun install` and `bun run build` — which compiles the WASM core (via the
`prebuild` hook) and bundles the static site into `web/dist`. Caching and a
strict Content-Security-Policy are applied via `web/public/_headers`.

### Official-domain warning

When the app is served from any origin that is **not** `l5z12.dev` (or a
subdomain), a banner warns that the deployment may be unofficial/modified.
Override the allowed list at build time with the `VITE_OFFICIAL_DOMAINS`
environment variable (comma-separated apex domains; subdomains are implied),
e.g. `VITE_OFFICIAL_DOMAINS=example.com,localhost`.

---

## Security notes

- All cryptography is performed in Rust/WASM; the JS layer only marshals data.
- There is **no password recovery** for the vault. Forgetting the master
  password makes stored keys unrecoverable (by design).
- **The master password is never retained.** At unlock it is used once to
  unseal the vault's ML-KEM decapsulation key; only that derived session key is
  kept in memory (and wiped on lock/auto-lock). The plaintext password does not
  persist past unlock.
- **Secret keys are decrypted on demand.** Even while the vault is unlocked,
  each secret key stays individually post-quantum-encrypted in memory and is
  only decrypted (with the session key) for the specific operation that needs
  it — so opening one secret key never exposes the others.
- A non-official origin shows an **unofficial-deployment** banner (see above).
- The `.gnupg` export and "vault backup" are the supported backup paths.

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).
