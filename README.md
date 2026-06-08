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
- Responsive — desktop and mobile.
- Hash-routed and fully static: host it from any path with no server.

---

## Architecture

```
gpg4web/
├── crypto-core/          # Rust crate compiled to WASM (the only place crypto happens)
│   ├── src/lib.rs        #   wasm-bindgen exports
│   ├── src/pgp.rs        #   OpenPGP operations (rPGP)
│   └── src/vault.rs      #   ML-KEM + AES-GCM + Argon2id vault
└── web/                  # Vue 3 + Vite front-end
    ├── src/crypto/       #   typed wrapper around the WASM module
    ├── src/stores/       #   Pinia vault store (lock/unlock + persistence)
    ├── src/lib/          #   .gnupg export, zip writer, toasts
    ├── src/views/        #   Certificates, Notepad, Sign/Verify, Settings, About
    └── src/wasm/         #   built WASM artifacts (committed)
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
bun run wasm      # build the Rust core into web/src/wasm (+ d.ts fixup)
bun run dev       # start the Vite dev server
```

Build for production:

```bash
cd web
bun run build     # type-check + bundle into web/dist
bun run preview   # serve the production build locally
```

The committed WASM in `web/src/wasm/` lets you run `bun run dev` / `build`
without a Rust toolchain; rebuild it with `bun run wasm` after changing
`crypto-core/`.

## Deploying to Cloudflare Pages

The repo ships a ready-made build script. In your Cloudflare Pages project:

| Setting | Value |
|---------|-------|
| **Build command** | `bash cloudflare-build.sh` |
| **Build output directory** | `web/dist` |
| **Root directory** | `/` (default) |

`cloudflare-build.sh` installs Bun (if missing), uses the committed WASM core,
runs `bun install`, and builds the static site into `web/dist`. Caching and a
strict Content-Security-Policy are applied via `web/public/_headers`.

Because changing `crypto-core/` requires recompiling the Rust core, set the
environment variable **`REBUILD_WASM=1`** in the Pages build settings — the
script will then install the Rust toolchain + `wasm-pack` and rebuild the WASM
before bundling. (For routine deploys this is unnecessary; the committed
artifact is used.)

---

## Security notes

- All cryptography is performed in Rust/WASM; the JS layer only marshals data.
- There is **no password recovery** for the vault. Forgetting the master
  password makes stored keys unrecoverable (by design).
- The `.gnupg` export and "vault backup" are the supported backup paths.

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).
