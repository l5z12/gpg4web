#!/usr/bin/env bash
#
# Cloudflare Pages build script for gpg4web.
#
# Configure your Cloudflare Pages project as:
#   Build command:            bash cloudflare-build.sh
#   Build output directory:   web/dist
#   Root directory:           /            (repo root — the default)
#
# The Rust→WASM crypto core is NOT committed; it is compiled during the build.
# This script sets up Bun and the Rust/wasm-pack toolchain, then runs the
# front-end build. `bun run build` triggers the `prebuild` hook, which compiles
# crypto-core into web/src/wasm before Vite bundles the site.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

log() { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }

# --- 1. Bun ----------------------------------------------------------------
if ! command -v bun >/dev/null 2>&1; then
  log "Installing Bun"
  curl -fsSL https://bun.sh/install | bash
  export BUN_INSTALL="${BUN_INSTALL:-$HOME/.bun}"
  export PATH="$BUN_INSTALL/bin:$PATH"
fi
log "Bun $(bun --version)"

# --- 2. Rust + wasm-pack ---------------------------------------------------
if ! command -v cargo >/dev/null 2>&1; then
  log "Installing Rust toolchain"
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
fi
# Ensure cargo is on PATH for this shell (rustup installs to ~/.cargo/bin).
[ -f "$HOME/.cargo/env" ] && source "$HOME/.cargo/env"
export PATH="$HOME/.cargo/bin:$PATH"
log "Rust $(rustc --version)"

rustup target add wasm32-unknown-unknown

if ! command -v wasm-pack >/dev/null 2>&1; then
  log "Installing wasm-pack (prebuilt binary)"
  curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh
fi
log "wasm-pack $(wasm-pack --version)"

# --- 3. Install deps and build (prebuild compiles the WASM core) -----------
cd "$ROOT/web"
log "Installing dependencies"
bun install --frozen-lockfile || bun install

log "Building (compiles WASM core, then bundles front-end)"
bun run build

log "Done — static site is in web/dist"
