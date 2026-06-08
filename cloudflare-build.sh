#!/usr/bin/env bash
#
# Cloudflare Pages build script for gpg4web.
#
# Configure your Cloudflare Pages project as:
#   Build command:            bash cloudflare-build.sh
#   Build output directory:   web/dist
#   Root directory:           /            (repo root — the default)
#
# The Rust→WASM core is committed under web/src/wasm/, so a normal Pages build
# only needs Bun: it installs dependencies and bundles the front-end. The Rust
# toolchain is set up and the WASM rebuilt only when the artifact is missing or
# you opt in with REBUILD_WASM=1 (e.g. after changing crypto-core/).
#
# Optional environment variables:
#   REBUILD_WASM=1   force rebuilding the WASM core from Rust source
#   BUN_VERSION      pinned by Cloudflare; respected by the bun installer

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WASM="$ROOT/web/src/wasm/gpg4web_core_bg.wasm"

log() { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }

# --- 1. Ensure Bun is available --------------------------------------------
if ! command -v bun >/dev/null 2>&1; then
  log "Installing Bun"
  curl -fsSL https://bun.sh/install | bash
  export BUN_INSTALL="${BUN_INSTALL:-$HOME/.bun}"
  export PATH="$BUN_INSTALL/bin:$PATH"
fi
log "Bun $(bun --version)"

# --- 2. Optionally (re)build the Rust → WASM core --------------------------
if [ "${REBUILD_WASM:-0}" = "1" ] || [ ! -f "$WASM" ]; then
  log "Building the Rust → WASM crypto core"

  if ! command -v cargo >/dev/null 2>&1; then
    log "Installing Rust toolchain"
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
    # shellcheck disable=SC1091
    source "$HOME/.cargo/env"
  fi
  rustup target add wasm32-unknown-unknown

  if ! command -v wasm-pack >/dev/null 2>&1; then
    log "Installing wasm-pack (prebuilt binary)"
    curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh
  fi

  ( cd "$ROOT/web" && bun run wasm )
else
  log "Using committed WASM core ($(du -h "$WASM" | cut -f1)); set REBUILD_WASM=1 to rebuild"
fi

# --- 3. Install dependencies and build the front-end -----------------------
cd "$ROOT/web"
log "Installing dependencies"
bun install --frozen-lockfile || bun install

log "Building front-end"
bun run build

log "Done — static site is in web/dist"
