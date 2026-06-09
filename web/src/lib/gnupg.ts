// Build a downloadable ".gnupg home" export from the in-browser keyring.
//
// GnuPG's real home directory uses binary formats (keybox `pubring.kbx`,
// per-key files under `private-keys-v1.d/`, `trustdb.gpg`). Reproducing those
// byte-for-byte in the browser is brittle; instead we export the keys as
// ASCII-armored bundles plus ready-to-run import scripts. Running the included
// `import.sh` (or `import.bat`) reconstructs a working `~/.gnupg` via the real
// `gpg` binary — which is the portable, supported way to move keys between
// installations.

import { makeZip, type ZipEntry } from './zip'

/** A key flattened for export, with its secret material already decrypted. */
export interface GnupgExportKey {
  fingerprint: string
  publicKey: string
  secretKey?: string
  trusted?: boolean
  info: { userIds: string[] }
}

function sanitize(name: string): string {
  return name.replace(/[^a-zA-Z0-9._-]+/g, '_').slice(0, 60) || 'key'
}

function ownerName(key: GnupgExportKey): string {
  const uid = key.info.userIds[0] ?? key.fingerprint
  return sanitize(uid)
}

const IMPORT_SH = `#!/usr/bin/env bash
# Reconstruct a GnuPG home directory from this export.
# Usage: ./import.sh   (imports into your default ~/.gnupg)
set -euo pipefail
DIR="$(cd "$(dirname "\${BASH_SOURCE[0]}")" && pwd)"

echo "Importing public keys..."
if [ -f "$DIR/pubring.asc" ]; then gpg --import "$DIR/pubring.asc"; fi

echo "Importing secret keys..."
if [ -f "$DIR/secring.asc" ]; then gpg --import "$DIR/secring.asc"; fi

if [ -f "$DIR/ownertrust.txt" ]; then
  echo "Restoring owner trust..."
  gpg --import-ownertrust "$DIR/ownertrust.txt" || true
fi

echo "Done. Run 'gpg --list-keys' to verify."
`

const IMPORT_BAT = `@echo off
REM Reconstruct a GnuPG home directory from this export.
setlocal
set DIR=%~dp0
echo Importing public keys...
if exist "%DIR%pubring.asc" gpg --import "%DIR%pubring.asc"
echo Importing secret keys...
if exist "%DIR%secring.asc" gpg --import "%DIR%secring.asc"
if exist "%DIR%ownertrust.txt" gpg --import-ownertrust "%DIR%ownertrust.txt"
echo Done. Run "gpg --list-keys" to verify.
endlocal
`

function readme(keys: GnupgExportKey[]): string {
  const lines = keys.map(
    (k) =>
      `  - ${k.info.userIds[0] ?? '(no user id)'}  [${k.fingerprint}]  ${
        k.secretKey ? '(public + secret)' : '(public only)'
      }`,
  )
  return `gpg4web — GnuPG home export
============================

This archive contains your OpenPGP keys exported from gpg4web, in the
standard ASCII-armored format that GnuPG understands.

Contents
--------
  pubring.asc        All public keys (concatenated, armored)
  secring.asc        All secret keys you own (concatenated, armored)
  ownertrust.txt     Owner-trust assignments
  keys/              Individual <name>.<fpr>.pub.asc / .sec.asc files
  import.sh          Importer for macOS / Linux
  import.bat         Importer for Windows

How to restore your ~/.gnupg
----------------------------
  1. Unzip this archive.
  2. Run  ./import.sh   (macOS/Linux)  or  import.bat  (Windows).
     This calls the real 'gpg' binary to import the keys into your
     GnuPG home directory (~/.gnupg or %APPDATA%\\gnupg).
  3. Verify with:  gpg --list-keys   and   gpg --list-secret-keys

Keys in this export
-------------------
${lines.join('\n')}

Generated: ${new Date().toISOString()}
`
}

/** Assemble the export zip. Returns a Blob the caller can download. */
export function buildGnupgExport(keys: GnupgExportKey[]): Blob {
  const entries: ZipEntry[] = []

  const pubring = keys.map((k) => k.publicKey.trim()).join('\n')
  const secring = keys
    .filter((k) => k.secretKey)
    .map((k) => k.secretKey!.trim())
    .join('\n')

  entries.push({ name: 'gnupg-export/pubring.asc', content: pubring + '\n' })
  if (secring) entries.push({ name: 'gnupg-export/secring.asc', content: secring + '\n' })

  // Owner trust file: ultimate trust for our own secret keys, full for others
  // the user marked trusted.
  const ownertrust = keys
    .filter((k) => k.secretKey || k.trusted)
    .map((k) => `${k.fingerprint}:${k.secretKey ? '6' : '5'}:`)
    .join('\n')
  entries.push({ name: 'gnupg-export/ownertrust.txt', content: ownertrust + '\n' })

  for (const k of keys) {
    const base = `gnupg-export/keys/${ownerName(k)}.${k.fingerprint.slice(-16)}`
    entries.push({ name: `${base}.pub.asc`, content: k.publicKey.trim() + '\n' })
    if (k.secretKey) entries.push({ name: `${base}.sec.asc`, content: k.secretKey.trim() + '\n' })
  }

  entries.push({ name: 'gnupg-export/import.sh', content: IMPORT_SH })
  entries.push({ name: 'gnupg-export/import.bat', content: IMPORT_BAT })
  entries.push({ name: 'gnupg-export/README.txt', content: readme(keys) })

  return makeZip(entries)
}

/** Trigger a browser download of a Blob. */
export function downloadBlob(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  document.body.appendChild(a)
  a.click()
  a.remove()
  setTimeout(() => URL.revokeObjectURL(url), 1000)
}

/** Trigger a browser download of armored text. */
export function downloadText(text: string, filename: string): void {
  downloadBlob(new Blob([text], { type: 'text/plain' }), filename)
}
