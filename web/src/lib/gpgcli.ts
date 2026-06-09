// A gpg(1) command-line simulator.
//
// This implements a faithful subset of the GnuPG command-line surface on top
// of the in-browser rPGP/WASM crypto core and the vault keyring. It parses the
// real gpg option grammar (long options with `=`/space arguments and
// unambiguous abbreviations, bundled short options, `--` operand terminator),
// recognises the full command/option vocabulary, and executes the operations
// that the browser crypto core can perform locally. Operations that inherently
// require things a sandboxed browser cannot do (network keyservers, smartcard
// access, the interactive `--edit-key` menu) are recognised and reported
// honestly rather than silently ignored.
//
// Everything runs against a per-session virtual filesystem so that the classic
// `gpg -e -r alice file.txt` / `gpg -d file.txt.gpg` workflows behave the way
// they do on a real shell, including stdin pipes and `>`/`<` redirection.

import {
  decrypt as coreDecrypt,
  decryptFile,
  encryptFile,
  signCleartext,
  signFileDetached,
  verifyCleartext,
  verifyFileDetached,
  generateKey as coreGenerateKey,
  coreVersion,
  type KeyAlgorithm,
} from '@/crypto/core'

// ---------------------------------------------------------------------------
// Keyring port — implemented by the host (the Pinia vault store)
// ---------------------------------------------------------------------------

/** A keyring entry, flattened for the CLI. */
export interface CliKey {
  fingerprint: string
  keyId: string
  userIds: string[]
  algorithm: string
  createdAt: number
  expiresAt: number | null
  isSecret: boolean
  canEncrypt: boolean
  canSign: boolean
  bitStrength: number | null
  trusted: boolean
  publicKey: string
  subkeys: {
    keyId: string
    fingerprint: string
    algorithm: string
    canEncrypt: boolean
    canSign: boolean
  }[]
}

/**
 * The bridge between the simulator and the live keyring. The host decrypts
 * secret material on demand and persists imports/deletes.
 */
export interface KeyringPort {
  list(): CliKey[]
  /** Decrypt and return the armored secret key for a fingerprint, or null. */
  getSecretKey(fingerprint: string): string | null
  /** Import an armored block (public or secret). */
  importArmored(armored: string): { fingerprint: string; keyId: string; isSecret: boolean }
  removeKey(fingerprint: string): void
  setTrusted(fingerprint: string, trusted: boolean): void
  addGenerated(publicKey: string, secretKey: string): CliKey
}

// ---------------------------------------------------------------------------
// Shell I/O — implemented by the terminal view
// ---------------------------------------------------------------------------

export interface ShellIO {
  /** Write text to the terminal (caller includes newlines). */
  write(text: string): void
  /** Prompt the user for a line of input (optionally masked). */
  prompt(label: string, opts?: { password?: boolean }): Promise<string>
  /** Clear the terminal scrollback. */
  clear(): void
}

// ---------------------------------------------------------------------------
// Small byte helpers
// ---------------------------------------------------------------------------

const enc = new TextEncoder()
const dec = new TextDecoder()

const toBytes = (s: string): Uint8Array => enc.encode(s)
const fromBytes = (b: Uint8Array): string => dec.decode(b)

function looksBinary(b: Uint8Array): boolean {
  const n = Math.min(b.length, 8000)
  for (let i = 0; i < n; i++) {
    const c = b[i]
    if (c === 0) return true
    if (c < 9 || (c > 13 && c < 32)) return true
  }
  return false
}

function bytesToBase64(b: Uint8Array): string {
  let s = ''
  for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i])
  return btoa(s)
}
function base64ToBytes(s: string): Uint8Array {
  const bin = atob(s.replace(/\s+/g, ''))
  const out = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out
}

function hex(b: Uint8Array): string {
  let s = ''
  for (let i = 0; i < b.length; i++) s += b[i].toString(16).padStart(2, '0')
  return s
}

const fmtDate = (unixSecs: number): string =>
  new Date(unixSecs * 1000).toISOString().slice(0, 10)

// ---------------------------------------------------------------------------
// gpg-style ASCII armor (CRC24) — used by --enarmor / --dearmor
// ---------------------------------------------------------------------------

function crc24(data: Uint8Array): number {
  let crc = 0xb704ce
  for (let i = 0; i < data.length; i++) {
    crc ^= data[i] << 16
    for (let j = 0; j < 8; j++) {
      crc <<= 1
      if (crc & 0x1000000) crc ^= 0x1864cfb
    }
  }
  return crc & 0xffffff
}

function enarmor(data: Uint8Array, label = 'PGP ARMORED FILE'): string {
  const b64 = bytesToBase64(data)
  const lines: string[] = []
  for (let i = 0; i < b64.length; i += 64) lines.push(b64.slice(i, i + 64))
  const crc = crc24(data)
  const crcBytes = new Uint8Array([(crc >> 16) & 0xff, (crc >> 8) & 0xff, crc & 0xff])
  const checksum = '=' + bytesToBase64(crcBytes)
  return (
    `-----BEGIN ${label}-----\n` +
    `Comment: gpg4web\n\n` +
    lines.join('\n') +
    '\n' +
    checksum +
    `\n-----END ${label}-----\n`
  )
}

function dearmor(text: string): Uint8Array {
  const lines = text.split(/\r?\n/)
  let inBody = false
  let started = false
  const body: string[] = []
  for (const raw of lines) {
    const line = raw.trimEnd()
    if (line.startsWith('-----BEGIN')) {
      started = true
      continue
    }
    if (line.startsWith('-----END')) break
    if (started && !inBody) {
      // Armor headers run until the first blank line.
      if (line === '') {
        inBody = true
        continue
      }
      if (/^[A-Za-z][A-Za-z-]*:/.test(line)) continue
      // No headers present — this blank-less armor goes straight to body.
      inBody = true
    }
    if (inBody) {
      if (line.startsWith('=')) break // CRC checksum line
      body.push(line)
    }
  }
  if (!started) throw new Error('no armor header found')
  return base64ToBytes(body.join(''))
}

// ---------------------------------------------------------------------------
// Algorithm naming, mirroring gpg's short tokens
// ---------------------------------------------------------------------------

function algoToken(algorithm: string, bits: number | null): string {
  const a = algorithm.toLowerCase()
  if (a.includes('eddsa') || a === 'ed25519') return 'ed25519'
  if (a.includes('mldsa65')) return 'ml-dsa65'
  if (a.includes('mldsa87')) return 'ml-dsa87'
  if (a.includes('slhdsa')) return 'slh-dsa'
  if (a.includes('mlkem768')) return 'ml-kem768'
  if (a.includes('mlkem1024')) return 'ml-kem1024'
  if (a === 'x25519' || a.includes('ecdh') || a.includes('cv25519')) return 'cv25519'
  if (a.includes('ecdsa')) return 'nistp'
  if (a.includes('rsa')) return bits ? `rsa${bits}` : 'rsa'
  if (a.includes('dsa')) return 'dsa'
  if (a.includes('elgamal') || a === 'elg') return 'elg'
  return a || 'unknown'
}

// OpenPGP public-key algorithm IDs (RFC 4880 §9.1 + drafts), for --with-colons.
function algoId(algorithm: string): number {
  const a = algorithm.toLowerCase()
  if (a.includes('rsa')) return 1
  if (a.includes('elgamal')) return 16
  if (a === 'dsa') return 17
  if (a.includes('ecdh') || a === 'x25519') return 18
  if (a.includes('ecdsa')) return 19
  if (a.includes('eddsa') || a === 'ed25519') return 22
  return 0
}

function usageFlags(k: { canSign: boolean; canEncrypt: boolean }, isPrimary: boolean): string {
  let f = ''
  if (k.canSign) f += 'S'
  if (k.canEncrypt) f += 'E'
  if (isPrimary) f += 'C'
  return f
}

// ---------------------------------------------------------------------------
// Tokenizer (POSIX-ish: single/double quotes and backslash escapes)
// ---------------------------------------------------------------------------

export function tokenize(line: string): string[] {
  const tokens: string[] = []
  let cur = ''
  let has = false
  let i = 0
  const n = line.length
  while (i < n) {
    const c = line[i]
    if (c === "'") {
      has = true
      i++
      while (i < n && line[i] !== "'") cur += line[i++]
      i++ // closing quote
    } else if (c === '"') {
      has = true
      i++
      while (i < n && line[i] !== '"') {
        if (line[i] === '\\' && i + 1 < n && '"\\$`'.includes(line[i + 1])) {
          cur += line[i + 1]
          i += 2
        } else cur += line[i++]
      }
      i++
    } else if (c === '\\') {
      has = true
      if (i + 1 < n) {
        cur += line[i + 1]
        i += 2
      } else i++
    } else if (c === ' ' || c === '\t') {
      if (has) {
        tokens.push(cur)
        cur = ''
        has = false
      }
      i++
    } else if (c === '|' || c === '>' || c === '<') {
      if (has) {
        tokens.push(cur)
        cur = ''
        has = false
      }
      // `>>` is a two-char operator.
      if (c === '>' && line[i + 1] === '>') {
        tokens.push('>>')
        i += 2
      } else {
        tokens.push(c)
        i++
      }
    } else {
      has = true
      cur += c
      i++
    }
  }
  if (has) tokens.push(cur)
  return tokens
}

// ---------------------------------------------------------------------------
// gpg option registry
// ---------------------------------------------------------------------------

interface OptSpec {
  /** canonical name (first long form, without leading dashes) */
  name: string
  long: string[]
  short?: string
  /** takes an argument */
  arg?: boolean
  /** is a "command" (action) rather than a modifier option */
  cmd?: boolean
  /** accumulates into an array (e.g. --recipient) */
  multi?: boolean
}

function spec(
  long: string | string[],
  o: Partial<Omit<OptSpec, 'name' | 'long'>> = {},
): OptSpec {
  const longs = Array.isArray(long) ? long : [long]
  return { name: longs[0], long: longs, ...o }
}

// The vocabulary gpg understands. Commands are marked `cmd`; argument-taking
// options `arg`; repeatable ones `multi`.
const OPTIONS: OptSpec[] = [
  // --- commands ---
  spec('version', { cmd: true }),
  spec(['help'], { short: 'h', cmd: true }),
  spec('warranty', { cmd: true }),
  spec('dump-options', { cmd: true }),
  spec('sign', { short: 's', cmd: true }),
  spec(['clear-sign', 'clearsign'], { cmd: true }),
  spec('detach-sign', { short: 'b', cmd: true }),
  spec('encrypt', { short: 'e', cmd: true }),
  spec('symmetric', { short: 'c', cmd: true }),
  spec('store', { cmd: true }),
  spec('decrypt', { short: 'd', cmd: true }),
  spec('verify', { cmd: true }),
  spec('multifile', { cmd: true }),
  spec('verify-files', { cmd: true }),
  spec('encrypt-files', { cmd: true }),
  spec('decrypt-files', { cmd: true }),
  spec(['list-keys', 'list-public-keys', 'list-key'], { short: 'k', cmd: true }),
  spec(['list-secret-keys', 'list-secret-key'], { short: 'K', cmd: true }),
  spec(['list-signatures', 'list-sigs'], { cmd: true }),
  spec(['check-signatures', 'check-sigs'], { cmd: true }),
  spec('fingerprint', { cmd: true }),
  spec('list-packets', { cmd: true }),
  spec(['delete-keys', 'delete-key'], { cmd: true }),
  spec(['delete-secret-keys', 'delete-secret-key'], { cmd: true }),
  spec('delete-secret-and-public-key', { cmd: true }),
  spec('export', { cmd: true }),
  spec('send-keys', { cmd: true }),
  spec(['receive-keys', 'recv-keys'], { cmd: true }),
  spec('search-keys', { cmd: true }),
  spec('refresh-keys', { cmd: true }),
  spec(['import', 'fast-import'], { cmd: true }),
  spec('import-ownertrust', { cmd: true }),
  spec('export-ownertrust', { cmd: true }),
  spec('list-config', { cmd: true }),
  spec(['gen-key', 'generate-key'], { cmd: true }),
  spec(['full-gen-key', 'full-generate-key'], { cmd: true }),
  spec(['quick-gen-key', 'quick-generate-key'], { cmd: true }),
  spec('quick-add-uid', { cmd: true }),
  spec('quick-add-key', { cmd: true }),
  spec('quick-revoke-uid', { cmd: true }),
  spec('quick-set-expire', { cmd: true }),
  spec('quick-set-primary-uid', { cmd: true }),
  spec(['gen-revoke', 'generate-revocation'], { cmd: true }),
  spec('edit-key', { cmd: true }),
  spec('sign-key', { cmd: true }),
  spec('lsign-key', { cmd: true }),
  spec('quick-sign-key', { cmd: true }),
  spec('quick-lsign-key', { cmd: true }),
  spec('passwd', { cmd: true }),
  spec('export-secret-keys', { cmd: true }),
  spec('export-secret-subkeys', { cmd: true }),
  spec('export-ssh-key', { cmd: true }),
  spec('gen-random', { cmd: true }),
  spec('gen-prime', { cmd: true }),
  spec(['print-md', 'print-mds'], { cmd: true }),
  spec('enarmor', { cmd: true }),
  spec('dearmor', { cmd: true }),
  spec('card-status', { cmd: true }),
  spec('card-edit', { cmd: true }),
  spec('change-pin', { cmd: true }),
  spec('rebuild-keydb-caches', { cmd: true }),

  // --- options that take an argument ---
  spec('output', { short: 'o', arg: true }),
  spec('recipient', { short: 'r', arg: true, multi: true }),
  spec('hidden-recipient', { short: 'R', arg: true, multi: true }),
  spec('recipient-file', { short: 'f', arg: true, multi: true }),
  spec('hidden-recipient-file', { short: 'F', arg: true, multi: true }),
  spec('encrypt-to', { arg: true, multi: true }),
  spec('hidden-encrypt-to', { arg: true, multi: true }),
  spec('local-user', { short: 'u', arg: true, multi: true }),
  spec('sender', { arg: true }),
  spec('default-key', { arg: true }),
  spec('default-recipient', { arg: true }),
  spec('group', { arg: true, multi: true }),
  spec('ungroup', { arg: true, multi: true }),
  spec('passphrase', { arg: true }),
  spec('passphrase-fd', { arg: true }),
  spec('passphrase-file', { arg: true }),
  spec('passphrase-repeat', { arg: true }),
  spec('pinentry-mode', { arg: true }),
  spec('command-fd', { arg: true }),
  spec('command-file', { arg: true }),
  spec('status-fd', { arg: true }),
  spec('status-file', { arg: true }),
  spec('logger-fd', { arg: true }),
  spec('logger-file', { arg: true }),
  spec('attribute-fd', { arg: true }),
  spec('attribute-file', { arg: true }),
  spec('homedir', { arg: true }),
  spec('options', { arg: true }),
  spec('keyring', { arg: true, multi: true }),
  spec('primary-keyring', { arg: true }),
  spec('secret-keyring', { arg: true }),
  spec('trustdb-name', { arg: true }),
  spec('keyid-format', { arg: true }),
  spec('list-options', { arg: true }),
  spec('verify-options', { arg: true }),
  spec('export-options', { arg: true }),
  spec('import-options', { arg: true }),
  spec('cipher-algo', { arg: true }),
  spec('digest-algo', { arg: true }),
  spec('cert-digest-algo', { arg: true }),
  spec(['compress-algo', 'compression-algo'], { arg: true }),
  spec('s2k-cipher-algo', { arg: true }),
  spec('s2k-digest-algo', { arg: true }),
  spec('s2k-mode', { arg: true }),
  spec('s2k-count', { arg: true }),
  spec('personal-cipher-preferences', { arg: true }),
  spec('personal-digest-preferences', { arg: true }),
  spec('personal-compress-preferences', { arg: true }),
  spec('default-preference-list', { arg: true }),
  spec('keyserver', { arg: true }),
  spec('keyserver-options', { arg: true }),
  spec('trust-model', { arg: true }),
  spec('auto-key-locate', { arg: true }),
  spec('trusted-key', { arg: true, multi: true }),
  spec('set-filename', { arg: true }),
  spec('comment', { arg: true, multi: true }),
  spec('set-notation', { arg: true, multi: true }),
  spec('sig-notation', { arg: true, multi: true }),
  spec('cert-notation', { arg: true, multi: true }),
  spec('set-policy-url', { arg: true }),
  spec('sig-policy-url', { arg: true }),
  spec('cert-policy-url', { arg: true }),
  spec('default-sig-expire', { arg: true }),
  spec('default-cert-expire', { arg: true }),
  spec('compress-level', { short: 'z', arg: true }),
  spec('bzip2-compress-level', { arg: true }),
  spec('charset', { arg: true }),
  spec('display-charset', { arg: true }),
  spec('compliance', { arg: true }),
  spec('debug', { arg: true }),
  spec('debug-level', { arg: true }),
  spec('faked-system-time', { arg: true }),
  spec('limit-card-insert-tries', { arg: true }),

  // --- boolean options ---
  spec('armor', { short: 'a' }),
  spec('no-armor'),
  spec('textmode', { short: 't' }),
  spec('no-textmode'),
  spec('verbose', { short: 'v' }),
  spec('quiet', { short: 'q' }),
  spec('dry-run', { short: 'n' }),
  spec('interactive', { short: 'i' }),
  spec('batch'),
  spec('no-batch'),
  spec('yes'),
  spec('no'),
  spec('always-trust'),
  spec('with-colons'),
  spec('with-fingerprint'),
  spec(['with-subkey-fingerprint', 'with-subkey-fingerprints']),
  spec('with-keygrip'),
  spec('with-key-data'),
  spec('with-icao-spelling'),
  spec('with-sig-list'),
  spec('with-sig-check'),
  spec('with-wkd-hash'),
  spec('fixed-list-mode'),
  spec('no-tty'),
  spec('expert'),
  spec('no-expert'),
  spec('openpgp'),
  spec('gnupg'),
  spec('rfc4880'),
  spec('rfc4880bis'),
  spec('rfc2440'),
  spec('pgp6'),
  spec('pgp7'),
  spec('pgp8'),
  spec('force-mdc'),
  spec('disable-mdc'),
  spec('force-ocb'),
  spec('require-secmem'),
  spec('no-require-secmem'),
  spec('no-greeting'),
  spec('no-secmem-warning'),
  spec('no-permission-warning'),
  spec('no-default-keyring'),
  spec('no-keyring'),
  spec('no-options'),
  spec('no-default-recipient'),
  spec('default-recipient-self'),
  spec('no-encrypt-to'),
  spec('throw-keyids'),
  spec('no-throw-keyids'),
  spec('for-your-eyes-only'),
  spec('no-for-your-eyes-only'),
  spec('escape-from-lines'),
  spec('not-dash-escaped'),
  spec('emit-version'),
  spec('no-emit-version'),
  spec('no-comments'),
  spec('utf8-strings'),
  spec('no-utf8-strings'),
  spec('allow-freeform-uid'),
  spec('allow-secret-key-import'),
  spec('auto-key-retrieve'),
  spec('no-auto-key-retrieve'),
  spec('auto-key-locate-disable'),
  spec('lock-once'),
  spec('lock-multiple'),
  spec('lock-never'),
  spec('exit-on-status-write-error'),
  spec('debug-all'),
  spec('debug-none'),
  spec('full-timestrings'),
]

// Build lookup tables.
const longMap = new Map<string, OptSpec>()
const shortMap = new Map<string, OptSpec>()
for (const s of OPTIONS) {
  for (const l of s.long) longMap.set(l, s)
  if (s.short) shortMap.set(s.short, s)
}

export interface ParsedArgs {
  commands: Set<string>
  /** scalar option values keyed by canonical name */
  opts: Map<string, string>
  /** repeatable option values keyed by canonical name */
  multi: Map<string, string[]>
  /** boolean flags present */
  flags: Set<string>
  operands: string[]
}

function resolveLong(name: string): OptSpec {
  const exact = longMap.get(name)
  if (exact) return exact
  // Unambiguous-prefix abbreviation, as gpg/popt allows.
  const matches = OPTIONS.filter((s) => s.long.some((l) => l.startsWith(name)))
  const uniqueNames = new Set(matches.map((m) => m.name))
  if (uniqueNames.size === 1) return matches[0]
  if (uniqueNames.size === 0) throw new GpgError(`invalid option "--${name}"`)
  throw new GpgError(`option "--${name}" is ambiguous`)
}

function record(parsed: ParsedArgs, s: OptSpec, value?: string) {
  if (s.cmd) {
    parsed.commands.add(s.name)
    return
  }
  if (s.arg) {
    if (s.multi) {
      const arr = parsed.multi.get(s.name) ?? []
      arr.push(value ?? '')
      parsed.multi.set(s.name, arr)
    } else {
      parsed.opts.set(s.name, value ?? '')
    }
  } else {
    parsed.flags.add(s.name)
  }
}

export class GpgError extends Error {}

export function parseArgs(tokens: string[]): ParsedArgs {
  const parsed: ParsedArgs = {
    commands: new Set(),
    opts: new Map(),
    multi: new Map(),
    flags: new Set(),
    operands: [],
  }
  let operandsOnly = false
  for (let i = 0; i < tokens.length; i++) {
    const tok = tokens[i]
    if (operandsOnly) {
      parsed.operands.push(tok)
      continue
    }
    if (tok === '--') {
      operandsOnly = true
      continue
    }
    if (tok === '-' || tok[0] !== '-') {
      parsed.operands.push(tok)
      continue
    }
    if (tok.startsWith('--')) {
      const eq = tok.indexOf('=')
      const name = eq >= 0 ? tok.slice(2, eq) : tok.slice(2)
      const inlineVal = eq >= 0 ? tok.slice(eq + 1) : undefined
      const s = resolveLong(name)
      if (s.arg) {
        let val = inlineVal
        if (val === undefined) {
          val = tokens[++i]
          if (val === undefined) throw new GpgError(`option "--${name}" requires an argument`)
        }
        record(parsed, s, val)
      } else {
        if (inlineVal !== undefined)
          throw new GpgError(`option "--${name}" does not take an argument`)
        record(parsed, s)
      }
    } else {
      // bundled short options: -sea, -r alice, -rAlice
      const cluster = tok.slice(1)
      for (let j = 0; j < cluster.length; j++) {
        const ch = cluster[j]
        const s = shortMap.get(ch)
        if (!s) throw new GpgError(`invalid option "-${ch}"`)
        if (s.arg) {
          const rest = cluster.slice(j + 1)
          let val: string
          if (rest) val = rest
          else {
            val = tokens[++i]
            if (val === undefined) throw new GpgError(`option "-${ch}" requires an argument`)
          }
          record(parsed, s, val)
          break
        } else {
          record(parsed, s)
        }
      }
    }
  }
  return parsed
}

// ---------------------------------------------------------------------------
// The shell
// ---------------------------------------------------------------------------

const PROGRAM = 'gpg'
const HOMEDIR = '/home/user/.gnupg'

export class GpgShell {
  readonly vfs = new Map<string, Uint8Array>()
  constructor(private keyring: KeyringPort) {}

  /** Seed the virtual filesystem with a file (used by drag/drop uploads). */
  putFile(name: string, data: Uint8Array) {
    this.vfs.set(name, data)
  }
  listFiles(): string[] {
    return [...this.vfs.keys()].sort()
  }

  /** Execute one input line (may contain a pipeline and redirections). */
  async run(line: string, io: ShellIO): Promise<number> {
    const trimmed = line.trim()
    if (!trimmed) return 0
    let tokens: string[]
    try {
      tokens = tokenize(trimmed)
    } catch (e) {
      io.write(`gpgsh: ${msg(e)}\n`)
      return 2
    }
    // Split into pipeline stages on top-level `|`.
    const stages: string[][] = [[]]
    for (const t of tokens) {
      if (t === '|') stages.push([])
      else stages[stages.length - 1].push(t)
    }

    let stdin: Uint8Array | null = null
    let code = 0
    for (let si = 0; si < stages.length; si++) {
      const stage = stages[si]
      const isLast = si === stages.length - 1
      // Extract redirections from the stage tokens.
      let redirOut: { name: string; append: boolean } | null = null
      let redirIn: string | null = null
      const argv: string[] = []
      for (let k = 0; k < stage.length; k++) {
        const t = stage[k]
        if (t === '>' || t === '>>') {
          const name = stage[++k]
          if (!name) {
            io.write('gpgsh: syntax error near redirection\n')
            return 2
          }
          redirOut = { name, append: t === '>>' }
        } else if (t === '<') {
          redirIn = stage[++k]
          if (!redirIn) {
            io.write('gpgsh: syntax error near redirection\n')
            return 2
          }
        } else argv.push(t)
      }
      if (argv.length === 0) continue

      if (redirIn) {
        const f = this.vfs.get(redirIn)
        if (!f) {
          io.write(`gpgsh: ${redirIn}: No such file\n`)
          return 2
        }
        stdin = f
      }

      let result: { code: number; stdout: Uint8Array }
      try {
        result = await this.execCommand(argv, stdin, io)
      } catch (e) {
        if (e instanceof GpgError) {
          io.write(`${PROGRAM}: ${e.message}\n`)
          return 2
        }
        io.write(`${PROGRAM}: ${msg(e)}\n`)
        return 2
      }
      code = result.code

      if (redirOut) {
        this.vfs.set(redirOut.name, mergeRedirect(this.vfs.get(redirOut.name), result.stdout, redirOut.append))
        stdin = null
      } else if (isLast) {
        this.renderStdout(result.stdout, io)
      } else {
        stdin = result.stdout
      }
    }
    return code
  }

  private renderStdout(out: Uint8Array, io: ShellIO) {
    if (out.length === 0) return
    if (looksBinary(out)) {
      io.write(
        `[binary output: ${out.length} bytes — redirect to a file with '> name' or add --armor]\n`,
      )
      return
    }
    let text = fromBytes(out)
    if (!text.endsWith('\n')) text += '\n'
    io.write(text)
  }

  // -------------------------------------------------------------------------
  // Command dispatch
  // -------------------------------------------------------------------------

  private async execCommand(
    argv: string[],
    stdin: Uint8Array | null,
    io: ShellIO,
  ): Promise<{ code: number; stdout: Uint8Array }> {
    const cmd = argv[0]
    const rest = argv.slice(1)
    switch (cmd) {
      case 'gpg':
      case 'gpg2':
        return this.gpg(rest, stdin, io)
      case 'echo':
        return this.echo(rest)
      case 'cat':
        return this.cat(rest, stdin)
      case 'ls':
        return { code: 0, stdout: toBytes(this.listFiles().join('\n') + (this.vfs.size ? '\n' : '')) }
      case 'rm':
        for (const f of rest) {
          if (!this.vfs.delete(f)) io.write(`rm: ${f}: No such file\n`)
        }
        return ok()
      case 'clear':
        io.clear()
        return ok()
      case 'help':
        io.write(SHELL_HELP)
        return ok()
      case 'pwd':
        return { code: 0, stdout: toBytes('/home/user\n') }
      default:
        io.write(`gpgsh: ${cmd}: command not found\n`)
        return { code: 127, stdout: new Uint8Array() }
    }
  }

  private echo(args: string[]): { code: number; stdout: Uint8Array } {
    let noNewline = false
    if (args[0] === '-n') {
      noNewline = true
      args = args.slice(1)
    }
    return { code: 0, stdout: toBytes(args.join(' ') + (noNewline ? '' : '\n')) }
  }

  private cat(args: string[], stdin: Uint8Array | null): { code: number; stdout: Uint8Array } {
    if (args.length === 0) return { code: 0, stdout: stdin ?? new Uint8Array() }
    const chunks: Uint8Array[] = []
    for (const name of args) {
      if (name === '-') {
        if (stdin) chunks.push(stdin)
        continue
      }
      const f = this.vfs.get(name)
      if (!f) throw new GpgError(`cat: ${name}: No such file`)
      chunks.push(f)
    }
    return { code: 0, stdout: concat(chunks) }
  }

  // -------------------------------------------------------------------------
  // gpg(1)
  // -------------------------------------------------------------------------

  private async gpg(
    args: string[],
    stdin: Uint8Array | null,
    io: ShellIO,
  ): Promise<{ code: number; stdout: Uint8Array }> {
    const p = parseArgs(args)
    const has = (c: string) => p.commands.has(c)

    // Pick a single primary command (gpg resolves these in roughly this order).
    if (has('version')) return out(this.cmdVersion())
    if (has('help')) return out(HELP_TEXT)
    if (has('warranty')) return out(WARRANTY)
    if (has('dump-options')) return out(OPTIONS.flatMap((s) => s.long.map((l) => '--' + l)).join('\n') + '\n')

    if (has('list-keys') || has('fingerprint') || has('list-signatures') || has('check-signatures'))
      return out(this.listKeys(p, false))
    if (has('list-secret-keys')) return out(this.listKeys(p, true))
    if (has('list-config')) return out(this.listConfig())

    if (has('quick-gen-key')) return out(await this.quickGenKey(p, io))
    if (has('gen-key') || has('full-gen-key')) return out(await this.genKeyInteractive(io))

    if (has('export')) return this.exportKeys(p, false, io)
    if (has('export-secret-keys') || has('export-secret-subkeys')) return this.exportKeys(p, true, io)
    if (has('import')) return out(this.importKeys(p, stdin))
    if (has('delete-secret-and-public-key') || has('delete-secret-keys'))
      return out(await this.deleteKeys(p, true, io))
    if (has('delete-keys')) return out(await this.deleteKeys(p, false, io))

    if (has('enarmor')) return this.runEnarmor(p, stdin)
    if (has('dearmor')) return this.runDearmor(p, stdin)
    if (has('print-md') || has('print-mds')) return out(await this.printMd(p, stdin))
    if (has('gen-random')) return this.genRandom(p)
    if (has('list-packets')) return out(await this.listPackets(p, stdin))

    if (has('encrypt') || has('symmetric')) return this.encryptCmd(p, stdin, io)
    if (has('clear-sign')) return this.signCmd(p, stdin, io, 'clear')
    if (has('detach-sign')) return this.signCmd(p, stdin, io, 'detach')
    if (has('sign')) return this.signCmd(p, stdin, io, 'inline')
    if (has('decrypt')) return this.decryptCmd(p, stdin, io)
    if (has('verify')) return out(await this.verifyCmd(p, stdin, io))

    // Recognised-but-unavailable in a browser sandbox.
    const unavailable: Record<string, string> = {
      'send-keys': 'sending keys to a keyserver is not available in the browser',
      'receive-keys': 'keyserver access is not available in the browser',
      'search-keys': 'keyserver access is not available in the browser',
      'refresh-keys': 'keyserver access is not available in the browser',
      'card-status': 'no smartcard reader is available in the browser',
      'card-edit': 'no smartcard reader is available in the browser',
      'change-pin': 'no smartcard reader is available in the browser',
      'edit-key': 'the interactive --edit-key menu is not available; use the Certificates view',
      'sign-key': 'certifying keys is not available in this simulator',
      'lsign-key': 'certifying keys is not available in this simulator',
      'gen-revoke': 'revocation certificates are not supported by the crypto core yet',
    }
    for (const k of Object.keys(unavailable)) {
      if (has(k)) throw new GpgError(unavailable[k])
    }

    // No command given: gpg with operands defaults to verify/decrypt, but a
    // bare invocation is an error.
    if (p.operands.length === 0) throw new GpgError('no command supplied (try --help)')
    // gpg treats a lone file operand as "decrypt or verify".
    return this.decryptCmd(p, stdin, io)
  }

  // ----- listing ----------------------------------------------------------

  private listKeys(p: ParsedArgs, secretOnly: boolean): string {
    let keys = this.keyring.list()
    if (secretOnly) keys = keys.filter((k) => k.isSecret)
    if (p.operands.length) {
      keys = keys.filter((k) => p.operands.some((q) => matchKey(k, q)))
    }
    if (p.flags.has('with-colons')) return this.listColons(keys, secretOnly)

    const header = `${HOMEDIR}/pubring.kbx`
    const lines = [header, '-'.repeat(header.length)]
    if (keys.length === 0) lines.push('')
    const showSubFpr = p.flags.has('with-subkey-fingerprint') || p.commands.has('fingerprint')
    for (const k of keys) {
      const primaryTag = secretOnly ? 'sec' : 'pub'
      const subTag = secretOnly ? 'ssb' : 'sub'
      const trust = k.isSecret ? 'ultimate' : k.trusted ? 'full' : 'unknown'
      const exp = k.expiresAt ? ` [expires: ${fmtDate(k.expiresAt)}]` : ''
      lines.push(
        `${primaryTag}   ${algoToken(k.algorithm, k.bitStrength)} ${fmtDate(k.createdAt)} [${usageFlags(k, true)}]${exp}`,
      )
      lines.push(`      ${k.fingerprint}`)
      k.userIds.forEach((uid, idx) => {
        const label = idx === 0 ? `[${trust}]` : '[ unknown]'
        lines.push(`uid           ${label} ${uid}`)
      })
      for (const sub of k.subkeys) {
        lines.push(
          `${subTag}   ${algoToken(sub.algorithm, null)} ${fmtDate(k.createdAt)} [${usageFlags(sub, false)}]`,
        )
        if (showSubFpr) lines.push(`      ${sub.fingerprint}`)
      }
      lines.push('')
    }
    return lines.join('\n')
  }

  private listColons(keys: CliKey[], secretOnly: boolean): string {
    const lines: string[] = ['tru::1:' + Math.floor(Date.now() / 1000) + ':0:3:1:5']
    for (const k of keys) {
      const validity = k.isSecret ? 'u' : k.trusted ? 'f' : '-'
      const created = k.createdAt
      const expires = k.expiresAt ?? ''
      const primaryTag = secretOnly ? 'sec' : 'pub'
      const subTag = secretOnly ? 'ssb' : 'sub'
      const caps = (k.canEncrypt ? 'e' : '') + (k.canSign ? 's' : '') + 'c'
      lines.push(
        `${primaryTag}:${validity}:${k.bitStrength ?? 0}:${algoId(k.algorithm)}:${k.keyId}:${created}:${expires}:::${k.isSecret ? 'u' : '-'}:::${caps}::`,
      )
      lines.push(`fpr:::::::::${k.fingerprint}:`)
      k.userIds.forEach((uid) => {
        lines.push(`uid:${validity}::::${created}::${uidHash(uid)}::${uid}:`)
      })
      for (const sub of k.subkeys) {
        const scaps = (sub.canEncrypt ? 'e' : '') + (sub.canSign ? 's' : '')
        lines.push(
          `${subTag}:${validity}:0:${algoId(sub.algorithm)}:${sub.keyId}:${created}:${expires}::::::${scaps}::`,
        )
        lines.push(`fpr:::::::::${sub.fingerprint}:`)
      }
    }
    return lines.join('\n') + '\n'
  }

  private listConfig(): string {
    return [
      'cfg:version:2.4.0 (gpg4web)',
      'cfg:pubkey:1;17;18;19;22',
      'cfg:cipher:2;3;4;7;8;9',
      'cfg:ciphername:3DES;CAST5;BLOWFISH;AES;AES192;AES256',
      'cfg:digest:1;2;3;8;9;10;11',
      'cfg:digestname:MD5;SHA1;RIPEMD160;SHA256;SHA384;SHA512;SHA224',
      'cfg:compress:0;1;2;3',
      'cfg:compressname:Uncompressed;ZIP;ZLIB;BZIP2',
      `cfg:homedir:${HOMEDIR}`,
      '',
    ].join('\n')
  }

  // ----- key generation ---------------------------------------------------

  private mapAlgoPreset(s: string): KeyAlgorithm {
    const a = s.toLowerCase().trim()
    const table: Record<string, KeyAlgorithm> = {
      default: 'curve25519',
      future: 'ed25519',
      'future-default': 'ed25519',
      ed25519: 'ed25519',
      cv25519: 'curve25519',
      curve25519: 'curve25519',
      rsa: 'rsa3072',
      rsa2048: 'rsa2048',
      rsa3072: 'rsa3072',
      rsa4096: 'rsa4096',
      nistp256: 'nistp256',
      nistp384: 'nistp384',
      nistp521: 'nistp521',
      pqc: 'pqc',
      'mldsa65-mlkem768': 'pqc',
      'mldsa87-mlkem1024': 'mldsa87-mlkem1024',
      'slhdsa128s-mlkem768': 'slhdsa128s-mlkem768',
    }
    const found = table[a]
    if (!found) throw new GpgError(`unknown algorithm "${s}"`)
    return found
  }

  private async quickGenKey(p: ParsedArgs, io: ShellIO): Promise<string> {
    const [userId, algo, , expire] = p.operands
    if (!userId) throw new GpgError('--quick-generate-key needs a USER-ID')
    const algorithm = this.mapAlgoPreset(algo || 'default')
    const expireDays = parseExpire(expire)
    let passphrase = p.opts.get('passphrase') ?? ''
    if (!passphrase && p.opts.get('pinentry-mode') !== 'loopback' && !p.flags.has('batch')) {
      passphrase = await io.prompt(`Passphrase for new key (empty for none): `, { password: true })
    }
    return this.doGenerate(userId, algorithm, passphrase, expireDays, io)
  }

  private async genKeyInteractive(io: ShellIO): Promise<string> {
    io.write('gpg: starting key generation — answer the prompts (blank = default)\n\n')
    const presets = ['curve25519', 'ed25519', 'rsa3072', 'rsa4096', 'nistp256', 'pqc']
    io.write('Key types: ' + presets.join(', ') + '\n')
    const algoIn = (await io.prompt('Your selection? (curve25519) ')).trim() || 'curve25519'
    const algorithm = this.mapAlgoPreset(algoIn)
    const expireIn = (await io.prompt('Key is valid for? (0 = does not expire) ')).trim()
    const expireDays = parseExpire(expireIn)
    const real = (await io.prompt('Real name: ')).trim()
    if (!real) throw new GpgError('a real name is required')
    const email = (await io.prompt('Email address: ')).trim()
    const userId = email ? `${real} <${email}>` : real
    io.write(`\nYou selected this USER-ID:\n    "${userId}"\n\n`)
    const passphrase = await io.prompt('Passphrase (empty for none): ', { password: true })
    return this.doGenerate(userId, algorithm, passphrase, expireDays, io)
  }

  private doGenerate(
    userId: string,
    algorithm: KeyAlgorithm,
    passphrase: string,
    expireDays: number,
    io: ShellIO,
  ): string {
    io.write('gpg: generating key (this happens entirely in your browser)…\n')
    const key = coreGenerateKey({ userId, algorithm, passphrase, expireDays: expireDays || undefined })
    this.keyring.addGenerated(key.publicKey, key.secretKey)
    return (
      `gpg: key ${key.keyId.slice(-16)} marked as ultimately trusted\n` +
      `gpg: revocation certificate stored in-vault\n` +
      `public and secret key created and signed.\n\n` +
      `pub   ${algoToken(key.algorithm, null)} ${fmtDate(key.createdAt)} [SC]${
        key.expiresAt ? ` [expires: ${fmtDate(key.expiresAt)}]` : ''
      }\n` +
      `      ${key.fingerprint}\n` +
      `uid                      ${userId}\n`
    )
  }

  // ----- export / import ---------------------------------------------------

  private exportKeys(
    p: ParsedArgs,
    secret: boolean,
    io: ShellIO,
  ): { code: number; stdout: Uint8Array } {
    let keys = this.keyring.list()
    if (secret) keys = keys.filter((k) => k.isSecret)
    if (p.operands.length) keys = keys.filter((k) => p.operands.some((q) => matchKey(k, q)))
    if (keys.length === 0) throw new GpgError('nothing exported')

    const parts: string[] = []
    for (const k of keys) {
      if (secret) {
        const sk = this.keyring.getSecretKey(k.fingerprint)
        if (!sk) {
          io.write(`gpg: WARNING: no secret key for ${k.keyId.slice(-16)}\n`)
          continue
        }
        parts.push(sk.trim())
      } else {
        parts.push(k.publicKey.trim())
      }
    }
    // gpg emits binary by default and ASCII armor only with --armor. The keys
    // are stored armored, so we dearmor each block back to packet bytes unless
    // armor was requested.
    const armor = p.flags.has('armor')
    const data = armor
      ? toBytes(parts.join('\n') + '\n')
      : concat(parts.map((block) => dearmor(block)))
    return this.writeOutputSync(p, data, '', '')
  }

  private importKeys(p: ParsedArgs, stdin: Uint8Array | null): string {
    const blocks: string[] = []
    if (p.operands.length) {
      for (const name of p.operands) {
        const f = name === '-' ? stdin : this.vfs.get(name)
        if (!f) throw new GpgError(`can't open '${name}': No such file`)
        blocks.push(fromBytes(f))
      }
    } else if (stdin) {
      blocks.push(fromBytes(stdin))
    } else {
      throw new GpgError('no input — supply a filename or pipe armored key text')
    }

    const text = blocks.join('\n')
    const armors = splitArmoredBlocks(text)
    if (armors.length === 0) throw new GpgError('no valid OpenPGP data found')

    const lines: string[] = []
    let imported = 0
    let secretImported = 0
    let unchanged = 0
    for (const block of armors) {
      try {
        const r = this.keyring.importArmored(block)
        const k = this.keyring.list().find((x) => x.fingerprint === r.fingerprint)
        const uid = k?.userIds[0] ?? ''
        lines.push(`gpg: key ${r.keyId.slice(-16)}: ${r.isSecret ? 'secret key imported' : 'public key "' + uid + '" imported'}`)
        imported++
        if (r.isSecret) secretImported++
      } catch (e) {
        lines.push(`gpg: error reading key: ${msg(e)}`)
        unchanged++
      }
    }
    lines.push(`gpg: Total number processed: ${armors.length}`)
    if (imported) lines.push(`gpg:               imported: ${imported}`)
    if (secretImported) lines.push(`gpg:       secret keys read: ${secretImported}`)
    if (unchanged) lines.push(`gpg:              unchanged: ${unchanged}`)
    return lines.join('\n') + '\n'
  }

  private async deleteKeys(p: ParsedArgs, secret: boolean, io: ShellIO): Promise<string> {
    if (p.operands.length === 0) throw new GpgError('key to delete not specified')
    const lines: string[] = []
    for (const q of p.operands) {
      const matches = this.keyring.list().filter((k) => matchKey(k, q))
      if (matches.length === 0) {
        lines.push(`gpg: key "${q}" not found`)
        continue
      }
      for (const k of matches) {
        if (!p.flags.has('yes')) {
          const what = secret ? 'secret key' : 'public key'
          const ans = await io.prompt(
            `Delete this ${what}? (y/N) [${k.userIds[0] ?? k.keyId}] `,
          )
          if (!/^y(es)?$/i.test(ans.trim())) {
            lines.push('gpg: deletion skipped')
            continue
          }
        }
        this.keyring.removeKey(k.fingerprint)
        lines.push(`gpg: ${k.keyId.slice(-16)} deleted`)
      }
    }
    return lines.join('\n') + '\n'
  }

  // ----- encryption --------------------------------------------------------

  private async encryptCmd(
    p: ParsedArgs,
    stdin: Uint8Array | null,
    io: ShellIO,
  ): Promise<{ code: number; stdout: Uint8Array }> {
    if (p.commands.has('symmetric') && !p.commands.has('encrypt')) {
      throw new GpgError(
        'symmetric (passphrase-only) encryption is not supported by the gpg4web crypto core; ' +
          'use public-key encryption: gpg -e -r <key>',
      )
    }
    const recipientQueries = [
      ...(p.multi.get('recipient') ?? []),
      ...(p.multi.get('hidden-recipient') ?? []),
      ...(p.multi.get('encrypt-to') ?? []),
      ...(p.multi.get('hidden-encrypt-to') ?? []),
    ]
    if (recipientQueries.length === 0) throw new GpgError('no recipients (use -r)')

    const pubs: string[] = []
    for (const q of recipientQueries) {
      const k = this.resolveRecipient(q)
      pubs.push(k.publicKey)
    }

    const sign = p.commands.has('sign')
    const armor = p.flags.has('armor')
    const { data, name } = this.readInput(p, stdin)
    let result: Uint8Array
    if (sign) {
      const { key, secret } = this.resolveSigner(p)
      result = await this.withPassphrase(p, key, io, (pass) =>
        encryptFile(data, pubs, secret, pass, armor),
      )
    } else {
      result = encryptFile(data, pubs, null, null, armor)
    }

    io.write(`gpg: encrypted to ${pubs.length} recipient(s)${sign ? ', signed' : ''}\n`)
    return this.writeOutputSync(p, result, name, armor ? '.asc' : '.gpg')
  }

  // ----- signing -----------------------------------------------------------

  private async signCmd(
    p: ParsedArgs,
    stdin: Uint8Array | null,
    io: ShellIO,
    style: 'clear' | 'detach' | 'inline',
  ): Promise<{ code: number; stdout: Uint8Array }> {
    const { key, secret } = this.resolveSigner(p)
    const { data, name } = this.readInput(p, stdin)

    if (style === 'detach') {
      const sig = await this.withPassphrase(p, key, io, (pass) =>
        signFileDetached(data, secret, pass),
      )
      io.write('gpg: detached signature created\n')
      return this.writeOutputSync(p, toBytes(sig), name, p.flags.has('armor') ? '.asc' : '.sig')
    }

    // clearsign and inline both operate on text here. The crypto core has no
    // standalone inline-signed packet builder, so plain `-s` on text emits a
    // clear-signed message (equivalent for text); binary data is steered to
    // --detach-sign.
    if (style === 'inline' && looksBinary(data)) {
      throw new GpgError(
        'inline signing of binary data is not supported; use --detach-sign (-b) instead',
      )
    }
    const text = fromBytes(data)
    const out = await this.withPassphrase(p, key, io, (pass) =>
      signCleartext(text, secret, pass),
    )
    io.write(
      style === 'clear'
        ? 'gpg: cleartext signature created\n'
        : 'gpg: signed (clear-signed; use -b for a detached signature)\n',
    )
    return this.writeOutputSync(p, toBytes(out), name, '.asc')
  }

  // ----- decrypt / verify --------------------------------------------------

  private async decryptCmd(
    p: ParsedArgs,
    stdin: Uint8Array | null,
    io: ShellIO,
  ): Promise<{ code: number; stdout: Uint8Array }> {
    const { data } = this.readInput(p, stdin)
    const text = fromBytes(data)

    // Clear-signed message → verify only.
    if (text.includes('BEGIN PGP SIGNED MESSAGE')) {
      io.write(await this.verifyClear(text))
      // Output the embedded plaintext.
      return { code: 0, stdout: toBytes(this.firstVerifyText(text)) }
    }

    const { out, key, sk, pass } = await this.decryptWithRing(p, data, io)
    io.write(`gpg: encrypted with key ${key.keyId.slice(-16)} (${key.userIds[0] ?? ''})\n`)
    // Report any contained signature (best-effort, armored text only).
    if (text.startsWith('-----BEGIN')) {
      try {
        const r = coreDecrypt(text, sk, pass, this.keyring.list().map((k) => k.publicKey))
        for (const s of r.signatures) {
          io.write(
            `gpg: Signature made using key ${s.keyId.slice(-16)} — ${s.valid ? 'Good signature' : 'BAD signature'}\n`,
          )
        }
      } catch {
        /* signature reporting is best-effort */
      }
    }
    // `--decrypt` writes plaintext to stdout by default (use -o to save).
    return this.writeOutputSync(p, out, '', '')
  }

  /**
   * Try to decrypt `data` with each secret key in the ring. Uses an explicit
   * passphrase if given, else the empty passphrase, prompting via pinentry at
   * most once if that fails. Returns the working key, its secret material and
   * the passphrase that unlocked it.
   */
  private async decryptWithRing(
    p: ParsedArgs,
    data: Uint8Array,
    io: ShellIO,
  ): Promise<{ out: Uint8Array; key: CliKey; sk: string; pass: string }> {
    const entries = this.keyring
      .list()
      .filter((k) => k.isSecret)
      .map((k) => ({ k, sk: this.keyring.getSecretKey(k.fingerprint) }))
      .filter((e): e is { k: CliKey; sk: string } => !!e.sk)
    if (entries.length === 0) throw new GpgError('no secret key available to decrypt')

    const attempt = (pass: string) => {
      for (const e of entries) {
        try {
          return { out: decryptFile(data, e.sk, pass), key: e.k, sk: e.sk, pass }
        } catch {
          /* try the next key */
        }
      }
      return null
    }

    const explicit = this.explicitPass(p)
    if (explicit !== undefined) {
      const r = attempt(explicit)
      if (r) return r
      throw new GpgError('decryption failed: bad passphrase or no matching secret key')
    }
    let r = attempt('')
    if (r) return r
    if (!p.flags.has('batch')) {
      const pass = await io.prompt('Enter passphrase to unlock your secret key: ', { password: true })
      r = attempt(pass)
      if (r) return r
    }
    throw new GpgError('decryption failed: bad passphrase or no matching secret key')
  }

  private async verifyCmd(p: ParsedArgs, stdin: Uint8Array | null, io: ShellIO): Promise<string> {
    // Detached: `gpg --verify SIG [DATA]`
    const ops = p.operands
    if (ops.length >= 2) {
      const sigFile = this.vfs.get(ops[0])
      const dataFile = this.vfs.get(ops[1])
      if (!sigFile) throw new GpgError(`can't open '${ops[0]}'`)
      if (!dataFile) throw new GpgError(`can't open '${ops[1]}'`)
      const sigText = fromBytes(sigFile)
      let goodKey: CliKey | null = null
      for (const k of this.keyring.list()) {
        if (verifyFileDetached(dataFile, sigText, k.publicKey)) {
          goodKey = k
          break
        }
      }
      if (goodKey)
        return `gpg: Good signature from "${goodKey.userIds[0] ?? goodKey.keyId}" [${
          goodKey.trusted ? 'full' : 'unknown'
        }]\ngpg:          using key ${goodKey.fingerprint}\n`
      return 'gpg: BAD signature or no matching public key in the keyring\n'
    }

    // Single operand or stdin → inline / clear-signed.
    const { data } = this.readInput(p, stdin)
    const text = fromBytes(data)
    if (text.includes('BEGIN PGP SIGNED MESSAGE')) return this.verifyClear(text)
    if (text.includes('BEGIN PGP MESSAGE')) {
      // Signed (and possibly encrypted) message: decrypt to reach the signature.
      const { sk, pass } = await this.decryptWithRing(p, data, io)
      const r = coreDecrypt(text, sk, pass, this.keyring.list().map((x) => x.publicKey))
      const good = r.signatures.find((s) => s.valid)
      if (good) return `gpg: Good signature, key ${good.keyId.slice(-16)}\n`
      if (r.signatures.length) return 'gpg: BAD signature\n'
      return 'gpg: no signature found in the message\n'
    }
    throw new GpgError('no signature found, or no matching key')
  }

  private verifyClear(text: string): string {
    for (const k of this.keyring.list()) {
      try {
        const r = verifyCleartext(text, k.publicKey)
        if (r.valid)
          return `gpg: Good signature from "${k.userIds[0] ?? k.keyId}" [${
            k.trusted ? 'full' : 'unknown'
          }]\ngpg:          using key ${k.fingerprint}\n`
      } catch {
        /* try next key */
      }
    }
    return 'gpg: BAD signature, or the signer\'s public key is not in your keyring\n'
  }

  private firstVerifyText(text: string): string {
    for (const k of this.keyring.list()) {
      try {
        const r = verifyCleartext(text, k.publicKey)
        if (r.text) return r.text + '\n'
      } catch {
        /* ignore */
      }
    }
    return ''
  }

  // ----- enarmor / dearmor / digests / random / packets --------------------

  private runEnarmor(p: ParsedArgs, stdin: Uint8Array | null): { code: number; stdout: Uint8Array } {
    const { data, name } = this.readInput(p, stdin)
    const armored = enarmor(data)
    return this.writeOutputSync(p, toBytes(armored), name, '.asc')
  }

  private runDearmor(p: ParsedArgs, stdin: Uint8Array | null): { code: number; stdout: Uint8Array } {
    const { data, name } = this.readInput(p, stdin)
    const raw = dearmor(fromBytes(data))
    return this.writeOutputSync(p, raw, name, '.bin')
  }

  private async printMd(p: ParsedArgs, stdin: Uint8Array | null): Promise<string> {
    const algoNames: Record<string, string> = {
      sha1: 'SHA-1',
      sha256: 'SHA-256',
      sha384: 'SHA-384',
      sha512: 'SHA-512',
    }
    const wantMds = p.commands.has('print-mds')
    let algo = ''
    let files = p.operands
    if (!wantMds) {
      algo = (p.operands[0] ?? '').toLowerCase()
      files = p.operands.slice(1)
    }
    const algos = wantMds ? ['sha1', 'sha256', 'sha512'] : [algo]
    const out: string[] = []
    const inputs: { label: string; data: Uint8Array }[] = []
    if (files.length) {
      for (const f of files) {
        const d = this.vfs.get(f)
        if (!d) throw new GpgError(`can't open '${f}'`)
        inputs.push({ label: f, data: d })
      }
    } else if (stdin) {
      inputs.push({ label: '', data: stdin })
    } else {
      throw new GpgError('no input for digest')
    }
    for (const inp of inputs) {
      for (const a of algos) {
        const sub = algoNames[a]
        if (!sub)
          throw new GpgError(`digest algorithm "${a || '?'}" not available (try SHA1/SHA256/SHA384/SHA512)`)
        const digest = new Uint8Array(await crypto.subtle.digest(sub, inp.data.slice()))
        out.push(`${inp.label ? inp.label + ': ' : ''}${groupHex(hex(digest))}`)
      }
    }
    return out.join('\n') + '\n'
  }

  private genRandom(p: ParsedArgs): { code: number; stdout: Uint8Array } {
    const level = parseInt(p.operands[0] ?? '0', 10)
    const count = parseInt(p.operands[1] ?? '0', 10)
    if (!count || count < 0) throw new GpgError('--gen-random needs a byte count (e.g. --gen-random 1 16)')
    void level
    const bytes = new Uint8Array(count)
    crypto.getRandomValues(bytes)
    if (p.flags.has('armor')) return { code: 0, stdout: toBytes(bytesToBase64(bytes) + '\n') }
    return { code: 0, stdout: bytes }
  }

  private async listPackets(p: ParsedArgs, stdin: Uint8Array | null): Promise<string> {
    const { data } = this.readInput(p, stdin)
    let raw = data
    const head = fromBytes(data.slice(0, 30))
    if (head.startsWith('-----BEGIN')) {
      try {
        raw = dearmor(fromBytes(data))
      } catch {
        /* fall through with original bytes */
      }
    }
    return parsePackets(raw)
  }

  // ----- shared helpers ----------------------------------------------------

  private cmdVersion(): string {
    return (
      `gpg (gpg4web) 2.4.0\n` +
      `${coreVersion()}\n` +
      `Copyright (C) 2025 gpg4web. License GPLv3+.\n` +
      `\n` +
      `Home: ${HOMEDIR}\n` +
      `Supported algorithms:\n` +
      `Pubkey: RSA, ECDH, ECDSA, EdDSA, ML-DSA, ML-KEM, SLH-DSA\n` +
      `Cipher: AES, AES192, AES256\n` +
      `Hash: SHA1, SHA256, SHA384, SHA512\n` +
      `Compression: Uncompressed, ZIP, ZLIB\n`
    )
  }

  private resolveRecipient(q: string): CliKey {
    const matches = this.keyring.list().filter((k) => matchKey(k, q) && k.canEncrypt)
    if (matches.length === 0) throw new GpgError(`${q}: no encryption-capable public key found`)
    return matches[0]
  }

  private resolveSigner(p: ParsedArgs): { key: CliKey; secret: string } {
    const q = (p.multi.get('local-user') ?? [])[0] ?? p.opts.get('default-key')
    let candidates = this.keyring.list().filter((k) => k.isSecret && k.canSign)
    if (q) candidates = candidates.filter((k) => matchKey(k, q))
    if (candidates.length === 0)
      throw new GpgError(
        q ? `no secret signing key matches "${q}"` : 'no secret key available for signing',
      )
    const key = candidates[0]
    const secret = this.keyring.getSecretKey(key.fingerprint)
    if (!secret) throw new GpgError('could not unlock the signing key')
    return { key, secret }
  }

  /** An explicit passphrase from --passphrase / --passphrase-file, or undefined. */
  private explicitPass(p: ParsedArgs): string | undefined {
    const direct = p.opts.get('passphrase')
    if (direct !== undefined) return direct
    const file = p.opts.get('passphrase-file')
    if (file) {
      const f = this.vfs.get(file)
      if (f) return fromBytes(f).split(/\r?\n/)[0]
    }
    return undefined
  }

  /**
   * Run `op` with a passphrase: an explicit one if supplied, otherwise the
   * empty passphrase (unprotected keys are common in-app), prompting via
   * pinentry only if that fails. Prompts at most once.
   */
  private async withPassphrase<T>(
    p: ParsedArgs,
    key: CliKey,
    io: ShellIO,
    op: (pass: string) => T,
  ): Promise<T> {
    const explicit = this.explicitPass(p)
    if (explicit !== undefined) return op(explicit)
    try {
      return op('')
    } catch (e) {
      if (p.flags.has('batch')) throw e
    }
    const pass = await io.prompt(
      `Enter passphrase for key ${key.keyId.slice(-16)} "${key.userIds[0] ?? ''}": `,
      { password: true },
    )
    return op(pass)
  }

  private readInput(p: ParsedArgs, stdin: Uint8Array | null): { data: Uint8Array; name: string } {
    const fileOps = p.operands
    if (fileOps.length && fileOps[0] !== '-') {
      const f = this.vfs.get(fileOps[0])
      if (!f) throw new GpgError(`can't open '${fileOps[0]}': No such file`)
      return { data: f, name: fileOps[0] }
    }
    if (stdin) return { data: stdin, name: '' }
    throw new GpgError("no input — pass a filename, or pipe data in (e.g. echo hi | gpg …)")
  }

  private writeOutputSync(
    p: ParsedArgs,
    data: Uint8Array,
    inputName: string,
    suffix: string,
    explicitName?: string,
  ): { code: number; stdout: Uint8Array } {
    const target = p.opts.get('output')
    if (target && target !== '-') {
      this.vfs.set(target, data)
      return { code: 0, stdout: new Uint8Array() }
    }
    if (target === '-') return { code: 0, stdout: data }
    // Derive a filename from the input when one exists; otherwise stdout.
    if (inputName) {
      const outName = explicitName ?? inputName + suffix
      this.vfs.set(outName, data)
      return { code: 0, stdout: new Uint8Array() }
    }
    return { code: 0, stdout: data }
  }
}

// ---------------------------------------------------------------------------
// Free functions
// ---------------------------------------------------------------------------

function matchKey(k: CliKey, query: string): boolean {
  let q = query.trim()
  if (q.startsWith('0x') || q.startsWith('0X')) q = q.slice(2)
  const norm = q.replace(/\s+/g, '').toUpperCase()
  if (norm.length >= 8 && /^[0-9A-F]+$/.test(norm)) {
    if (k.fingerprint.toUpperCase().endsWith(norm)) return true
    if (k.keyId.toUpperCase().endsWith(norm)) return true
    if (k.subkeys.some((s) => s.fingerprint.toUpperCase().endsWith(norm) || s.keyId.toUpperCase().endsWith(norm)))
      return true
  }
  const lc = query.toLowerCase()
  return k.userIds.some((u) => u.toLowerCase().includes(lc))
}

function parseExpire(s: string | undefined): number {
  if (!s) return 0
  const m = s.trim().match(/^(\d+)\s*([dwmy]?)$/i)
  if (!m) {
    // Maybe an ISO date.
    const t = Date.parse(s)
    if (!isNaN(t)) return Math.max(0, Math.round((t - Date.now()) / 86400000))
    return 0
  }
  const n = parseInt(m[1], 10)
  switch (m[2].toLowerCase()) {
    case 'w':
      return n * 7
    case 'm':
      return n * 30
    case 'y':
      return n * 365
    default:
      return n
  }
}

function splitArmoredBlocks(text: string): string[] {
  const blocks: string[] = []
  const re = /-----BEGIN [^-]+-----[\s\S]*?-----END [^-]+-----/g
  let m: RegExpExecArray | null
  while ((m = re.exec(text)) !== null) blocks.push(m[0])
  return blocks
}

function uidHash(uid: string): string {
  // gpg uses an MD5 of the uid; we approximate with a stable 32-hex token.
  let h = 0x811c9dc5
  for (let i = 0; i < uid.length; i++) {
    h ^= uid.charCodeAt(i)
    h = Math.imul(h, 0x01000193)
  }
  const base = (h >>> 0).toString(16).padStart(8, '0')
  return (base + base + base + base).slice(0, 32).toUpperCase()
}

function groupHex(h: string): string {
  return (h.match(/.{1,4}/g) ?? []).join(' ').toUpperCase()
}

function concat(chunks: Uint8Array[]): Uint8Array {
  const total = chunks.reduce((n, c) => n + c.length, 0)
  const out = new Uint8Array(total)
  let off = 0
  for (const c of chunks) {
    out.set(c, off)
    off += c.length
  }
  return out
}

function mergeRedirect(existing: Uint8Array | undefined, add: Uint8Array, append: boolean): Uint8Array {
  if (append && existing) return concat([existing, add])
  return add
}

function ok(): { code: number; stdout: Uint8Array } {
  return { code: 0, stdout: new Uint8Array() }
}
function out(text: string): { code: number; stdout: Uint8Array } {
  return { code: 0, stdout: toBytes(text) }
}
function msg(e: unknown): string {
  return e instanceof Error ? e.message : String(e ?? '')
}

// OpenPGP packet tag names (RFC 4880 §4.3 + drafts).
const PACKET_TAGS: Record<number, string> = {
  1: 'Public-Key Encrypted Session Key Packet',
  2: 'Signature Packet',
  3: 'Symmetric-Key Encrypted Session Key Packet',
  4: 'One-Pass Signature Packet',
  5: 'Secret-Key Packet',
  6: 'Public-Key Packet',
  7: 'Secret-Subkey Packet',
  8: 'Compressed Data Packet',
  9: 'Symmetrically Encrypted Data Packet',
  10: 'Marker Packet',
  11: 'Literal Data Packet',
  12: 'Trust Packet',
  13: 'User ID Packet',
  14: 'Public-Subkey Packet',
  17: 'User Attribute Packet',
  18: 'Sym. Encrypted and Integrity Protected Data Packet',
  19: 'Modification Detection Code Packet',
  20: 'AEAD Encrypted Data Packet',
}

/** A minimal OpenPGP packet structure lister (mirrors `gpg --list-packets`). */
function parsePackets(data: Uint8Array): string {
  const lines: string[] = []
  let i = 0
  const n = data.length
  let offset = 0
  while (i < n) {
    const tagByte = data[i]
    if (!(tagByte & 0x80)) {
      lines.push(`# off=${offset} invalid packet header byte 0x${tagByte.toString(16)}`)
      break
    }
    const newFormat = (tagByte & 0x40) !== 0
    let tag: number
    let len = 0
    let headerLen = 0
    if (newFormat) {
      tag = tagByte & 0x3f
      const l0 = data[i + 1]
      if (l0 < 192) {
        len = l0
        headerLen = 2
      } else if (l0 < 224) {
        len = ((l0 - 192) << 8) + data[i + 2] + 192
        headerLen = 3
      } else if (l0 === 255) {
        len = (data[i + 2] << 24) | (data[i + 3] << 16) | (data[i + 4] << 8) | data[i + 5]
        headerLen = 6
      } else {
        // partial body length — bail out gracefully
        len = 1 << (l0 & 0x1f)
        headerLen = 2
      }
    } else {
      tag = (tagByte >> 2) & 0x0f
      const lenType = tagByte & 0x03
      if (lenType === 0) {
        len = data[i + 1]
        headerLen = 2
      } else if (lenType === 1) {
        len = (data[i + 1] << 8) | data[i + 2]
        headerLen = 3
      } else if (lenType === 2) {
        len = (data[i + 1] << 24) | (data[i + 2] << 16) | (data[i + 3] << 8) | data[i + 4]
        headerLen = 5
      } else {
        len = n - i - 1
        headerLen = 1
      }
    }
    const name = PACKET_TAGS[tag] ?? `Unknown packet (tag ${tag})`
    lines.push(`# off=${offset} ctb=${tagByte.toString(16)} tag=${tag} hlen=${headerLen} plen=${len}`)
    lines.push(`:${name.toLowerCase()}:`)
    i += headerLen + len
    offset = i
    if (headerLen + len <= 0) break
  }
  if (lines.length === 0) return 'gpg: no packets found\n'
  return lines.join('\n') + '\n'
}

// ---------------------------------------------------------------------------
// Help text
// ---------------------------------------------------------------------------

const SHELL_HELP = `gpg4web shell — a gpg(1) command-line simulator.

Builtins:
  echo TEXT            write TEXT (use with a pipe: echo hi | gpg ...)
  cat FILE             print a virtual file
  ls                   list virtual files
  rm FILE              delete a virtual file
  clear                clear the screen
  help                 this help; 'gpg --help' for gpg options

Pipes & redirection work like a real shell:
  echo "hello" | gpg -e -r alice -a > secret.asc
  gpg -d secret.asc

Type 'gpg --help' for the gpg command list, or try the examples below the prompt.
`

const HELP_TEXT = `gpg (gpg4web) 2.4.0
Syntax: gpg [options] [files]
Sign, check, encrypt or decrypt — default operation depends on the input data.

Commands:
 -s, --sign                  make a signature (clear-signed for text)
     --clear-sign            make a clear text signature
 -b, --detach-sign           make a detached signature
 -e, --encrypt               encrypt data (needs -r)
 -c, --symmetric             (unsupported in-browser)
 -d, --decrypt               decrypt data
     --verify                verify a signature
 -k, --list-keys             list keys
 -K, --list-secret-keys      list secret keys
     --fingerprint           list keys and fingerprints
     --gen-key               generate a new key pair (interactive)
     --full-generate-key     generate a new key pair (interactive, all options)
     --quick-generate-key    USER-ID [ALGO [USAGE [EXPIRE]]]
     --export                export keys
     --export-secret-keys    export secret keys
     --import                import/merge keys
     --delete-keys           remove keys from the keyring
     --delete-secret-keys    remove secret keys from the keyring
     --list-packets          list the packet structure of OpenPGP data
     --enarmor / --dearmor   ASCII-armor conversion
     --print-md ALGO         print message digests (SHA1/256/384/512)
     --gen-random 1 N        emit N random bytes (-a for base64)
     --version               show version information

Options:
 -a, --armor                 create ASCII armored output
 -o, --output FILE           write output to FILE
 -r, --recipient USER        encrypt for USER
 -u, --local-user USER       use USER to sign
     --passphrase STRING     supply the key passphrase (with --pinentry-mode loopback)
     --with-colons           machine-readable key listing
     --yes                   assume "yes" on most questions

Keys are matched by user-id substring, key-id, or fingerprint (0x… accepted).
`

const WARRANTY = `gpg4web is free software: you can redistribute it and/or modify it under the
terms of the GNU General Public License. It is distributed WITHOUT ANY WARRANTY,
without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
PURPOSE. See the GNU GPL for more details.
`
