// Tests for the gpg(1) CLI simulator.
//
// Pure parsing/plumbing tests always run. The crypto-backed gpg command flows
// (keygen, encrypt/decrypt, sign/verify, import/export) need the WASM core: we
// load the Node-target build and substitute it for '@/crypto/core' via
// `mock.module`, so the real GpgShell code runs against real OpenPGP crypto.
// Build it first (CI does this automatically):
//
//   wasm-pack build crypto-core --target nodejs --release --out-dir /tmp/wasm-node
//   cd web && GPG4WEB_WASM=/tmp/wasm-node/gpg4web_core.js bun test src/lib/gpgcli.test.ts
//
// Without the WASM core the crypto tests are skipped (the pure tests still run).

import { describe, it, expect, mock } from 'bun:test'
import { existsSync } from 'node:fs'
import type { KeyringPort, CliKey, ShellIO } from '@/lib/gpgcli'

const WASM = process.env.GPG4WEB_WASM ?? '/tmp/wasm-node/gpg4web_core.js'
const haveWasm = existsSync(WASM)

// Substitute the WASM-backed crypto module before importing the shell.
if (haveWasm) {
  const w: any = await import(WASM)
  mock.module('@/crypto/core', () => ({
    generateKey: (o: unknown) => w.generate_key(o),
    inspectKey: (a: string) => w.inspect_key(a),
    extractPublicKey: (a: string) => w.extract_public_key(a),
    encrypt: (t: string, r: string[], ss?: string | null, sp?: string | null, armor?: boolean) =>
      w.encrypt(t, r, ss ?? undefined, sp ?? undefined, armor),
    decrypt: (c: string, s: string, p: string, v?: string[]) => w.decrypt(c, s, p, v ?? []),
    encryptFile: (d: Uint8Array, r: string[], ss?: string | null, sp?: string | null, armor?: boolean) =>
      w.encrypt_file(d, r, ss ?? undefined, sp ?? undefined, armor),
    decryptFile: (d: Uint8Array, s: string, p: string) => w.decrypt_file(d, s, p),
    signCleartext: (t: string, s: string, p: string) => w.sign_cleartext(t, s, p),
    verifyCleartext: (a: string, pub: string) => w.verify_cleartext(a, pub),
    signDetached: (t: string, s: string, p: string) => w.sign_detached(t, s, p),
    verifyDetached: (t: string, sig: string, pub: string) => w.verify_detached(t, sig, pub),
    signFileDetached: (d: Uint8Array, s: string, p: string) => w.sign_file_detached(d, s, p),
    verifyFileDetached: (d: Uint8Array, sig: string, pub: string) => w.verify_file_detached(d, sig, pub),
    coreVersion: () => w.version(),
  }))
} else {
  // Minimal stub so the module imports; crypto tests are skipped.
  const die = () => {
    throw new Error('WASM core not built')
  }
  mock.module('@/crypto/core', () => ({
    generateKey: die,
    inspectKey: die,
    extractPublicKey: () => '',
    encrypt: () => '',
    decrypt: () => ({}),
    encryptFile: () => new Uint8Array(),
    decryptFile: () => new Uint8Array(),
    signCleartext: () => '',
    verifyCleartext: () => ({ text: '', valid: false }),
    signDetached: () => '',
    verifyDetached: () => false,
    signFileDetached: () => '',
    verifyFileDetached: () => false,
    coreVersion: () => 'stub',
  }))
}

// Import the shell (and crypto helpers) only after the mock is registered.
const { GpgShell, tokenize, parseArgs } = await import('@/lib/gpgcli')
const core: any = await import('@/crypto/core')

const cit = haveWasm ? it : it.skip
if (!haveWasm) {
  // eslint-disable-next-line no-console
  console.warn(`\n[gpgcli.test] WASM core not found at ${WASM} — crypto tests skipped.\n`)
}

// ---------------------------------------------------------------------------
// A stateful in-memory keyring backed by the real inspect/extract helpers.
// ---------------------------------------------------------------------------

class TestKeyring implements KeyringPort {
  private items: { publicKey: string; secretKey?: string; info: any; trusted: boolean }[] = []

  list(): CliKey[] {
    return this.items.map((it) => ({
      fingerprint: it.info.fingerprint,
      keyId: it.info.keyId,
      userIds: it.info.userIds,
      algorithm: it.info.algorithm,
      createdAt: it.info.createdAt,
      expiresAt: it.info.expiresAt,
      isSecret: !!it.secretKey,
      canEncrypt: it.info.canEncrypt,
      canSign: it.info.canSign,
      bitStrength: it.info.bitStrength,
      trusted: it.trusted,
      publicKey: it.publicKey,
      subkeys: it.info.subkeys,
    }))
  }
  getSecretKey(fpr: string) {
    return this.items.find((i) => i.info.fingerprint === fpr)?.secretKey ?? null
  }
  importArmored(armored: string) {
    const info = core.inspectKey(armored)
    const publicKey = info.isSecret ? core.extractPublicKey(armored) : armored
    const existing = this.items.find((i) => i.info.fingerprint === info.fingerprint)
    if (existing) {
      if (info.isSecret) existing.secretKey = armored
      existing.publicKey = publicKey
      existing.info = info
    } else {
      this.items.push({ publicKey, secretKey: info.isSecret ? armored : undefined, info, trusted: false })
    }
    return { fingerprint: info.fingerprint, keyId: info.keyId, isSecret: info.isSecret }
  }
  removeKey(fpr: string) {
    this.items = this.items.filter((i) => i.info.fingerprint !== fpr)
  }
  setTrusted(fpr: string, t: boolean) {
    const k = this.items.find((i) => i.info.fingerprint === fpr)
    if (k) k.trusted = t
  }
  addGenerated(pub: string, sec: string): CliKey {
    const info = core.inspectKey(pub)
    this.items.push({ publicKey: pub, secretKey: sec, info, trusted: true })
    return this.list().find((k) => k.fingerprint === info.fingerprint)!
  }
}

function mkShell() {
  const ring = new TestKeyring()
  const sh = new GpgShell(ring)
  let buf = ''
  const answers: string[] = []
  const io: ShellIO = {
    write: (t) => {
      buf += t
    },
    clear: () => {
      buf = ''
    },
    prompt: async () => answers.shift() ?? '',
  }
  return {
    ring,
    sh,
    setAnswers: (...a: string[]) => {
      answers.length = 0
      answers.push(...a)
    },
    run: async (line: string) => {
      buf = ''
      await sh.run(line, io)
      return buf
    },
  }
}

// ---------------------------------------------------------------------------
// Pure: tokenizer
// ---------------------------------------------------------------------------

describe('tokenize', () => {
  it('splits pipes and redirections', () => {
    expect(tokenize('echo "a b" | gpg -e -r alice -a > out.asc')).toEqual([
      'echo', 'a b', '|', 'gpg', '-e', '-r', 'alice', '-a', '>', 'out.asc',
    ])
  })
  it('handles >> append and single quotes', () => {
    expect(tokenize('cat x >> y')).toEqual(['cat', 'x', '>>', 'y'])
    expect(tokenize("gpg -r 'Bob Smith'")).toEqual(['gpg', '-r', 'Bob Smith'])
  })
  it('handles backslash escapes inside double quotes', () => {
    expect(tokenize('echo "a\\"b"')).toEqual(['echo', 'a"b'])
  })
})

// ---------------------------------------------------------------------------
// Pure: argument parser
// ---------------------------------------------------------------------------

describe('parseArgs', () => {
  it('parses bundled short options', () => {
    const p = parseArgs(['-sea', '-r', 'alice', '-u', 'bob', 'file.txt'])
    expect(p.commands.has('sign')).toBe(true)
    expect(p.commands.has('encrypt')).toBe(true)
    expect(p.flags.has('armor')).toBe(true)
    expect(p.multi.get('recipient')).toEqual(['alice'])
    expect(p.multi.get('local-user')).toEqual(['bob'])
    expect(p.operands).toEqual(['file.txt'])
  })
  it('parses --opt=value and operands', () => {
    const p = parseArgs(['--output=foo', '--armor', '--export', 'alice'])
    expect(p.opts.get('output')).toBe('foo')
    expect(p.commands.has('export')).toBe(true)
    expect(p.operands).toEqual(['alice'])
  })
  it('accepts unambiguous abbreviations', () => {
    expect(parseArgs(['--fingerp']).commands.has('fingerprint')).toBe(true)
  })
  it('accepts an attached short-option argument', () => {
    expect(parseArgs(['-rAlice']).multi.get('recipient')).toEqual(['Alice'])
  })
  it('treats -- as an operand terminator', () => {
    const p = parseArgs(['--', '--encrypt'])
    expect(p.operands).toEqual(['--encrypt'])
    expect(p.commands.has('encrypt')).toBe(false)
  })
  it('repeats accumulating options', () => {
    expect(parseArgs(['-r', 'a', '-r', 'b']).multi.get('recipient')).toEqual(['a', 'b'])
  })
  it('rejects unknown options', () => {
    expect(() => parseArgs(['--bogusoption'])).toThrow(/invalid option/)
  })
  it('rejects ambiguous abbreviations', () => {
    expect(() => parseArgs(['--ex'])).toThrow(/ambiguous/)
  })
  it('requires an argument for option that takes one', () => {
    expect(() => parseArgs(['-r'])).toThrow(/requires an argument/)
  })
})

// ---------------------------------------------------------------------------
// Shell plumbing + non-crypto gpg commands (no WASM needed)
// ---------------------------------------------------------------------------

describe('shell builtins and plumbing', () => {
  it('writes, reads, lists and removes virtual files', async () => {
    const t = mkShell()
    await t.run('echo "hello world" > greeting.txt')
    expect(t.sh.listFiles()).toContain('greeting.txt')
    expect(await t.run('cat greeting.txt')).toContain('hello world')
    expect(await t.run('ls')).toContain('greeting.txt')
    await t.run('rm greeting.txt')
    expect(t.sh.listFiles()).not.toContain('greeting.txt')
  })
  it('pipes stdout into the next stage', async () => {
    const t = mkShell()
    expect(await t.run('echo piped | cat')).toContain('piped')
  })
  it('reports unknown commands', async () => {
    expect(await mkShell().run('frobnicate')).toContain('command not found')
  })
})

describe('gpg informational and conversion commands', () => {
  it('--version reports the engine and algorithms', async () => {
    const o = await mkShell().run('gpg --version')
    expect(o).toContain('gpg (gpg4web)')
    expect(o).toContain('Pubkey:')
  })
  it('--help lists commands', async () => {
    expect(await mkShell().run('gpg --help')).toContain('--encrypt')
  })
  it('--list-config emits cfg records', async () => {
    expect(await mkShell().run('gpg --list-config')).toContain('cfg:version:')
  })
  it('enarmor → dearmor round-trips bytes', async () => {
    const t = mkShell()
    await t.run('echo abc > raw.bin') // "abc\n"
    await t.run('gpg --enarmor raw.bin')
    expect(t.sh.listFiles()).toContain('raw.bin.asc')
    const armored = new TextDecoder().decode(t.sh.vfs.get('raw.bin.asc')!)
    expect(armored).toContain('-----BEGIN PGP ARMORED FILE-----')
    await t.run('gpg --dearmor raw.bin.asc')
    expect(new TextDecoder().decode(t.sh.vfs.get('raw.bin.asc.bin')!)).toBe('abc\n')
  })
  it('--print-md computes known digests (file and stdin)', async () => {
    const t = mkShell()
    await t.run('echo abc > f.txt') // sha256("abc\n")
    const o = await t.run('gpg --print-md SHA256 f.txt')
    expect(o.toLowerCase().replace(/\s/g, '')).toContain(
      'edeaaff3f1774ad2888673770c6d64097e391bc362d7d6fb34982ddf0efd18cb',
    )
    const o2 = await t.run('echo -n abc | gpg --print-md SHA1') // sha1("abc")
    expect(o2.toLowerCase().replace(/\s/g, '')).toContain('a9993e364706816aba3e25717850c26c9cd0d89d')
  })
  it('--gen-random --armor emits base64', async () => {
    const o = (await mkShell().run('gpg --gen-random 1 8 --armor')).trim()
    expect(o.length).toBeGreaterThan(0)
    expect(/^[A-Za-z0-9+/=\s]+$/.test(o)).toBe(true)
  })
  it('reports browser-impossible commands honestly', async () => {
    expect(await mkShell().run('gpg --recv-keys 0xDEADBEEF')).toContain('keyserver')
    expect((await mkShell().run('gpg -c x')).toLowerCase()).toContain('symmetric')
    expect(await mkShell().run('gpg --edit-key alice')).toContain('Certificates view')
  })
})

// ---------------------------------------------------------------------------
// Crypto-backed gpg command flows (real OpenPGP via the WASM core)
// ---------------------------------------------------------------------------

describe('gpg crypto commands', () => {
  cit('generates a key and lists it', async () => {
    const t = mkShell()
    const o = await t.run('gpg --quick-generate-key "Alice <alice@example.com>" ed25519')
    expect(o).toContain('public and secret key created')
    expect(t.ring.list().length).toBe(1)

    const list = await t.run('gpg --list-keys')
    expect(list).toContain('Alice <alice@example.com>')
    expect(list).toMatch(/pub\s+ed25519/)
    expect(list).toContain(t.ring.list()[0].fingerprint)

    const sec = await t.run('gpg -K')
    expect(sec).toMatch(/sec\s+ed25519/)
    expect(sec).toContain('ssb')

    const colons = await t.run('gpg --list-keys --with-colons')
    expect(colons).toContain('pub:')
    expect(colons).toMatch(/fpr:::::::::[0-9A-F]{40}/)
  })

  cit('encrypts and decrypts via pipe and file', async () => {
    const t = mkShell()
    await t.run('gpg --quick-generate-key "Alice <alice@example.com>" ed25519')
    await t.run('echo "top secret" > msg.txt')
    await t.run('gpg -e -r alice -a msg.txt')
    expect(t.sh.listFiles()).toContain('msg.txt.asc')
    expect(new TextDecoder().decode(t.sh.vfs.get('msg.txt.asc')!)).toContain('BEGIN PGP MESSAGE')
    expect(await t.run('gpg -d msg.txt.asc')).toContain('top secret')

    // list-packets understands the produced ciphertext
    const lp = await t.run('gpg --list-packets msg.txt.asc')
    expect(lp.toLowerCase()).toContain('session key')
  })

  cit('matches recipients by key-id and fingerprint', async () => {
    const t = mkShell()
    await t.run('gpg --quick-generate-key "Alice <alice@example.com>" ed25519')
    const fpr = t.ring.list()[0].fingerprint
    await t.run('echo hi | gpg -e -r 0x' + fpr.slice(-16) + ' -a > byid.asc')
    expect(await t.run('gpg -d byid.asc')).toContain('hi')
  })

  cit('signs and encrypts, and reports the signature on decrypt', async () => {
    const t = mkShell()
    await t.run('gpg --quick-generate-key "Alice <alice@example.com>" ed25519')
    await t.run('echo "signed+sealed" | gpg -e -s -r alice -a > se.asc')
    const d = await t.run('gpg -d se.asc')
    expect(d).toContain('signed+sealed')
    expect(d).toContain('Good signature')
  })

  cit('clear-signs and verifies', async () => {
    const t = mkShell()
    await t.run('gpg --quick-generate-key "Alice <alice@example.com>" ed25519')
    await t.run('echo "clear text" | gpg --clear-sign > cs.asc')
    expect(new TextDecoder().decode(t.sh.vfs.get('cs.asc')!)).toContain('BEGIN PGP SIGNED MESSAGE')
    expect(await t.run('gpg --verify cs.asc')).toContain('Good signature')
  })

  cit('makes and verifies a detached signature', async () => {
    const t = mkShell()
    await t.run('gpg --quick-generate-key "Alice <alice@example.com>" ed25519')
    await t.run('echo "document" > doc.txt')
    await t.run('gpg -a -b doc.txt')
    expect(t.sh.listFiles()).toContain('doc.txt.asc')
    expect(await t.run('gpg --verify doc.txt.asc doc.txt')).toContain('Good signature')
    // tamper → bad
    await t.run('echo "tampered" > doc.txt')
    expect(await t.run('gpg --verify doc.txt.asc doc.txt')).toContain('BAD')
  })

  cit('exports, deletes and re-imports a key', async () => {
    const t = mkShell()
    await t.run('gpg --quick-generate-key "Alice <alice@example.com>" ed25519')
    await t.run('gpg --armor --export alice > alice.pub')
    expect(new TextDecoder().decode(t.sh.vfs.get('alice.pub')!)).toContain('BEGIN PGP PUBLIC KEY BLOCK')
    await t.run('gpg --delete-keys --yes alice')
    expect(t.ring.list().length).toBe(0)
    const imp = await t.run('gpg --import alice.pub')
    expect(imp).toContain('imported')
    expect(t.ring.list().length).toBe(1)
    expect(t.ring.list()[0].isSecret).toBe(false)
  })

  cit('exports binary by default and armored with --armor', async () => {
    const t = mkShell()
    await t.run('gpg --quick-generate-key "Alice <alice@example.com>" ed25519')
    await t.run('gpg --export alice > bin.gpg')
    const bin = t.sh.vfs.get('bin.gpg')!
    expect(bin[0]).not.toBe(0x2d) // not '-', i.e. not armored
    await t.run('gpg --armor --export alice > armored.asc')
    expect(new TextDecoder().decode(t.sh.vfs.get('armored.asc')!).startsWith('-----BEGIN')).toBe(true)
  })

  cit('prompts for a passphrase on a protected key', async () => {
    const t = mkShell()
    await t.run(
      'gpg --quick-generate-key "Carol <carol@example.com>" ed25519 default 0 --passphrase secretpw --pinentry-mode loopback',
    )
    await t.run('echo "hush hush" | gpg -e -r carol -a > c.asc')
    // First the empty passphrase is tried and fails, then our answer is used.
    t.setAnswers('secretpw')
    expect(await t.run('gpg -d c.asc')).toContain('hush hush')
  })

  cit('does an interactive --gen-key dialog', async () => {
    const t = mkShell()
    // answers: algo, expiry, real name, email, passphrase
    t.setAnswers('ed25519', '0', 'Dave', 'dave@example.com', '')
    const o = await t.run('gpg --gen-key')
    expect(o).toContain('public and secret key created')
    expect(t.ring.list()[0].userIds[0]).toBe('Dave <dave@example.com>')
  })

  cit('generates an rsa2048 key (regression: expireDays serialization)', async () => {
    const t = mkShell()
    const o = await t.run('gpg --quick-generate-key "Eve <eve@example.com>" rsa2048')
    expect(o).toContain('public and secret key created')
    expect(t.ring.list()[0].canEncrypt).toBe(true)
  })
})
