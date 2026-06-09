// The terminal shell that hosts the gpg(1) engine.
//
// The gpg program itself — option parsing, command dispatch and all output
// formatting — lives in the Rust/WASM core (see crypto-core/src/gpgcli.rs).
// This module is only the surrounding shell: it tokenizes the input line,
// splits it into pipeline stages on `|`, applies `>`/`>>`/`<` redirection over
// a per-session virtual filesystem, runs a handful of builtins (echo/cat/ls/
// rm/clear/help/pwd), and drives the interactive prompt loop. Every `gpg`/
// `gpg2` invocation is handed to the WASM engine via `gpgRun` with a
// synchronous host for keyring + file access.

import { gpgRun, type GpgHost, type GpgHostKey } from '@/crypto/core'

// ---------------------------------------------------------------------------
// Keyring port — implemented by the host (the Pinia vault store)
// ---------------------------------------------------------------------------

/** A keyring entry, flattened for the engine (matches the WASM host shape). */
export type CliKey = GpgHostKey

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
// The shell
// ---------------------------------------------------------------------------

const MAX_PROMPTS = 64

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

  /** The synchronous host the WASM gpg engine calls into. */
  private host(): GpgHost {
    return {
      listKeys: () => this.keyring.list(),
      getSecretKey: (fpr) => this.keyring.getSecretKey(fpr),
      importArmored: (armored) => this.keyring.importArmored(armored),
      removeKey: (fpr) => this.keyring.removeKey(fpr),
      setTrusted: (fpr, t) => this.keyring.setTrusted(fpr, t),
      addGenerated: (pub, sec) => this.keyring.addGenerated(pub, sec),
      readFile: (name) => this.vfs.get(name) ?? null,
      // Copy: `data` may be a view into WASM memory that is later reused.
      writeFile: (name, data) => this.vfs.set(name, new Uint8Array(data)),
    }
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
        io.write(`gpgsh: ${msg(e)}\n`)
        return 2
      }
      code = result.code

      if (redirOut) {
        this.vfs.set(
          redirOut.name,
          mergeRedirect(this.vfs.get(redirOut.name), result.stdout, redirOut.append),
        )
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
  // Command dispatch (builtins live here; gpg runs in WASM)
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
        return this.gpg(argv, stdin, io)
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

  /**
   * Run a `gpg` invocation in the WASM engine, driving the prompt-replay loop:
   * when the engine asks for input, prompt the user and re-invoke with the
   * answer appended until it completes.
   */
  private async gpg(
    argv: string[],
    stdin: Uint8Array | null,
    io: ShellIO,
  ): Promise<{ code: number; stdout: Uint8Array }> {
    const host = this.host()
    let responses: string[] = []
    for (let guard = 0; guard < MAX_PROMPTS; guard++) {
      const res = gpgRun(host, argv, stdin, responses)
      if (res.pending) {
        const ans = await io.prompt(res.pending.label, { password: res.pending.password })
        responses = [...responses, ans]
        continue
      }
      if (res.stderr) io.write(res.stderr)
      return { code: res.exitCode, stdout: res.stdout }
    }
    io.write('gpg: too many interactive prompts\n')
    return { code: 2, stdout: new Uint8Array() }
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
      if (!f) throw new Error(`cat: ${name}: No such file`)
      chunks.push(f)
    }
    return { code: 0, stdout: concat(chunks) }
  }
}

// ---------------------------------------------------------------------------
// Free helpers
// ---------------------------------------------------------------------------

function ok(): { code: number; stdout: Uint8Array } {
  return { code: 0, stdout: new Uint8Array() }
}
function msg(e: unknown): string {
  return e instanceof Error ? e.message : String(e ?? '')
}

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
