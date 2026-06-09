<script setup lang="ts">
import { computed, nextTick, onMounted, ref, shallowRef } from 'vue'
import { useVault } from '@/stores/vault'
import { GpgShell, type CliKey, type KeyringPort, type ShellIO } from '@/lib/gpgcli'
import { downloadBlob } from '@/lib/gnupg'
import { toastError } from '@/lib/toast'

const vault = useVault()

// --- Terminal scrollback ----------------------------------------------------
type Line = { kind: 'in' | 'out' | 'sys'; text: string }
const lines = ref<Line[]>([])
const scrollEl = ref<HTMLElement | null>(null)

function emit(text: string, kind: Line['kind'] = 'out') {
  // Split on newlines so each terminal row is its own element.
  const parts = text.split('\n')
  // A trailing newline shouldn't add a blank row.
  if (parts.length > 1 && parts[parts.length - 1] === '') parts.pop()
  for (const p of parts) lines.value.push({ kind, text: p })
  void nextTick(() => {
    if (scrollEl.value) scrollEl.value.scrollTop = scrollEl.value.scrollHeight
  })
}

// --- Keyring adapter over the vault store -----------------------------------
function toCliKey(k: ReturnType<typeof vault.keyByFingerprint> & object): CliKey {
  return {
    fingerprint: k.fingerprint,
    keyId: k.keyId,
    userIds: k.info.userIds,
    algorithm: k.info.algorithm,
    curve: k.info.curve ?? null,
    createdAt: k.info.createdAt,
    expiresAt: k.info.expiresAt,
    isSecret: !!k.secretKeyEnc,
    canEncrypt: k.info.canEncrypt,
    canSign: k.info.canSign,
    primaryCanEncrypt: k.info.primaryCanEncrypt,
    primaryCanSign: k.info.primaryCanSign,
    bitStrength: k.info.bitStrength,
    trusted: !!k.trusted,
    publicKey: k.publicKey,
    subkeys: k.info.subkeys.map((s) => ({
      keyId: s.keyId,
      fingerprint: s.fingerprint,
      algorithm: s.algorithm,
      curve: s.curve ?? null,
      bitStrength: s.bitStrength ?? null,
      canEncrypt: s.canEncrypt,
      canSign: s.canSign,
    })),
  }
}

const keyringPort: KeyringPort = {
  list: () => vault.keys.map((k) => toCliKey(k)),
  getSecretKey: (fpr) => vault.getSecretKey(fpr),
  importArmored: (armored) => {
    const stored = vault.importArmored(armored)
    return {
      fingerprint: stored.fingerprint,
      keyId: stored.keyId,
      isSecret: !!stored.secretKeyEnc,
    }
  },
  removeKey: (fpr) => vault.removeKey(fpr),
  setTrusted: (fpr, t) => vault.setTrusted(fpr, t),
  addGenerated: (pub, sec) => toCliKey(vault.addGeneratedKey(pub, sec)),
}

const shell = shallowRef(new GpgShell(keyringPort))

// --- Prompt handling (interactive commands) ---------------------------------
/** Thrown into a running command when the user presses Ctrl-C. */
class ConsoleInterrupt extends Error {}

const promptState = ref<{
  active: boolean
  label: string
  password: boolean
  resolve: ((v: string) => void) | null
  reject: ((e: unknown) => void) | null
}>({ active: false, label: '', password: false, resolve: null, reject: null })

const io: ShellIO = {
  write: (t) => emit(t, 'out'),
  clear: () => (lines.value = []),
  prompt: (label, opts) =>
    // The label is shown live as the prompt prefix (see promptLabel) and then
    // echoed with the typed value on submit, so we don't emit it to scrollback here.
    new Promise<string>((resolve, reject) => {
      promptState.value = { active: true, label, password: !!opts?.password, resolve, reject }
      void nextTick(() => inputEl.value?.focus())
    }),
}

// --- Command input + history ------------------------------------------------
const input = ref('')
const inputEl = ref<HTMLInputElement | null>(null)
const history = ref<string[]>([])
const histIdx = ref<number | null>(null)
const busy = ref(false)

const promptLabel = computed(() => (promptState.value.active ? promptState.value.label : 'gpg> '))

async function submit() {
  // If a command is awaiting interactive input, feed it the line.
  if (promptState.value.active && promptState.value.resolve) {
    const val = input.value
    const masked = promptState.value.password ? '•'.repeat(Math.min(val.length, 8)) : val
    emit(`${promptState.value.label}${masked}`, 'in')
    const resolve = promptState.value.resolve
    promptState.value = { active: false, label: '', password: false, resolve: null, reject: null }
    input.value = ''
    resolve(val)
    return
  }

  const line = input.value
  emit(`gpg> ${line}`, 'in')
  input.value = ''
  if (line.trim()) {
    history.value.push(line)
    histIdx.value = null
  }
  busy.value = true
  try {
    await shell.value.run(line, io)
  } catch (e) {
    // A Ctrl-C interrupt already echoed "^C"; only surface real errors.
    if (!(e instanceof ConsoleInterrupt))
      emit(`error: ${e instanceof Error ? e.message : String(e)}`, 'out')
  } finally {
    busy.value = false
    refreshVfs()
    void nextTick(() => inputEl.value?.focus())
  }
}

// Focus the prompt when the terminal is clicked — but not when the user is
// selecting text (the mouseup that ends a drag-select fires a click too, and
// focusing the input would clear the selection and scroll to the bottom).
function focusInput() {
  const sel = window.getSelection()
  if (sel && !sel.isCollapsed && sel.toString().length > 0) return
  inputEl.value?.focus({ preventScroll: true })
}

// Ctrl-C: copy if there's a selection, otherwise interrupt — cancel an
// awaiting interactive prompt, or abandon the current input line.
function handleInterrupt() {
  if (promptState.value.active && promptState.value.reject) {
    emit(`${promptState.value.label}^C`, 'in')
    const reject = promptState.value.reject
    promptState.value = { active: false, label: '', password: false, resolve: null, reject: null }
    input.value = ''
    reject(new ConsoleInterrupt('cancelled'))
    return
  }
  emit(`gpg> ${input.value}^C`, 'in')
  input.value = ''
  histIdx.value = null
}

function onKey(e: KeyboardEvent) {
  if (e.ctrlKey && (e.key === 'c' || e.key === 'C')) {
    // Don't steal a copy: let the browser handle Ctrl-C when text is selected
    // either in the scrollback or inside the input.
    const el = inputEl.value
    const inputHasSelection = !!el && el.selectionStart !== el.selectionEnd
    const docSel = window.getSelection()
    if (inputHasSelection || (docSel && docSel.toString().length > 0)) return
    e.preventDefault()
    handleInterrupt()
    return
  }
  if (promptState.value.active) return // no history nav mid-prompt
  if (e.key === 'ArrowUp') {
    e.preventDefault()
    if (history.value.length === 0) return
    histIdx.value = histIdx.value === null ? history.value.length - 1 : Math.max(0, histIdx.value - 1)
    input.value = history.value[histIdx.value]
  } else if (e.key === 'ArrowDown') {
    e.preventDefault()
    if (histIdx.value === null) return
    if (histIdx.value >= history.value.length - 1) {
      histIdx.value = null
      input.value = ''
    } else {
      histIdx.value++
      input.value = history.value[histIdx.value]
    }
  } else if (e.key === 'l' && e.ctrlKey) {
    e.preventDefault()
    lines.value = []
  }
}

// --- Virtual filesystem panel ------------------------------------------------
const vfsFiles = ref<string[]>([])
function refreshVfs() {
  vfsFiles.value = shell.value.listFiles()
}

function uploadFiles(e: Event) {
  const files = (e.target as HTMLInputElement).files
  if (!files) return
  for (const f of Array.from(files)) {
    void f.arrayBuffer().then((buf) => {
      shell.value.putFile(f.name, new Uint8Array(buf))
      refreshVfs()
      emit(`# uploaded ${f.name} (${f.size} bytes) into the virtual filesystem`, 'sys')
    })
  }
  ;(e.target as HTMLInputElement).value = ''
}

function downloadVfs(name: string) {
  const data = shell.value.vfs.get(name)
  if (!data) return toastError('File not found')
  downloadBlob(new Blob([data as BlobPart]), name)
}

onMounted(() => {
  emit('gpg4web shell — a gpg(1) command-line simulator.', 'sys')
  emit("All crypto runs locally against your unlocked keyring. Type 'help' or 'gpg --help'.", 'sys')
  emit('', 'sys')
  refreshVfs()
  inputEl.value?.focus()
})
</script>

<template>
  <div class="view cli-view">
    <div class="view-head">
      <h1>Console</h1>
      <div class="toolbar">
        <UButton color="neutral" variant="subtle" icon="i-lucide-eraser" @click="lines = []">
          Clear
        </UButton>
      </div>
    </div>

    <div class="cli-grid">
      <div class="cli-main">
        <div ref="scrollEl" class="terminal" @click="focusInput">
          <div v-for="(l, i) in lines" :key="i" class="term-line" :class="l.kind">
            <span>{{ l.text || ' ' }}</span>
          </div>
          <div class="term-input-row">
            <span class="term-prompt">{{ promptLabel }}</span>
            <input
              ref="inputEl"
              v-model="input"
              :type="promptState.active && promptState.password ? 'password' : 'text'"
              class="term-input"
              spellcheck="false"
              autocomplete="off"
              autocapitalize="off"
              :disabled="busy && !promptState.active"
              @keydown.enter.prevent="submit"
              @keydown="onKey"
            />
          </div>
        </div>
      </div>

      <aside class="cli-side">
        <div class="side-head">
          <span>Virtual filesystem</span>
          <label class="upload-btn">
            <input type="file" multiple class="hidden" @change="uploadFiles" />
            <UIcon name="i-lucide-upload" /> Upload
          </label>
        </div>
        <p v-if="!vfsFiles.length" class="muted small">
          No files yet. Outputs from <code>gpg -e</code>, <code>--export</code>, redirection
          (<code>&gt; file</code>) and uploads appear here.
        </p>
        <ul v-else class="vfs-list">
          <li v-for="f in vfsFiles" :key="f">
            <button class="vfs-name" @click="input = (input ? input + ' ' : '') + f">{{ f }}</button>
            <UButton
              size="xs"
              color="neutral"
              variant="ghost"
              icon="i-lucide-download"
              aria-label="Download"
              @click="downloadVfs(f)"
            />
          </li>
        </ul>
        <p class="hint mt-3">
          Keys are matched by user-id, key-id or fingerprint. Use ↑/↓ for history,
          Ctrl-L to clear.
        </p>
      </aside>
    </div>
  </div>
</template>

<style scoped>
.cli-grid {
  display: grid;
  grid-template-columns: 1fr 280px;
  gap: 18px;
  align-items: start;
}
.cli-main {
  min-width: 0;
}
.terminal {
  background: #0b0f17;
  border: 1px solid var(--ui-border);
  border-radius: 10px;
  padding: 14px 16px;
  height: 60vh;
  min-height: 360px;
  overflow-y: auto;
  font-family: 'SF Mono', 'JetBrains Mono', Menlo, Consolas, monospace;
  font-size: 0.82rem;
  line-height: 1.5;
  color: #d7dce3;
  cursor: text;
}
.term-line {
  white-space: pre-wrap;
  word-break: break-word;
}
.term-line.in {
  color: #7dd3fc;
}
.term-line.sys {
  color: #8a93a3;
}
.term-line.out {
  color: #d7dce3;
}
.term-input-row {
  display: flex;
  align-items: baseline;
  gap: 6px;
}
.term-prompt {
  color: #34d399;
  flex-shrink: 0;
  white-space: pre;
}
.term-input {
  flex: 1;
  min-width: 0;
  background: transparent;
  border: none;
  outline: none;
  color: #eaeef4;
  font: inherit;
  caret-color: #34d399;
}
.cli-side {
  background: var(--ui-bg-elevated);
  border: 1px solid var(--ui-border);
  border-radius: 10px;
  padding: 14px;
}
.side-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  font-size: 0.8rem;
  font-weight: 600;
  margin-bottom: 10px;
}
.upload-btn {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  font-size: 0.74rem;
  font-weight: 500;
  color: var(--ui-text-muted);
  cursor: pointer;
}
.upload-btn:hover {
  color: var(--ui-primary);
}
.vfs-list {
  list-style: none;
  margin: 0;
  padding: 0;
  display: flex;
  flex-direction: column;
  gap: 2px;
}
.vfs-list li {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 6px;
}
.vfs-name {
  flex: 1;
  min-width: 0;
  text-align: left;
  background: none;
  border: none;
  padding: 4px 0;
  color: var(--ui-text);
  font-family: 'SF Mono', monospace;
  font-size: 0.78rem;
  cursor: pointer;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.vfs-name:hover {
  color: var(--ui-primary);
}
.hidden {
  display: none;
}

@media (max-width: 820px) {
  .cli-grid {
    grid-template-columns: 1fr;
  }
  .terminal {
    height: 50vh;
  }
}
</style>
