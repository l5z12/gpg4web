<script setup lang="ts">
import { computed, ref } from 'vue'
import { useVault } from '@/stores/vault'
import { decrypt, encrypt, type DecryptResult } from '@/crypto/core'
import { downloadText } from '@/lib/gnupg'
import { toastError, toastSuccess } from '@/lib/toast'

const vault = useVault()
const tab = ref<'encrypt' | 'decrypt'>('encrypt')

// --- Encrypt state ---
const input = ref('')
const recipients = ref<string[]>([])
const signWith = ref<string>('')
const signPass = ref('')
const output = ref('')

// --- Decrypt state ---
const cipherIn = ref('')
const decryptKey = ref<string>('')
const decryptPass = ref('')
const decryptOut = ref<DecryptResult | null>(null)

const allKeys = computed(() => vault.keys)
const myKeys = computed(() => vault.ownKeys)

function toggleRecipient(fpr: string) {
  const i = recipients.value.indexOf(fpr)
  if (i >= 0) recipients.value.splice(i, 1)
  else recipients.value.push(fpr)
}

function doEncrypt() {
  if (!input.value) {
    toastError('Nothing to encrypt')
    return
  }
  if (!recipients.value.length) {
    toastError('Select at least one recipient')
    return
  }
  try {
    const pubs = recipients.value
      .map((f) => vault.keyByFingerprint(f)?.publicKey)
      .filter((x): x is string => !!x)
    let signer: string | null = null
    if (signWith.value) {
      signer = vault.keyByFingerprint(signWith.value)?.secretKey ?? null
    }
    output.value = encrypt(input.value, pubs, signer, signPass.value || null, true)
    toastSuccess('Encrypted')
  } catch (e) {
    toastError(e instanceof Error ? e.message : String(e))
  }
}

function doDecrypt() {
  if (!cipherIn.value) {
    toastError('Paste a PGP message first')
    return
  }
  const sk = vault.keyByFingerprint(decryptKey.value)?.secretKey
  if (!sk) {
    toastError('Select one of your secret keys')
    return
  }
  try {
    const verifiers = vault.keys.map((k) => k.publicKey)
    decryptOut.value = decrypt(cipherIn.value, sk, decryptPass.value, verifiers)
    toastSuccess('Decrypted')
  } catch (e) {
    toastError(e instanceof Error ? e.message : String(e))
  }
}

async function copyOut() {
  await navigator.clipboard.writeText(output.value)
  toastSuccess('Copied')
}
</script>

<template>
  <div class="view">
    <div class="view-head">
      <h1>Notepad</h1>
      <div class="seg">
        <button :class="{ on: tab === 'encrypt' }" @click="tab = 'encrypt'">Encrypt</button>
        <button :class="{ on: tab === 'decrypt' }" @click="tab = 'decrypt'">Decrypt / Verify</button>
      </div>
    </div>

    <!-- ENCRYPT -->
    <div v-if="tab === 'encrypt'" class="pad-grid">
      <div class="pad-col">
        <label>Message</label>
        <textarea v-model="input" rows="12" placeholder="Type or paste your message…" />

        <label>Recipients</label>
        <div class="recipient-list">
          <p v-if="!allKeys.length" class="muted">No keys yet — import or create one.</p>
          <label v-for="k in allKeys" :key="k.fingerprint" class="recipient">
            <input
              type="checkbox"
              :checked="recipients.includes(k.fingerprint)"
              @change="toggleRecipient(k.fingerprint)"
            />
            <span>{{ k.info.userIds[0] || k.keyId }}</span>
            <span class="mono small muted">{{ k.keyId.slice(-8) }}</span>
          </label>
        </div>

        <label>Sign with (optional)</label>
        <select v-model="signWith">
          <option value="">Don't sign</option>
          <option v-for="k in myKeys" :key="k.fingerprint" :value="k.fingerprint">
            {{ k.info.userIds[0] || k.keyId }}
          </option>
        </select>
        <input
          v-if="signWith"
          v-model="signPass"
          type="password"
          placeholder="Signing key passphrase (if any)"
        />

        <button class="primary block" @click="doEncrypt">🔒 Encrypt</button>
      </div>

      <div class="pad-col">
        <label>Output</label>
        <textarea v-model="output" rows="20" readonly class="mono" placeholder="Encrypted message appears here" />
        <div class="row">
          <button class="ghost" :disabled="!output" @click="copyOut">Copy</button>
          <button class="ghost" :disabled="!output" @click="downloadText(output, 'message.asc')">
            Download .asc
          </button>
        </div>
      </div>
    </div>

    <!-- DECRYPT -->
    <div v-else class="pad-grid">
      <div class="pad-col">
        <label>PGP message</label>
        <textarea v-model="cipherIn" rows="12" class="mono" placeholder="-----BEGIN PGP MESSAGE-----" />

        <label>Decrypt with</label>
        <select v-model="decryptKey">
          <option value="">Select your secret key</option>
          <option v-for="k in myKeys" :key="k.fingerprint" :value="k.fingerprint">
            {{ k.info.userIds[0] || k.keyId }}
          </option>
        </select>
        <input v-model="decryptPass" type="password" placeholder="Key passphrase (if any)" />

        <button class="primary block" @click="doDecrypt">🔓 Decrypt / Verify</button>
      </div>

      <div class="pad-col">
        <label>Result</label>
        <textarea
          :value="decryptOut?.data ?? ''"
          rows="14"
          readonly
          placeholder="Decrypted text appears here"
        />
        <div v-if="decryptOut" class="verify-box">
          <div class="kv"><span>Encrypted</span><span>{{ decryptOut.wasEncrypted ? 'yes' : 'no' }}</span></div>
          <template v-if="decryptOut.signatures.length">
            <h4>Signatures</h4>
            <div v-for="s in decryptOut.signatures" :key="s.keyId" class="sig" :class="s.valid ? 'good' : 'bad'">
              <span>{{ s.valid ? '✓ valid' : '✕ invalid' }}</span>
              <span class="mono small">{{ s.keyId.slice(-16) }}</span>
            </div>
          </template>
          <p v-else class="muted small">No signatures, or signer key not in your keyring.</p>
        </div>
      </div>
    </div>
  </div>
</template>
