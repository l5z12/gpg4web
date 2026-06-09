<script setup lang="ts">
import { computed, ref } from 'vue'
import type { TabsItem } from '@nuxt/ui'
import { useVault } from '@/stores/vault'
import { decrypt, encrypt, signCleartext, verifyCleartext } from '@/crypto/core'
import { downloadText } from '@/lib/gnupg'
import { toastError, toastSuccess } from '@/lib/toast'

const vault = useVault()
const tab = ref('signencrypt')

const tabs: TabsItem[] = [
  { label: 'Sign / Encrypt', value: 'signencrypt', slot: 'signencrypt', icon: 'i-lucide-lock' },
  { label: 'Decrypt / Verify', value: 'decryptverify', slot: 'decryptverify', icon: 'i-lucide-lock-open' },
]

// --- Sign / Encrypt ---
const input = ref('')
const recipients = ref<string[]>([])
const signWith = ref('')
const signPass = ref('')
const output = ref('')

// --- Decrypt / Verify ---
const cipherIn = ref('')
const decryptKey = ref('')
const decryptPass = ref('')

interface NotepadResult {
  text: string
  encrypted: boolean
  signatures: { label: string; valid: boolean }[]
}
const result = ref<NotepadResult | null>(null)

const allKeyItems = computed(() =>
  vault.keys.map((k) => ({ label: `${k.info.userIds[0] || k.keyId} (${k.keyId.slice(-8)})`, value: k.fingerprint })),
)
const signItems = computed(() => [
  { label: "Don't sign", value: '' },
  ...vault.ownKeys.map((k) => ({ label: k.info.userIds[0] || k.keyId, value: k.fingerprint })),
])
const myKeyItems = computed(() =>
  vault.ownKeys.map((k) => ({ label: k.info.userIds[0] || k.keyId, value: k.fingerprint })),
)

function doSignEncrypt() {
  if (!input.value) return toastError('Nothing to sign or encrypt')
  const hasRecipients = recipients.value.length > 0
  const signer = signWith.value ? vault.getSecretKey(signWith.value) : null
  if (signWith.value && !signer) return toastError('Could not unlock the signing key')

  try {
    if (hasRecipients) {
      const pubs = recipients.value
        .map((f) => vault.keyByFingerprint(f)?.publicKey)
        .filter((x): x is string => !!x)
      output.value = encrypt(input.value, pubs, signer, signPass.value || null, true)
      toastSuccess(signer ? 'Signed and encrypted' : 'Encrypted')
    } else if (signer) {
      // Sign-only with no recipients → clearsigned message
      // (-----BEGIN PGP SIGNED MESSAGE-----), matching Kleopatra's Notepad.
      output.value = signCleartext(input.value, signer, signPass.value)
      toastSuccess('Signed')
    } else {
      return toastError('Choose recipients to encrypt, and/or a key to sign with')
    }
  } catch (e) {
    toastError(e instanceof Error ? e.message : String(e))
  }
}

function doDecryptVerify() {
  const inp = cipherIn.value.trim()
  if (!inp) return toastError('Paste a PGP message first')

  try {
    if (inp.includes('BEGIN PGP SIGNED MESSAGE')) {
      // Cleartext-signed message: find a key in the ring that validates it.
      if (!vault.keys.length) return toastError("Import the signer's public key to verify")
      let text = ''
      let valid = false
      let label = 'unknown signer'
      for (const key of vault.keys) {
        const r = verifyCleartext(inp, key.publicKey)
        text = r.text
        if (r.valid) {
          valid = true
          label = key.info.userIds[0] || key.keyId
          break
        }
      }
      result.value = { text, encrypted: false, signatures: [{ label, valid }] }
      toastSuccess(valid ? 'Valid signature' : 'Signature could not be verified')
    } else {
      const sk = decryptKey.value ? vault.getSecretKey(decryptKey.value) : null
      if (!sk) return toastError('Select one of your secret keys')
      const d = decrypt(inp, sk, decryptPass.value, vault.keys.map((k) => k.publicKey))
      result.value = {
        text: d.data,
        encrypted: d.wasEncrypted,
        signatures: d.signatures.map((s) => ({ label: s.keyId.slice(-16), valid: s.valid })),
      }
      toastSuccess('Decrypted')
    }
  } catch (e) {
    toastError(e instanceof Error ? e.message : String(e))
  }
}

async function copyOut() {
  await navigator.clipboard.writeText(output.value)
  toastSuccess('Copied')
}

const isClearsign = computed(() => cipherIn.value.includes('BEGIN PGP SIGNED MESSAGE'))
</script>

<template>
  <div class="view">
    <div class="view-head"><h1>Notepad</h1></div>

    <UTabs v-model="tab" :items="tabs" class="w-full">
      <template #signencrypt>
        <div class="pad-grid">
          <div class="pad-col">
            <label>Message</label>
            <UTextarea v-model="input" :rows="11" class="w-full" placeholder="Type or paste your message…" />

            <label>Encrypt for (leave empty to sign only)</label>
            <USelect
              v-model="recipients"
              multiple
              :items="allKeyItems"
              placeholder="No recipients — sign only"
              class="w-full"
            />

            <label>Sign as</label>
            <USelect v-model="signWith" :items="signItems" class="w-full" />
            <UInput
              v-if="signWith"
              v-model="signPass"
              type="password"
              placeholder="Signing key passphrase (if any)"
              class="w-full mt-2"
            />

            <UButton block icon="i-lucide-pen-line" class="mt-4" @click="doSignEncrypt">
              Sign / Encrypt Notepad
            </UButton>
            <p class="hint">
              With no recipients this produces a clear-signed message
              (<code>BEGIN PGP SIGNED MESSAGE</code>). With recipients it encrypts
              (and signs inline if a key is selected).
            </p>
          </div>

          <div class="pad-col">
            <label>Output</label>
            <UTextarea :model-value="output" :rows="18" readonly class="w-full mono" placeholder="Result appears here" />
            <div class="row mt-2">
              <UButton color="neutral" variant="subtle" :disabled="!output" icon="i-lucide-copy" @click="copyOut">Copy</UButton>
              <UButton color="neutral" variant="subtle" :disabled="!output" icon="i-lucide-download" @click="downloadText(output, 'message.asc')">Download .asc</UButton>
            </div>
          </div>
        </div>
      </template>

      <template #decryptverify>
        <div class="pad-grid">
          <div class="pad-col">
            <label>PGP message or signed message</label>
            <UTextarea v-model="cipherIn" :rows="11" class="w-full mono" placeholder="-----BEGIN PGP MESSAGE----- or -----BEGIN PGP SIGNED MESSAGE-----" />

            <template v-if="!isClearsign">
              <label>Decrypt with</label>
              <USelect v-model="decryptKey" :items="myKeyItems" placeholder="Select your secret key" class="w-full" />
              <UInput v-model="decryptPass" type="password" placeholder="Key passphrase (if any)" class="w-full mt-2" />
            </template>
            <p v-else class="hint">Clear-signed message detected — no secret key needed to verify.</p>

            <UButton block icon="i-lucide-lock-open" class="mt-4" @click="doDecryptVerify">
              Decrypt / Verify Notepad
            </UButton>
          </div>

          <div class="pad-col">
            <label>Result</label>
            <UTextarea :model-value="result?.text ?? ''" :rows="13" readonly class="w-full" placeholder="Decrypted / verified text appears here" />
            <UCard v-if="result" class="mt-3">
              <div class="kv"><span>Encrypted</span><span>{{ result.encrypted ? 'yes' : 'no' }}</span></div>
              <template v-if="result.signatures.length">
                <div class="sig-title">Signatures</div>
                <div v-for="(s, i) in result.signatures" :key="i" class="sig-row">
                  <UBadge :color="s.valid ? 'success' : 'error'" variant="subtle">
                    {{ s.valid ? '✓ valid' : '✕ invalid' }}
                  </UBadge>
                  <span class="small">{{ s.label }}</span>
                </div>
              </template>
              <p v-else class="muted small">No signatures, or the signer's key is not in your keyring.</p>
            </UCard>
          </div>
        </div>
      </template>
    </UTabs>
  </div>
</template>
