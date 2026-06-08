<script setup lang="ts">
import { computed, ref } from 'vue'
import type { TabsItem } from '@nuxt/ui'
import { useVault } from '@/stores/vault'
import { decrypt, encrypt, type DecryptResult } from '@/crypto/core'
import { downloadText } from '@/lib/gnupg'
import { toastError, toastSuccess } from '@/lib/toast'

const vault = useVault()
const tab = ref('encrypt')

const tabs: TabsItem[] = [
  { label: 'Encrypt', value: 'encrypt', slot: 'encrypt', icon: 'i-lucide-lock' },
  { label: 'Decrypt / Verify', value: 'decrypt', slot: 'decrypt', icon: 'i-lucide-lock-open' },
]

const input = ref('')
const recipients = ref<string[]>([])
const signWith = ref('')
const signPass = ref('')
const output = ref('')

const cipherIn = ref('')
const decryptKey = ref('')
const decryptPass = ref('')
const decryptOut = ref<DecryptResult | null>(null)

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

function doEncrypt() {
  if (!input.value) return toastError('Nothing to encrypt')
  if (!recipients.value.length) return toastError('Select at least one recipient')
  try {
    const pubs = recipients.value
      .map((f) => vault.keyByFingerprint(f)?.publicKey)
      .filter((x): x is string => !!x)
    const signer = signWith.value ? vault.keyByFingerprint(signWith.value)?.secretKey ?? null : null
    output.value = encrypt(input.value, pubs, signer, signPass.value || null, true)
    toastSuccess('Encrypted')
  } catch (e) {
    toastError(e instanceof Error ? e.message : String(e))
  }
}

function doDecrypt() {
  if (!cipherIn.value) return toastError('Paste a PGP message first')
  const sk = decryptKey.value ? vault.keyByFingerprint(decryptKey.value)?.secretKey : undefined
  if (!sk) return toastError('Select one of your secret keys')
  try {
    decryptOut.value = decrypt(cipherIn.value, sk, decryptPass.value, vault.keys.map((k) => k.publicKey))
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
    <div class="view-head"><h1>Notepad</h1></div>

    <UTabs v-model="tab" :items="tabs" class="w-full">
      <template #encrypt>
        <div class="pad-grid">
          <div class="pad-col">
            <label>Message</label>
            <UTextarea v-model="input" :rows="11" class="w-full" placeholder="Type or paste your message…" />

            <label>Recipients</label>
            <USelect
              v-model="recipients"
              multiple
              :items="allKeyItems"
              placeholder="Choose one or more recipients"
              class="w-full"
            />

            <label>Sign with (optional)</label>
            <USelect v-model="signWith" :items="signItems" class="w-full" />
            <UInput
              v-if="signWith"
              v-model="signPass"
              type="password"
              placeholder="Signing key passphrase (if any)"
              class="w-full mt-2"
            />

            <UButton block icon="i-lucide-lock" class="mt-4" @click="doEncrypt">Encrypt</UButton>
          </div>

          <div class="pad-col">
            <label>Output</label>
            <UTextarea :model-value="output" :rows="18" readonly class="w-full mono" placeholder="Encrypted message appears here" />
            <div class="row mt-2">
              <UButton color="neutral" variant="subtle" :disabled="!output" icon="i-lucide-copy" @click="copyOut">Copy</UButton>
              <UButton color="neutral" variant="subtle" :disabled="!output" icon="i-lucide-download" @click="downloadText(output, 'message.asc')">Download .asc</UButton>
            </div>
          </div>
        </div>
      </template>

      <template #decrypt>
        <div class="pad-grid">
          <div class="pad-col">
            <label>PGP message</label>
            <UTextarea v-model="cipherIn" :rows="11" class="w-full mono" placeholder="-----BEGIN PGP MESSAGE-----" />

            <label>Decrypt with</label>
            <USelect v-model="decryptKey" :items="myKeyItems" placeholder="Select your secret key" class="w-full" />
            <UInput v-model="decryptPass" type="password" placeholder="Key passphrase (if any)" class="w-full mt-2" />

            <UButton block icon="i-lucide-lock-open" class="mt-4" @click="doDecrypt">Decrypt / Verify</UButton>
          </div>

          <div class="pad-col">
            <label>Result</label>
            <UTextarea :model-value="decryptOut?.data ?? ''" :rows="13" readonly class="w-full" placeholder="Decrypted text appears here" />
            <UCard v-if="decryptOut" class="mt-3">
              <div class="kv"><span>Encrypted</span><span>{{ decryptOut.wasEncrypted ? 'yes' : 'no' }}</span></div>
              <template v-if="decryptOut.signatures.length">
                <div class="sig-title">Signatures</div>
                <div v-for="s in decryptOut.signatures" :key="s.keyId" class="sig-row">
                  <UBadge :color="s.valid ? 'success' : 'error'" variant="subtle">
                    {{ s.valid ? '✓ valid' : '✕ invalid' }}
                  </UBadge>
                  <span class="mono small">{{ s.keyId.slice(-16) }}</span>
                </div>
              </template>
              <p v-else class="muted small">No signatures, or signer key not in your keyring.</p>
            </UCard>
          </div>
        </div>
      </template>
    </UTabs>
  </div>
</template>
