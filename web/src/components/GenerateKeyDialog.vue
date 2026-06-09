<script setup lang="ts">
import { reactive, ref } from 'vue'
import { generateKey, type KeyAlgorithm } from '@/crypto/core'
import { useVault } from '@/stores/vault'
import { toastError, toastSuccess } from '@/lib/toast'

const emit = defineEmits<{ close: [] }>()
const vault = useVault()
const busy = ref(false)
const open = ref(true)

function isoDate(d: Date): string {
  return d.toISOString().slice(0, 10)
}
// Kleopatra defaults a new key to expire in two years.
const defaultExpiry = (() => {
  const d = new Date()
  d.setFullYear(d.getFullYear() + 2)
  return isoDate(d)
})()
const minExpiry = isoDate(new Date(Date.now() + 86_400_000))

const form = reactive({
  name: '',
  email: '',
  algorithm: (vault.settings.defaultAlgorithm as KeyAlgorithm) || 'curve25519',
  passphrase: '',
  passphrase2: '',
  expires: true,
  validUntil: defaultExpiry,
})

const algorithms = [
  { label: 'Curve25519 / EdDSA (recommended, GnuPG compatible)', value: 'curve25519' },
  { label: 'Ed25519 + X25519 (modern v6)', value: 'ed25519' },
  { label: 'RSA 3072', value: 'rsa3072' },
  { label: 'RSA 4096', value: 'rsa4096' },
  { label: 'RSA 2048', value: 'rsa2048' },
  { label: 'NIST P-256', value: 'nistp256' },
  { label: 'NIST P-384', value: 'nistp384' },
  { label: 'NIST P-521', value: 'nistp521' },
  { label: '🛡 Post-quantum: ML-DSA-65 + ML-KEM-768', value: 'pqc' },
  { label: '🛡 Post-quantum: ML-DSA-87 + ML-KEM-1024', value: 'mldsa87-mlkem1024' },
  { label: '🛡 Post-quantum: SLH-DSA-128s + ML-KEM-768', value: 'slhdsa128s-mlkem768' },
]

function onOpenChange(v: boolean) {
  if (!v && !busy.value) emit('close')
}

async function create() {
  if (busy.value) return
  if (!form.name.trim()) return toastError('Please enter a name')
  if (form.passphrase !== form.passphrase2) return toastError('Passphrases do not match')
  const userId = form.email.trim()
    ? `${form.name.trim()} <${form.email.trim()}>`
    : form.name.trim()

  // Convert the "valid until" date into the number of days the core expects.
  let expireDays = 0
  if (form.expires && form.validUntil) {
    const until = new Date(`${form.validUntil}T23:59:59`).getTime()
    if (Number.isNaN(until)) return toastError('Invalid expiry date')
    expireDays = Math.ceil((until - Date.now()) / 86_400_000)
    if (expireDays < 1) return toastError('Expiry date must be in the future')
  }

  busy.value = true
  // Defer so the UI can paint before the (possibly slow) generation blocks.
  await new Promise((r) => setTimeout(r, 30))
  try {
    const key = generateKey({
      userId,
      algorithm: form.algorithm,
      passphrase: form.passphrase,
      expireDays,
    })
    vault.addGeneratedKey(key.publicKey, key.secretKey)
    toastSuccess(`Created key ${key.fingerprint.slice(-16)}`)
    emit('close')
  } catch (e) {
    toastError(e instanceof Error ? e.message : String(e))
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <UModal
    :open="open"
    title="New key pair"
    description="Generate an OpenPGP key pair locally in your browser."
    @update:open="onOpenChange"
  >
    <template #body>
      <div class="form-stack">
        <UFormField label="Name">
          <UInput v-model="form.name" placeholder="Alice Example" class="w-full" />
        </UFormField>
        <UFormField label="Email (optional)">
          <UInput v-model="form.email" placeholder="alice@example.com" class="w-full" />
        </UFormField>
        <UFormField label="Algorithm">
          <USelect v-model="form.algorithm" :items="algorithms" class="w-full" />
        </UFormField>
        <UFormField label="Key expires">
          <div class="expiry-row">
            <USwitch v-model="form.expires" />
            <UInput
              v-if="form.expires"
              v-model="form.validUntil"
              type="date"
              :min="minExpiry"
              class="expiry-date"
            />
            <span v-else class="muted small">Key never expires</span>
          </div>
        </UFormField>
        <UFormField label="Passphrase (optional)">
          <UInput
            v-model="form.passphrase"
            type="password"
            placeholder="Protect the secret key"
            class="w-full"
          />
        </UFormField>
        <UFormField label="Confirm passphrase">
          <UInput v-model="form.passphrase2" type="password" class="w-full" />
        </UFormField>
        <p class="hint">
          RSA and SLH-DSA keys can take several seconds to generate; the page may
          briefly freeze while the WASM core works.
        </p>
      </div>
    </template>

    <template #footer>
      <div class="modal-actions">
        <UButton color="neutral" variant="ghost" :disabled="busy" @click="emit('close')">
          Cancel
        </UButton>
        <UButton :loading="busy" icon="i-lucide-key-round" @click="create">Create</UButton>
      </div>
    </template>
  </UModal>
</template>
