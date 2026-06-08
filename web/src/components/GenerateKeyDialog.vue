<script setup lang="ts">
import { reactive, ref } from 'vue'
import AppModal from './AppModal.vue'
import { generateKey, type KeyAlgorithm } from '@/crypto/core'
import { useVault } from '@/stores/vault'
import { toastError, toastSuccess } from '@/lib/toast'

const emit = defineEmits<{ close: []; created: [] }>()
const vault = useVault()
const busy = ref(false)

const form = reactive({
  name: '',
  email: '',
  algorithm: (vault.settings.defaultAlgorithm as KeyAlgorithm) || 'curve25519',
  passphrase: '',
  passphrase2: '',
  expireDays: 0,
})

const algorithms: { value: KeyAlgorithm; label: string; pq?: boolean }[] = [
  { value: 'curve25519', label: 'Curve25519 / EdDSA (recommended, GnuPG compatible)' },
  { value: 'ed25519', label: 'Ed25519 + X25519 (modern v6)' },
  { value: 'rsa3072', label: 'RSA 3072' },
  { value: 'rsa4096', label: 'RSA 4096' },
  { value: 'rsa2048', label: 'RSA 2048' },
  { value: 'nistp256', label: 'NIST P-256' },
  { value: 'nistp384', label: 'NIST P-384' },
  { value: 'nistp521', label: 'NIST P-521' },
  { value: 'pqc', label: '🛡 Post-quantum: ML-DSA-65 + ML-KEM-768', pq: true },
  { value: 'mldsa87-mlkem1024', label: '🛡 Post-quantum: ML-DSA-87 + ML-KEM-1024', pq: true },
  { value: 'slhdsa128s-mlkem768', label: '🛡 Post-quantum: SLH-DSA-128s + ML-KEM-768', pq: true },
]

async function create() {
  if (busy.value) return
  if (!form.name.trim()) {
    toastError('Please enter a name')
    return
  }
  if (form.passphrase !== form.passphrase2) {
    toastError('Passphrases do not match')
    return
  }
  const userId = form.email.trim()
    ? `${form.name.trim()} <${form.email.trim()}>`
    : form.name.trim()

  busy.value = true
  // Defer so the UI can paint the "working" state before the (possibly slow,
  // for RSA / SLH-DSA) generation blocks the main thread.
  await new Promise((r) => setTimeout(r, 30))
  try {
    const key = generateKey({
      userId,
      algorithm: form.algorithm,
      passphrase: form.passphrase,
      expireDays: Number(form.expireDays) || 0,
    })
    vault.addGeneratedKey(key.publicKey, key.secretKey)
    toastSuccess(`Created key ${key.fingerprint.slice(-16)}`)
    emit('created')
    emit('close')
  } catch (e) {
    toastError(e instanceof Error ? e.message : String(e))
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <AppModal title="New key pair" @close="emit('close')">
    <div class="form-grid">
      <label>Name</label>
      <input v-model="form.name" placeholder="Alice Example" />

      <label>Email (optional)</label>
      <input v-model="form.email" type="email" placeholder="alice@example.com" />

      <label>Algorithm</label>
      <select v-model="form.algorithm">
        <option v-for="a in algorithms" :key="a.value" :value="a.value">{{ a.label }}</option>
      </select>

      <label>Expires in (days)</label>
      <input v-model.number="form.expireDays" type="number" min="0" placeholder="0 = never" />

      <label>Passphrase (optional)</label>
      <input v-model="form.passphrase" type="password" autocomplete="new-password" placeholder="Protect the secret key" />

      <label>Confirm passphrase</label>
      <input v-model="form.passphrase2" type="password" autocomplete="new-password" />
    </div>
    <p class="hint">
      RSA and SLH-DSA keys can take several seconds to generate. The page may
      briefly freeze while the WASM core works.
    </p>

    <template #footer>
      <button class="ghost" @click="emit('close')">Cancel</button>
      <button class="primary" :disabled="busy" @click="create">
        {{ busy ? 'Generating…' : 'Create' }}
      </button>
    </template>
  </AppModal>
</template>
