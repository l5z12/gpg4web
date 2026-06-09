<script setup lang="ts">
import { computed, reactive, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { generateKey, type KeyAlgorithm } from '@/crypto/core'
import { useVault } from '@/stores/vault'
import { toastError, toastSuccess } from '@/lib/toast'

const { t } = useI18n()

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

const algorithms = computed(() => [
  { label: t('generate.algCurve25519'), value: 'curve25519' },
  { label: t('generate.algEd25519'), value: 'ed25519' },
  { label: t('generate.algRsa3072'), value: 'rsa3072' },
  { label: t('generate.algRsa4096'), value: 'rsa4096' },
  { label: t('generate.algRsa2048'), value: 'rsa2048' },
  { label: t('generate.algNistP256'), value: 'nistp256' },
  { label: t('generate.algNistP384'), value: 'nistp384' },
  { label: t('generate.algNistP521'), value: 'nistp521' },
  { label: t('generate.algPqc'), value: 'pqc' },
  { label: t('generate.algMldsa87Mlkem1024'), value: 'mldsa87-mlkem1024' },
  { label: t('generate.algSlhdsa128sMlkem768'), value: 'slhdsa128s-mlkem768' },
])

function onOpenChange(v: boolean) {
  if (!v && !busy.value) emit('close')
}

async function create() {
  if (busy.value) return
  if (!form.name.trim()) return toastError(t('generate.errName'))
  if (form.passphrase !== form.passphrase2) return toastError(t('generate.errPassphraseMismatch'))
  const userId = form.email.trim()
    ? `${form.name.trim()} <${form.email.trim()}>`
    : form.name.trim()

  // Convert the "valid until" date into the number of days the core expects.
  let expireDays = 0
  if (form.expires && form.validUntil) {
    const until = new Date(`${form.validUntil}T23:59:59`).getTime()
    if (Number.isNaN(until)) return toastError(t('generate.errInvalidExpiry'))
    expireDays = Math.ceil((until - Date.now()) / 86_400_000)
    if (expireDays < 1) return toastError(t('generate.errExpiryFuture'))
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
    toastSuccess(t('generate.created', { id: key.fingerprint.slice(-16) }))
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
    :title="t('generate.title')"
    :description="t('generate.description')"
    @update:open="onOpenChange"
  >
    <template #body>
      <div class="form-stack">
        <UFormField :label="t('generate.name')">
          <UInput v-model="form.name" :placeholder="t('generate.namePlaceholder')" class="w-full" />
        </UFormField>
        <UFormField :label="t('generate.email')">
          <UInput v-model="form.email" :placeholder="t('generate.emailPlaceholder')" class="w-full" />
        </UFormField>
        <UFormField :label="t('generate.algorithm')">
          <USelect v-model="form.algorithm" :items="algorithms" class="w-full" />
        </UFormField>
        <UFormField :label="t('generate.expires')">
          <div class="expiry-row">
            <USwitch v-model="form.expires" />
            <UInput
              v-if="form.expires"
              v-model="form.validUntil"
              type="date"
              :min="minExpiry"
              class="expiry-date"
            />
            <span v-else class="muted small">{{ t('generate.neverExpires') }}</span>
          </div>
        </UFormField>
        <UFormField :label="t('generate.passphrase')">
          <UInput
            v-model="form.passphrase"
            type="password"
            :placeholder="t('generate.passphrasePlaceholder')"
            class="w-full"
          />
        </UFormField>
        <UFormField :label="t('generate.confirmPassphrase')">
          <UInput v-model="form.passphrase2" type="password" class="w-full" />
        </UFormField>
        <p class="hint">
          {{ t('generate.hint') }}
        </p>
      </div>
    </template>

    <template #footer>
      <div class="modal-actions">
        <UButton color="neutral" variant="ghost" :disabled="busy" @click="emit('close')">
          {{ t('generate.cancel') }}
        </UButton>
        <UButton :loading="busy" icon="i-lucide-key-round" @click="create">{{ t('generate.create') }}</UButton>
      </div>
    </template>
  </UModal>
</template>
