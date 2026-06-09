<script setup lang="ts">
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'
import { useVault } from '@/stores/vault'
import { availableLocales, setLocale, type Locale } from '@/i18n'
import { buildGnupgExport, downloadBlob } from '@/lib/gnupg'
import { toastSuccess } from '@/lib/toast'
import { confirmDialog } from '@/lib/confirm'

const vault = useVault()
const { t, locale } = useI18n()

const algoItems = computed(() => [
  { label: t('settings.algoCurve25519'), value: 'curve25519' },
  { label: t('settings.algoEd25519'), value: 'ed25519' },
  { label: t('settings.algoRsa4096'), value: 'rsa4096' },
  { label: t('settings.algoNistp256'), value: 'nistp256' },
  { label: t('settings.algoPqc'), value: 'pqc' },
])
const signKeyItems = computed(() => [
  { label: t('settings.none'), value: 'none' },
  ...vault.ownKeys.map((k) => ({ label: k.info.userIds[0] || k.keyId, value: k.fingerprint })),
])

const autoLockItems = computed(() => [
  { label: t('settings.never'), value: 0 },
  { label: t('settings.oneMinute'), value: 1 },
  { label: t('settings.fiveMinutes'), value: 5 },
  { label: t('settings.fifteenMinutes'), value: 15 },
  { label: t('settings.thirtyMinutes'), value: 30 },
  { label: t('settings.oneHour'), value: 60 },
])
const autoLock = computed({
  get: () => vault.settings.autoLockMinutes ?? 15,
  set: (v: number) => vault.updateSettings({ autoLockMinutes: v }),
})

const isDark = computed({
  get: () => vault.settings.theme !== 'light',
  set: (v: boolean) => vault.updateSettings({ theme: v ? 'dark' : 'light' }),
})
const language = computed({
  get: () => locale.value as Locale,
  set: (v: Locale) => setLocale(v),
})
const defaultAlgo = computed({
  get: () => vault.settings.defaultAlgorithm,
  set: (v: string) => vault.updateSettings({ defaultAlgorithm: v }),
})
const defaultSignKey = computed({
  get: () => vault.settings.defaultSignKey ?? 'none',
  set: (v: string) => vault.updateSettings({ defaultSignKey: v === 'none' ? null : v }),
})

function exportGnupg() {
  downloadBlob(buildGnupgExport(vault.keysForExport()), 'gnupg-home-export.zip')
  toastSuccess(t('settings.exportedGnupg'))
}
function exportVault() {
  const id = localStorage.getItem('gpg4web.vault.identity')
  const env = localStorage.getItem('gpg4web.vault.envelope')
  const blob = new Blob(
    [JSON.stringify({ identity: JSON.parse(id ?? 'null'), envelope: JSON.parse(env ?? 'null') }, null, 2)],
    { type: 'application/json' },
  )
  downloadBlob(blob, 'gpg4web-vault-backup.json')
  toastSuccess(t('settings.vaultBackup'))
}
async function destroy() {
  const ok = await confirmDialog({
    title: t('settings.destroyTitle'),
    message: t('settings.destroyConfirm'),
    confirmLabel: t('settings.deleteVault'),
    danger: true,
  })
  if (!ok) return
  vault.destroyVault()
}
</script>

<template>
  <div class="view">
    <div class="view-head"><h1>{{ t('settings.title') }}</h1></div>

    <UCard class="panel">
      <template #header><span>{{ t('settings.appearanceDefaults') }}</span></template>
      <UFormField :label="t('settings.darkTheme')" class="setting-row">
        <USwitch v-model="isDark" />
      </UFormField>
      <UFormField :label="t('settings.language')" class="setting-row">
        <USelect v-model="language" :items="availableLocales" class="setting-control" />
      </UFormField>
      <UFormField :label="t('settings.defaultAlgorithm')" class="setting-row">
        <USelect v-model="defaultAlgo" :items="algoItems" class="setting-control" />
      </UFormField>
      <UFormField :label="t('settings.defaultSigningKey')" class="setting-row">
        <USelect v-model="defaultSignKey" :items="signKeyItems" class="setting-control" />
      </UFormField>
    </UCard>

    <UCard class="panel">
      <template #header><span>{{ t('settings.security') }}</span></template>
      <UFormField
        :label="t('settings.autoLock')"
        :description="t('settings.autoLockDesc')"
        class="setting-row"
      >
        <USelect v-model="autoLock" :items="autoLockItems" class="setting-control" />
      </UFormField>
    </UCard>

    <UCard class="panel">
      <template #header><span>{{ t('settings.backupExport') }}</span></template>
      <p class="hint">{{ t('settings.backupHint') }}</p>
      <div class="row mt-3">
        <UButton color="neutral" variant="subtle" icon="i-lucide-package" :disabled="!vault.keys.length" @click="exportGnupg">
          {{ t('settings.exportGnupgHome') }}
        </UButton>
        <UButton color="neutral" variant="subtle" icon="i-lucide-hard-drive-download" @click="exportVault">
          {{ t('settings.backupVault') }}
        </UButton>
      </div>
    </UCard>

    <UCard class="panel">
      <template #header><span>{{ t('settings.dangerZone') }}</span></template>
      <p class="hint">{{ t('settings.dangerHint') }}</p>
      <UButton color="error" icon="i-lucide-trash-2" class="mt-3" @click="destroy">{{ t('settings.deleteVault') }}</UButton>
    </UCard>
  </div>
</template>
