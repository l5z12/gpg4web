<script setup lang="ts">
import { computed } from 'vue'
import { useVault } from '@/stores/vault'
import { buildGnupgExport, downloadBlob } from '@/lib/gnupg'
import { toastSuccess } from '@/lib/toast'

const vault = useVault()

const algoItems = [
  { label: 'Curve25519 (recommended)', value: 'curve25519' },
  { label: 'Ed25519 (v6)', value: 'ed25519' },
  { label: 'RSA 4096', value: 'rsa4096' },
  { label: 'NIST P-256', value: 'nistp256' },
  { label: 'Post-quantum (ML-DSA-65 + ML-KEM-768)', value: 'pqc' },
]
const signKeyItems = computed(() => [
  { label: 'None', value: '' },
  ...vault.ownKeys.map((k) => ({ label: k.info.userIds[0] || k.keyId, value: k.fingerprint })),
])

const autoLockItems = [
  { label: 'Never', value: 0 },
  { label: '1 minute', value: 1 },
  { label: '5 minutes', value: 5 },
  { label: '15 minutes', value: 15 },
  { label: '30 minutes', value: 30 },
  { label: '1 hour', value: 60 },
]
const autoLock = computed({
  get: () => vault.settings.autoLockMinutes ?? 15,
  set: (v: number) => vault.updateSettings({ autoLockMinutes: v }),
})

const isDark = computed({
  get: () => vault.settings.theme !== 'light',
  set: (v: boolean) => vault.updateSettings({ theme: v ? 'dark' : 'light' }),
})
const defaultAlgo = computed({
  get: () => vault.settings.defaultAlgorithm,
  set: (v: string) => vault.updateSettings({ defaultAlgorithm: v }),
})
const defaultSignKey = computed({
  get: () => vault.settings.defaultSignKey ?? '',
  set: (v: string) => vault.updateSettings({ defaultSignKey: v || null }),
})

function exportGnupg() {
  downloadBlob(buildGnupgExport(vault.keys), 'gnupg-home-export.zip')
  toastSuccess('Exported .gnupg home archive')
}
function exportVault() {
  const id = localStorage.getItem('gpg4web.vault.identity')
  const env = localStorage.getItem('gpg4web.vault.envelope')
  const blob = new Blob(
    [JSON.stringify({ identity: JSON.parse(id ?? 'null'), envelope: JSON.parse(env ?? 'null') }, null, 2)],
    { type: 'application/json' },
  )
  downloadBlob(blob, 'gpg4web-vault-backup.json')
  toastSuccess('Encrypted vault backup downloaded')
}
function destroy() {
  if (!window.confirm('This permanently deletes your vault and ALL stored keys. This cannot be undone. Continue?'))
    return
  vault.destroyVault()
}
</script>

<template>
  <div class="view">
    <div class="view-head"><h1>Settings</h1></div>

    <UCard class="panel">
      <template #header><span>Appearance &amp; defaults</span></template>
      <UFormField label="Dark theme" class="setting-row">
        <USwitch v-model="isDark" />
      </UFormField>
      <UFormField label="Default algorithm" class="setting-row">
        <USelect v-model="defaultAlgo" :items="algoItems" class="setting-control" />
      </UFormField>
      <UFormField label="Default signing key" class="setting-row">
        <USelect v-model="defaultSignKey" :items="signKeyItems" class="setting-control" />
      </UFormField>
    </UCard>

    <UCard class="panel">
      <template #header><span>Security</span></template>
      <UFormField
        label="Auto-lock after inactivity"
        description="Lock the vault automatically when idle. Also re-checks on wake from sleep."
        class="setting-row"
      >
        <USelect v-model="autoLock" :items="autoLockItems" class="setting-control" />
      </UFormField>
    </UCard>

    <UCard class="panel">
      <template #header><span>Backup &amp; export</span></template>
      <p class="hint">
        The <strong>.gnupg export</strong> produces a portable archive that the real
        <code>gpg</code> binary can import. The <strong>vault backup</strong> is the encrypted
        localStorage blob — safe to store anywhere, useless without your master password.
      </p>
      <div class="row mt-3">
        <UButton color="neutral" variant="subtle" icon="i-lucide-package" :disabled="!vault.keys.length" @click="exportGnupg">
          Export .gnupg home
        </UButton>
        <UButton color="neutral" variant="subtle" icon="i-lucide-hard-drive-download" @click="exportVault">
          Backup encrypted vault
        </UButton>
      </div>
    </UCard>

    <UCard class="panel">
      <template #header><span>Danger zone</span></template>
      <p class="hint">Permanently remove the local vault and every key it contains.</p>
      <UButton color="error" icon="i-lucide-trash-2" class="mt-3" @click="destroy">Delete vault</UButton>
    </UCard>
  </div>
</template>
