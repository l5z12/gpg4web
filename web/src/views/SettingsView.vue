<script setup lang="ts">
import { useVault } from '@/stores/vault'
import { buildGnupgExport, downloadBlob } from '@/lib/gnupg'
import { toastSuccess } from '@/lib/toast'

const vault = useVault()

function exportGnupg() {
  downloadBlob(buildGnupgExport(vault.keys), 'gnupg-home-export.zip')
  toastSuccess('Exported .gnupg home archive')
}

function exportVault() {
  // The raw encrypted blob — safe to back up; useless without the master password.
  const id = localStorage.getItem('gpg4web.vault.identity')
  const env = localStorage.getItem('gpg4web.vault.envelope')
  const blob = new Blob([JSON.stringify({ identity: JSON.parse(id ?? 'null'), envelope: JSON.parse(env ?? 'null') }, null, 2)], {
    type: 'application/json',
  })
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

    <div class="card">
      <h3>Defaults</h3>
      <div class="form-grid">
        <label>Default algorithm</label>
        <select
          :value="vault.settings.defaultAlgorithm"
          @change="vault.updateSettings({ defaultAlgorithm: ($event.target as HTMLSelectElement).value })"
        >
          <option value="curve25519">Curve25519 (recommended)</option>
          <option value="ed25519">Ed25519 (v6)</option>
          <option value="rsa4096">RSA 4096</option>
          <option value="nistp256">NIST P-256</option>
          <option value="pqc">Post-quantum (ML-DSA-65 + ML-KEM-768)</option>
        </select>

        <label>Default signing key</label>
        <select
          :value="vault.settings.defaultSignKey ?? ''"
          @change="vault.updateSettings({ defaultSignKey: ($event.target as HTMLSelectElement).value || null })"
        >
          <option value="">None</option>
          <option v-for="k in vault.ownKeys" :key="k.fingerprint" :value="k.fingerprint">
            {{ k.info.userIds[0] || k.keyId }}
          </option>
        </select>
      </div>
    </div>

    <div class="card">
      <h3>Backup &amp; export</h3>
      <p class="hint">
        The <strong>.gnupg export</strong> produces a portable archive that the
        real <code>gpg</code> binary can import. The
        <strong>vault backup</strong> is the encrypted localStorage blob — safe
        to store anywhere, useless without your master password.
      </p>
      <div class="row">
        <button class="ghost" :disabled="!vault.keys.length" @click="exportGnupg">
          📦 Export .gnupg home
        </button>
        <button class="ghost" @click="exportVault">💾 Backup encrypted vault</button>
      </div>
    </div>

    <div class="card danger-card">
      <h3>Danger zone</h3>
      <p class="hint">Permanently remove the local vault and every key it contains.</p>
      <button class="danger" @click="destroy">Delete vault</button>
    </div>
  </div>
</template>
