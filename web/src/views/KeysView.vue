<script setup lang="ts">
import { computed, ref } from 'vue'
import { useRouter } from 'vue-router'
import { useVault } from '@/stores/vault'
import GenerateKeyDialog from '@/components/GenerateKeyDialog.vue'
import ImportKeyDialog from '@/components/ImportKeyDialog.vue'
import { buildGnupgExport, downloadBlob } from '@/lib/gnupg'
import { toastSuccess } from '@/lib/toast'
import type { StoredKey } from '@/lib/types'

const vault = useVault()
const router = useRouter()
const showGenerate = ref(false)
const showImport = ref(false)
const query = ref('')
const filter = ref<'all' | 'mine' | 'others'>('all')

const filtered = computed(() => {
  let list = vault.keys
  if (filter.value === 'mine') list = list.filter((k) => k.secretKey)
  if (filter.value === 'others') list = list.filter((k) => !k.secretKey)
  const q = query.value.trim().toLowerCase()
  if (q) {
    list = list.filter(
      (k) =>
        k.fingerprint.toLowerCase().includes(q) ||
        k.info.userIds.some((u) => u.toLowerCase().includes(q)),
    )
  }
  return list
})

function isPq(k: StoredKey): boolean {
  return /MlKem|MlDsa|SlhDsa/i.test(
    k.info.algorithm + k.info.subkeys.map((s) => s.algorithm).join(''),
  )
}

function fmtDate(ts: number): string {
  return new Date(ts * 1000).toLocaleDateString()
}

function expiry(k: StoredKey): string {
  if (!k.info.expiresAt) return 'never'
  const d = new Date(k.info.expiresAt * 1000)
  const expired = d.getTime() < Date.now()
  return (expired ? 'expired ' : '') + d.toLocaleDateString()
}

function exportGnupg() {
  const blob = buildGnupgExport(vault.keys)
  downloadBlob(blob, 'gnupg-home-export.zip')
  toastSuccess('Exported .gnupg home archive')
}

function open(k: StoredKey) {
  router.push(`/keys/${k.fingerprint}`)
}
</script>

<template>
  <div class="view">
    <div class="view-head">
      <h1>Certificates</h1>
      <div class="toolbar">
        <button class="primary" @click="showGenerate = true">＋ New key</button>
        <button class="ghost" @click="showImport = true">⬇ Import</button>
        <button class="ghost" :disabled="!vault.keys.length" @click="exportGnupg">
          📦 Export .gnupg
        </button>
      </div>
    </div>

    <div class="filters">
      <input v-model="query" class="search" placeholder="Search name, email or fingerprint…" />
      <div class="seg">
        <button :class="{ on: filter === 'all' }" @click="filter = 'all'">All</button>
        <button :class="{ on: filter === 'mine' }" @click="filter = 'mine'">My keys</button>
        <button :class="{ on: filter === 'others' }" @click="filter = 'others'">Others</button>
      </div>
    </div>

    <div v-if="!filtered.length" class="empty">
      <p v-if="!vault.keys.length">
        No certificates yet. Create a new key pair or import an existing one.
      </p>
      <p v-else>No certificates match your search.</p>
    </div>

    <table v-else class="key-table">
      <thead>
        <tr>
          <th>Name / User ID</th>
          <th>Type</th>
          <th>Key ID</th>
          <th>Created</th>
          <th>Expires</th>
          <th></th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="k in filtered" :key="k.fingerprint" class="key-row" @click="open(k)">
          <td>
            <div class="uid">
              <span class="badge" :class="k.secretKey ? 'badge-secret' : 'badge-public'">
                {{ k.secretKey ? 'sec' : 'pub' }}
              </span>
              <span class="pq-badge" v-if="isPq(k)" title="Post-quantum key">🛡</span>
              <span>{{ k.info.userIds[0] || '(no user id)' }}</span>
            </div>
            <div v-if="k.info.userIds.length > 1" class="uid-extra">
              +{{ k.info.userIds.length - 1 }} more
            </div>
          </td>
          <td class="muted">{{ k.info.algorithm }}</td>
          <td class="mono small">{{ k.keyId.slice(-16) }}</td>
          <td class="muted">{{ fmtDate(k.info.createdAt) }}</td>
          <td class="muted">{{ expiry(k) }}</td>
          <td class="muted">›</td>
        </tr>
      </tbody>
    </table>

    <GenerateKeyDialog v-if="showGenerate" @close="showGenerate = false" @created="() => {}" />
    <ImportKeyDialog v-if="showImport" @close="showImport = false" @imported="() => {}" />
  </div>
</template>
