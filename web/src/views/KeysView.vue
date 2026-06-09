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

const filters = [
  { key: 'all', label: 'All' },
  { key: 'mine', label: 'My keys' },
  { key: 'others', label: 'Others' },
] as const

function isPq(k: StoredKey): boolean {
  return /MlKem|MlDsa|SlhDsa/i.test(
    k.info.algorithm + k.info.subkeys.map((s) => s.algorithm).join(''),
  )
}
const fmtDate = (ts: number) => new Date(ts * 1000).toLocaleDateString()
function expiry(k: StoredKey): string {
  if (!k.info.expiresAt) return 'never'
  const d = new Date(k.info.expiresAt * 1000)
  return (d.getTime() < Date.now() ? 'expired ' : '') + d.toLocaleDateString()
}

const filtered = computed(() => {
  let list = vault.keys
  if (filter.value === 'mine') list = list.filter((k) => k.secretKeyEnc)
  if (filter.value === 'others') list = list.filter((k) => !k.secretKeyEnc)
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

function exportGnupg() {
  downloadBlob(buildGnupgExport(vault.keysForExport()), 'gnupg-home-export.zip')
  toastSuccess('Exported .gnupg home archive')
}
</script>

<template>
  <div class="view">
    <div class="view-head">
      <h1>Certificates</h1>
      <div class="toolbar">
        <UButton icon="i-lucide-plus" @click="showGenerate = true">New key</UButton>
        <UButton icon="i-lucide-download" color="neutral" variant="subtle" @click="showImport = true">
          Import
        </UButton>
        <UButton
          icon="i-lucide-package"
          color="neutral"
          variant="subtle"
          :disabled="!vault.keys.length"
          @click="exportGnupg"
        >
          Export .gnupg
        </UButton>
      </div>
    </div>

    <div class="filters">
      <UInput
        v-model="query"
        icon="i-lucide-search"
        placeholder="Search name, email or fingerprint…"
        class="search"
      />
      <UButtonGroup class="filter-seg">
        <UButton
          v-for="f in filters"
          :key="f.key"
          :color="filter === f.key ? 'primary' : 'neutral'"
          :variant="filter === f.key ? 'solid' : 'outline'"
          @click="filter = f.key"
        >
          {{ f.label }}
        </UButton>
      </UButtonGroup>
    </div>

    <div v-if="!filtered.length" class="empty">
      {{ vault.keys.length ? 'No certificates match your search.' : 'No certificates yet. Create or import a key.' }}
    </div>

    <template v-else>
      <!-- Desktop / wide: table -->
      <table class="key-table cert-table">
        <thead>
          <tr>
            <th>Name / User ID</th>
            <th>Type</th>
            <th>Key ID</th>
            <th>Created</th>
            <th>Expires</th>
          </tr>
        </thead>
        <tbody>
          <tr
            v-for="k in filtered"
            :key="k.fingerprint"
            class="key-row"
            @click="router.push(`/keys/${k.fingerprint}`)"
          >
            <td>
              <div class="uid">
                <UBadge :color="k.secretKeyEnc ? 'warning' : 'info'" variant="subtle" size="sm">
                  {{ k.secretKeyEnc ? 'sec' : 'pub' }}
                </UBadge>
                <span v-if="isPq(k)" title="Post-quantum key">🛡</span>
                <span>{{ k.info.userIds[0] || '(no user id)' }}</span>
              </div>
            </td>
            <td class="muted">{{ k.info.algorithm }}</td>
            <td class="mono small">{{ k.keyId.slice(-16) }}</td>
            <td class="muted">{{ fmtDate(k.info.createdAt) }}</td>
            <td class="muted">{{ expiry(k) }}</td>
          </tr>
        </tbody>
      </table>

      <!-- Mobile / narrow: cards -->
      <div class="key-cards">
        <div
          v-for="k in filtered"
          :key="k.fingerprint"
          class="key-card"
          role="button"
          tabindex="0"
          @click="router.push(`/keys/${k.fingerprint}`)"
          @keydown.enter="router.push(`/keys/${k.fingerprint}`)"
        >
          <div class="key-card-head">
            <UBadge :color="k.secretKeyEnc ? 'warning' : 'info'" variant="subtle" size="sm">
              {{ k.secretKeyEnc ? 'sec' : 'pub' }}
            </UBadge>
            <span class="key-card-name">{{ k.info.userIds[0] || '(no user id)' }}</span>
            <span v-if="isPq(k)" class="key-card-pq" title="Post-quantum key">🛡</span>
            <UIcon name="i-lucide-chevron-right" class="key-card-chevron" />
          </div>
          <div class="key-card-meta">
            <span>{{ k.info.algorithm }}</span>
            <span class="mono">{{ k.keyId.slice(-16) }}</span>
          </div>
          <div class="key-card-meta muted">
            <span>Created {{ fmtDate(k.info.createdAt) }}</span>
            <span>Expires {{ expiry(k) }}</span>
          </div>
        </div>
      </div>
    </template>


    <GenerateKeyDialog v-if="showGenerate" @close="showGenerate = false" />
    <ImportKeyDialog v-if="showImport" @close="showImport = false" />
  </div>
</template>
