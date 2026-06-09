<script setup lang="ts">
import { computed, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { useRouter } from 'vue-router'
import { useVault } from '@/stores/vault'
import GenerateKeyDialog from '@/components/GenerateKeyDialog.vue'
import ImportKeyDialog from '@/components/ImportKeyDialog.vue'
import { buildGnupgExport, downloadBlob } from '@/lib/gnupg'
import { toastSuccess } from '@/lib/toast'
import type { StoredKey } from '@/lib/types'

const { t } = useI18n()
const vault = useVault()
const router = useRouter()
const showGenerate = ref(false)
const showImport = ref(false)
const query = ref('')
const filter = ref<'all' | 'mine' | 'others'>('all')

const filters = computed(() => [
  { key: 'all' as const, label: t('keys.filterAll') },
  { key: 'mine' as const, label: t('keys.filterMine') },
  { key: 'others' as const, label: t('keys.filterOthers') },
])

function isPq(k: StoredKey): boolean {
  return /MlKem|MlDsa|SlhDsa/i.test(
    k.info.algorithm + k.info.subkeys.map((s) => s.algorithm).join(''),
  )
}
const fmtDate = (ts: number) => new Date(ts * 1000).toLocaleDateString()
function expiry(k: StoredKey): string {
  if (!k.info.expiresAt) return t('keys.never')
  const d = new Date(k.info.expiresAt * 1000)
  return (d.getTime() < Date.now() ? t('keys.expiredPrefix') : '') + d.toLocaleDateString()
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
  toastSuccess(t('keys.exportedGnupg'))
}
</script>

<template>
  <div class="view">
    <div class="view-head">
      <h1>{{ t('keys.heading') }}</h1>
      <div class="toolbar">
        <UButton icon="i-lucide-plus" @click="showGenerate = true">{{ t('keys.newKey') }}</UButton>
        <UButton icon="i-lucide-download" color="neutral" variant="subtle" @click="showImport = true">
          {{ t('keys.import') }}
        </UButton>
        <UButton
          icon="i-lucide-package"
          color="neutral"
          variant="subtle"
          :disabled="!vault.keys.length"
          @click="exportGnupg"
        >
          {{ t('keys.exportGnupg') }}
        </UButton>
      </div>
    </div>

    <div class="filters">
      <UInput
        v-model="query"
        icon="i-lucide-search"
        :placeholder="t('keys.searchPlaceholder')"
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
      {{ vault.keys.length ? t('keys.emptySearch') : t('keys.emptyNone') }}
    </div>

    <template v-else>
      <!-- Desktop / wide: table -->
      <table class="key-table cert-table">
        <thead>
          <tr>
            <th>{{ t('keys.colName') }}</th>
            <th>{{ t('keys.colType') }}</th>
            <th>{{ t('keys.colKeyId') }}</th>
            <th>{{ t('keys.colCreated') }}</th>
            <th>{{ t('keys.colExpires') }}</th>
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
                <span v-if="isPq(k)" :title="t('keys.postQuantumKey')">🛡</span>
                <span>{{ k.info.userIds[0] || t('keys.noUserId') }}</span>
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
            <span class="key-card-name">{{ k.info.userIds[0] || t('keys.noUserId') }}</span>
            <span v-if="isPq(k)" class="key-card-pq" :title="t('keys.postQuantumKey')">🛡</span>
            <UIcon name="i-lucide-chevron-right" class="key-card-chevron" />
          </div>
          <div class="key-card-meta">
            <span>{{ k.info.algorithm }}</span>
            <span class="mono">{{ k.keyId.slice(-16) }}</span>
          </div>
          <div class="key-card-meta muted">
            <span>{{ t('keys.metaCreated') }} {{ fmtDate(k.info.createdAt) }}</span>
            <span>{{ t('keys.metaExpires') }} {{ expiry(k) }}</span>
          </div>
        </div>
      </div>
    </template>


    <GenerateKeyDialog v-if="showGenerate" @close="showGenerate = false" />
    <ImportKeyDialog v-if="showImport" @close="showImport = false" />
  </div>
</template>
