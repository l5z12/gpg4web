<script setup lang="ts">
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'
import { useRouter } from 'vue-router'
import { useVault } from '@/stores/vault'
import { downloadText } from '@/lib/gnupg'
import { toastSuccess } from '@/lib/toast'

const props = defineProps<{ fingerprint: string }>()
const { t } = useI18n()
const vault = useVault()
const router = useRouter()

const key = computed(() => vault.keyByFingerprint(props.fingerprint))

const fmtFpr = (fpr: string) => fpr.replace(/(.{4})/g, '$1 ').trim()
const fmtDate = (ts: number | null) => (ts ? new Date(ts * 1000).toLocaleString() : '—')

async function copy(text: string, label: string) {
  await navigator.clipboard.writeText(text)
  toastSuccess(t('keyDetail.copied', { label }))
}
function exportPub() {
  if (key.value) downloadText(key.value.publicKey, `${key.value.fingerprint.slice(-16)}.pub.asc`)
}
function exportSec() {
  if (!key.value?.secretKeyEnc) return
  const secret = vault.getSecretKey(key.value.fingerprint)
  if (secret) downloadText(secret, `${key.value.fingerprint.slice(-16)}.sec.asc`)
}
function remove() {
  if (!key.value) return
  if (!window.confirm(t('keyDetail.removeConfirm'))) return
  vault.removeKey(key.value.fingerprint)
  toastSuccess(t('keyDetail.removed'))
  router.push('/keys')
}
function toggleTrust() {
  if (key.value) vault.setTrusted(key.value.fingerprint, !key.value.trusted)
}
</script>

<template>
  <div v-if="!key" class="view">
    <p>{{ t('keyDetail.notFound') }} <router-link to="/keys">{{ t('keyDetail.backToCertificates') }}</router-link></p>
  </div>
  <div v-else class="view">
    <div class="view-head">
      <div>
        <router-link to="/keys" class="back">{{ t('keyDetail.backLink') }}</router-link>
        <h1>{{ key.info.userIds[0] || t('keyDetail.noUserId') }}</h1>
      </div>
      <div class="toolbar">
        <UButton color="neutral" variant="subtle" icon="i-lucide-download" @click="exportPub">
          {{ t('keyDetail.exportPublic') }}
        </UButton>
        <UButton
          v-if="key.secretKeyEnc"
          color="neutral"
          variant="subtle"
          icon="i-lucide-download"
          @click="exportSec"
        >
          {{ t('keyDetail.exportSecret') }}
        </UButton>
        <UButton color="error" variant="soft" icon="i-lucide-trash-2" @click="remove">{{ t('keyDetail.delete') }}</UButton>
      </div>
    </div>

    <UCard class="panel">
      <template #header><span>{{ t('keyDetail.identity') }}</span></template>
      <div class="kv">
        <span>{{ t('keyDetail.type') }}</span>
        <UBadge :color="key.secretKeyEnc ? 'warning' : 'info'" variant="subtle">
          {{ key.secretKeyEnc ? t('keyDetail.keyPair') : t('keyDetail.publicKey') }}
        </UBadge>
      </div>
      <div class="kv"><span>{{ t('keyDetail.algorithm') }}</span><span>{{ key.info.algorithm }}</span></div>
      <div class="kv"><span>{{ t('keyDetail.created') }}</span><span>{{ fmtDate(key.info.createdAt) }}</span></div>
      <div class="kv"><span>{{ t('keyDetail.expires') }}</span><span>{{ fmtDate(key.info.expiresAt) }}</span></div>
      <div class="kv">
        <span>{{ t('keyDetail.capabilities') }}</span>
        <span class="chips">
          <UBadge v-if="key.info.canSign" color="neutral" variant="subtle">{{ t('keyDetail.sign') }}</UBadge>
          <UBadge v-if="key.info.canEncrypt" color="neutral" variant="subtle">{{ t('keyDetail.encrypt') }}</UBadge>
        </span>
      </div>
      <div class="kv">
        <span>{{ t('keyDetail.trust') }}</span>
        <UButton variant="link" :icon="key.trusted ? 'i-lucide-star' : 'i-lucide-star-off'" @click="toggleTrust">
          {{ key.trusted ? t('keyDetail.trusted') : t('keyDetail.markTrusted') }}
        </UButton>
      </div>
    </UCard>

    <UCard class="panel">
      <template #header><span>{{ t('keyDetail.fingerprintUserIds') }}</span></template>
      <code class="fingerprint" @click="copy(key.fingerprint, t('keyDetail.fingerprintLabel'))">
        {{ fmtFpr(key.fingerprint) }}
      </code>
      <ul class="uid-list">
        <li v-for="(u, i) in key.info.userIds" :key="i">{{ u }}</li>
      </ul>
    </UCard>

    <UCard class="panel">
      <template #header><span>{{ t('keyDetail.subkeys') }}</span></template>
      <table class="key-table">
        <thead>
          <tr><th>{{ t('keyDetail.colKeyId') }}</th><th>{{ t('keyDetail.colAlgorithm') }}</th><th>{{ t('keyDetail.colUsage') }}</th></tr>
        </thead>
        <tbody>
          <tr v-for="s in key.info.subkeys" :key="s.fingerprint">
            <td class="mono small">{{ s.keyId.slice(-16) }}</td>
            <td>{{ s.algorithm }}</td>
            <td>
              <span class="chips">
                <UBadge v-if="s.canSign" color="neutral" variant="subtle">{{ t('keyDetail.sign') }}</UBadge>
                <UBadge v-if="s.canEncrypt" color="neutral" variant="subtle">{{ t('keyDetail.encrypt') }}</UBadge>
              </span>
            </td>
          </tr>
          <tr v-if="!key.info.subkeys.length"><td colspan="3" class="muted">{{ t('keyDetail.noSubkeys') }}</td></tr>
        </tbody>
      </table>
    </UCard>

    <UCard class="panel">
      <template #header>
        <div class="card-header-row">
          <span>{{ t('keyDetail.armoredPublicKey') }}</span>
          <UButton size="xs" color="neutral" variant="subtle" icon="i-lucide-copy" @click="copy(key.publicKey, t('keyDetail.publicKeyLabel'))">
            {{ t('keyDetail.copy') }}
          </UButton>
        </div>
      </template>
      <pre class="armored">{{ key.publicKey }}</pre>
    </UCard>
  </div>
</template>
