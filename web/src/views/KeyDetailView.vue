<script setup lang="ts">
import { computed } from 'vue'
import { useRouter } from 'vue-router'
import { useVault } from '@/stores/vault'
import { downloadText } from '@/lib/gnupg'
import { toastSuccess } from '@/lib/toast'

const props = defineProps<{ fingerprint: string }>()
const vault = useVault()
const router = useRouter()

const key = computed(() => vault.keyByFingerprint(props.fingerprint))

const fmtFpr = (fpr: string) => fpr.replace(/(.{4})/g, '$1 ').trim()
const fmtDate = (ts: number | null) => (ts ? new Date(ts * 1000).toLocaleString() : '—')

async function copy(text: string, label: string) {
  await navigator.clipboard.writeText(text)
  toastSuccess(`${label} copied`)
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
  if (!window.confirm('Remove this certificate from your vault?')) return
  vault.removeKey(key.value.fingerprint)
  toastSuccess('Certificate removed')
  router.push('/keys')
}
function toggleTrust() {
  if (key.value) vault.setTrusted(key.value.fingerprint, !key.value.trusted)
}
</script>

<template>
  <div v-if="!key" class="view">
    <p>Certificate not found. <router-link to="/keys">Back to certificates</router-link></p>
  </div>
  <div v-else class="view">
    <div class="view-head">
      <div>
        <router-link to="/keys" class="back">‹ Certificates</router-link>
        <h1>{{ key.info.userIds[0] || '(no user id)' }}</h1>
      </div>
      <div class="toolbar">
        <UButton color="neutral" variant="subtle" icon="i-lucide-download" @click="exportPub">
          Export public
        </UButton>
        <UButton
          v-if="key.secretKeyEnc"
          color="neutral"
          variant="subtle"
          icon="i-lucide-download"
          @click="exportSec"
        >
          Export secret
        </UButton>
        <UButton color="error" variant="soft" icon="i-lucide-trash-2" @click="remove">Delete</UButton>
      </div>
    </div>

    <UCard class="panel">
      <template #header><span>Identity</span></template>
      <div class="kv">
        <span>Type</span>
        <UBadge :color="key.secretKeyEnc ? 'warning' : 'info'" variant="subtle">
          {{ key.secretKeyEnc ? 'Key pair (public + secret)' : 'Public key' }}
        </UBadge>
      </div>
      <div class="kv"><span>Algorithm</span><span>{{ key.info.algorithm }}</span></div>
      <div class="kv"><span>Created</span><span>{{ fmtDate(key.info.createdAt) }}</span></div>
      <div class="kv"><span>Expires</span><span>{{ fmtDate(key.info.expiresAt) }}</span></div>
      <div class="kv">
        <span>Capabilities</span>
        <span class="chips">
          <UBadge v-if="key.info.canSign" color="neutral" variant="subtle">Sign</UBadge>
          <UBadge v-if="key.info.canEncrypt" color="neutral" variant="subtle">Encrypt</UBadge>
        </span>
      </div>
      <div class="kv">
        <span>Trust</span>
        <UButton variant="link" :icon="key.trusted ? 'i-lucide-star' : 'i-lucide-star-off'" @click="toggleTrust">
          {{ key.trusted ? 'Trusted' : 'Mark trusted' }}
        </UButton>
      </div>
    </UCard>

    <UCard class="panel">
      <template #header><span>Fingerprint &amp; User IDs</span></template>
      <code class="fingerprint" @click="copy(key.fingerprint, 'Fingerprint')">
        {{ fmtFpr(key.fingerprint) }}
      </code>
      <ul class="uid-list">
        <li v-for="(u, i) in key.info.userIds" :key="i">{{ u }}</li>
      </ul>
    </UCard>

    <UCard class="panel">
      <template #header><span>Subkeys</span></template>
      <table class="key-table">
        <thead>
          <tr><th>Key ID</th><th>Algorithm</th><th>Usage</th></tr>
        </thead>
        <tbody>
          <tr v-for="s in key.info.subkeys" :key="s.fingerprint">
            <td class="mono small">{{ s.keyId.slice(-16) }}</td>
            <td>{{ s.algorithm }}</td>
            <td>
              <span class="chips">
                <UBadge v-if="s.canSign" color="neutral" variant="subtle">Sign</UBadge>
                <UBadge v-if="s.canEncrypt" color="neutral" variant="subtle">Encrypt</UBadge>
              </span>
            </td>
          </tr>
          <tr v-if="!key.info.subkeys.length"><td colspan="3" class="muted">No subkeys</td></tr>
        </tbody>
      </table>
    </UCard>

    <UCard class="panel">
      <template #header>
        <div class="card-header-row">
          <span>Armored public key</span>
          <UButton size="xs" color="neutral" variant="subtle" icon="i-lucide-copy" @click="copy(key.publicKey, 'Public key')">
            Copy
          </UButton>
        </div>
      </template>
      <pre class="armored">{{ key.publicKey }}</pre>
    </UCard>
  </div>
</template>
