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

function fmtFpr(fpr: string): string {
  return fpr.replace(/(.{4})/g, '$1 ').trim()
}
function fmtDate(ts: number | null): string {
  return ts ? new Date(ts * 1000).toLocaleString() : '—'
}

async function copy(text: string, label: string) {
  await navigator.clipboard.writeText(text)
  toastSuccess(`${label} copied`)
}

function exportPub() {
  if (key.value) downloadText(key.value.publicKey, `${key.value.fingerprint.slice(-16)}.pub.asc`)
}
function exportSec() {
  if (key.value?.secretKey)
    downloadText(key.value.secretKey, `${key.value.fingerprint.slice(-16)}.sec.asc`)
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
        <button class="ghost" @click="exportPub">Export public</button>
        <button v-if="key.secretKey" class="ghost" @click="exportSec">Export secret</button>
        <button class="danger" @click="remove">Delete</button>
      </div>
    </div>

    <div class="detail-grid">
      <div class="card">
        <h3>Identity</h3>
        <div class="kv">
          <span>Type</span>
          <span>
            <span class="badge" :class="key.secretKey ? 'badge-secret' : 'badge-public'">
              {{ key.secretKey ? 'Key pair' : 'Public key' }}
            </span>
          </span>
        </div>
        <div class="kv"><span>Algorithm</span><span>{{ key.info.algorithm }}</span></div>
        <div class="kv"><span>Created</span><span>{{ fmtDate(key.info.createdAt) }}</span></div>
        <div class="kv"><span>Expires</span><span>{{ fmtDate(key.info.expiresAt) }}</span></div>
        <div class="kv">
          <span>Capabilities</span>
          <span>
            <span v-if="key.info.canSign" class="chip">Sign</span>
            <span v-if="key.info.canEncrypt" class="chip">Encrypt</span>
          </span>
        </div>
        <div class="kv">
          <span>Trust</span>
          <span>
            <button class="link" @click="toggleTrust">
              {{ key.trusted ? '★ Trusted' : '☆ Mark trusted' }}
            </button>
          </span>
        </div>
      </div>

      <div class="card">
        <h3>Fingerprint</h3>
        <code class="fingerprint" @click="copy(key.fingerprint, 'Fingerprint')">
          {{ fmtFpr(key.fingerprint) }}
        </code>
        <h3>User IDs</h3>
        <ul class="uid-list">
          <li v-for="(u, i) in key.info.userIds" :key="i">{{ u }}</li>
        </ul>
      </div>
    </div>

    <div class="card">
      <h3>Subkeys</h3>
      <table class="key-table compact">
        <thead>
          <tr><th>Key ID</th><th>Algorithm</th><th>Usage</th></tr>
        </thead>
        <tbody>
          <tr v-for="s in key.info.subkeys" :key="s.fingerprint">
            <td class="mono small">{{ s.keyId.slice(-16) }}</td>
            <td>{{ s.algorithm }}</td>
            <td>
              <span v-if="s.canSign" class="chip">Sign</span>
              <span v-if="s.canEncrypt" class="chip">Encrypt</span>
            </td>
          </tr>
          <tr v-if="!key.info.subkeys.length"><td colspan="3" class="muted">No subkeys</td></tr>
        </tbody>
      </table>
    </div>

    <div class="card">
      <h3>Armored public key</h3>
      <button class="ghost small" @click="copy(key.publicKey, 'Public key')">Copy</button>
      <pre class="armored">{{ key.publicKey }}</pre>
    </div>
  </div>
</template>
