<script setup lang="ts">
import { computed, ref } from 'vue'
import type { TabsItem } from '@nuxt/ui'
import { useVault } from '@/stores/vault'
import {
  decryptFile,
  encryptFile,
  signFileDetached,
  verifyFileDetached,
} from '@/crypto/core'
import { downloadBlob } from '@/lib/gnupg'
import { toastError, toastSuccess } from '@/lib/toast'

const vault = useVault()
const tab = ref('signencrypt')
const tabs: TabsItem[] = [
  { label: 'Sign / Encrypt', value: 'signencrypt', slot: 'signencrypt', icon: 'i-lucide-lock' },
  { label: 'Decrypt / Verify', value: 'decryptverify', slot: 'decryptverify', icon: 'i-lucide-lock-open' },
]

// --- Sign / Encrypt ---
const seFile = ref<File | null>(null)
const seRecipients = ref<string[]>([])
const seSign = ref('none')
const sePass = ref('')
const seArmor = ref(false)

// --- Decrypt / Verify ---
const dvFile = ref<File | null>(null)
const dvSigFile = ref<File | null>(null)
const dvKey = ref('')
const dvPass = ref('')
const dvResult = ref<{ ok: boolean; title: string; detail: string } | null>(null)

const allKeyItems = computed(() =>
  vault.keys.map((k) => ({ label: `${k.info.userIds[0] || k.keyId} (${k.keyId.slice(-8)})`, value: k.fingerprint })),
)
const signItems = computed(() => [
  { label: "Don't sign", value: 'none' },
  ...vault.ownKeys.map((k) => ({ label: k.info.userIds[0] || k.keyId, value: k.fingerprint })),
])
const myKeyItems = computed(() =>
  vault.ownKeys.map((k) => ({ label: k.info.userIds[0] || k.keyId, value: k.fingerprint })),
)

const fmtSize = (n: number) =>
  n < 1024 ? `${n} B` : n < 1048576 ? `${(n / 1024).toFixed(1)} KB` : `${(n / 1048576).toFixed(1)} MB`

async function bytes(f: File): Promise<Uint8Array> {
  return new Uint8Array(await f.arrayBuffer())
}

async function doSignEncrypt() {
  if (!seFile.value) return toastError('Choose a file')
  const data = await bytes(seFile.value)
  const hasRecipients = seRecipients.value.length > 0
  const wantSign = seSign.value !== 'none'
  const signer = wantSign ? vault.getSecretKey(seSign.value) : null
  if (wantSign && !signer) return toastError('Could not unlock the signing key')

  try {
    if (hasRecipients) {
      const pubs = seRecipients.value
        .map((f) => vault.keyByFingerprint(f)?.publicKey)
        .filter((x): x is string => !!x)
      const out = encryptFile(data, pubs, signer, sePass.value || null, seArmor.value)
      const ext = seArmor.value ? '.asc' : '.gpg'
      downloadBlob(new Blob([out as BlobPart]), seFile.value.name + ext)
      toastSuccess(signer ? 'Signed and encrypted' : 'Encrypted')
    } else if (signer) {
      // No recipients → detached signature (Kleopatra signs files detached).
      const sig = signFileDetached(data, signer, sePass.value)
      downloadBlob(new Blob([sig]), seFile.value.name + '.sig.asc')
      toastSuccess('Signed (detached signature)')
    } else {
      toastError('Choose recipients to encrypt, and/or a key to sign with')
    }
  } catch (e) {
    toastError(e instanceof Error ? e.message : String(e))
  }
}

async function doDecryptVerify() {
  if (!dvFile.value) return toastError('Choose a file')
  const data = await bytes(dvFile.value)
  try {
    if (dvSigFile.value) {
      // Verify the file against a detached signature.
      if (!vault.keys.length) return toastError("Import the signer's public key to verify")
      const sigText = new TextDecoder().decode(await bytes(dvSigFile.value))
      let ok = false
      let label = 'unknown signer'
      for (const key of vault.keys) {
        if (verifyFileDetached(data, sigText, key.publicKey)) {
          ok = true
          label = key.info.userIds[0] || key.keyId
          break
        }
      }
      dvResult.value = {
        ok,
        title: ok ? 'Valid signature' : 'Invalid or untrusted signature',
        detail: ok ? `Signed by ${label}` : 'No key in your ring matches this signature.',
      }
      toastSuccess(ok ? 'Valid signature' : 'Signature could not be verified')
    } else {
      // Decrypt the file.
      const sk = dvKey.value ? vault.getSecretKey(dvKey.value) : null
      if (!sk) return toastError('Select one of your secret keys')
      const out = decryptFile(data, sk, dvPass.value)
      const name = dvFile.value.name.replace(/\.(gpg|pgp|asc)$/i, '') || 'decrypted'
      downloadBlob(new Blob([out as BlobPart]), name)
      dvResult.value = { ok: true, title: 'Decrypted', detail: `Saved as ${name}` }
      toastSuccess('Decrypted')
    }
  } catch (e) {
    toastError(e instanceof Error ? e.message : String(e))
  }
}

function pick(target: 'se' | 'dv' | 'dvsig', e: Event) {
  const f = (e.target as HTMLInputElement).files?.[0] ?? null
  if (target === 'se') seFile.value = f
  else if (target === 'dv') dvFile.value = f
  else dvSigFile.value = f
}
function drop(target: 'se' | 'dv', e: DragEvent) {
  const f = e.dataTransfer?.files?.[0] ?? null
  if (f) {
    if (target === 'se') seFile.value = f
    else dvFile.value = f
  }
}
</script>

<template>
  <div class="view">
    <div class="view-head"><h1>Files</h1></div>

    <UTabs v-model="tab" :items="tabs" class="w-full">
      <template #signencrypt>
        <div class="pad-grid">
          <div class="pad-col">
            <label>File</label>
            <label
              class="dropzone"
              @dragover.prevent
              @drop.prevent="drop('se', $event)"
            >
              <input type="file" class="hidden" @change="pick('se', $event)" />
              <UIcon name="i-lucide-upload" class="dropzone-icon" />
              <span v-if="seFile">{{ seFile.name }} · {{ fmtSize(seFile.size) }}</span>
              <span v-else class="muted">Drop a file here or click to choose</span>
            </label>

            <label>Encrypt for (leave empty to sign only)</label>
            <USelect v-model="seRecipients" multiple :items="allKeyItems" placeholder="No recipients — sign only" class="w-full" />

            <label>Sign as</label>
            <USelect v-model="seSign" :items="signItems" class="w-full" />
            <UInput v-if="seSign !== 'none'" v-model="sePass" type="password" placeholder="Signing key passphrase (if any)" class="w-full mt-2" />

            <div class="armor-row mt-3">
              <USwitch v-model="seArmor" />
              <span>ASCII armor (.asc instead of binary .gpg)</span>
            </div>

            <UButton block icon="i-lucide-lock" class="mt-4" @click="doSignEncrypt">Sign / Encrypt File</UButton>
            <p class="hint">
              With recipients the file is encrypted (<code>.gpg</code>/<code>.asc</code>). With no
              recipients a detached signature (<code>.sig.asc</code>) is produced.
            </p>
          </div>
          <div class="pad-col"></div>
        </div>
      </template>

      <template #decryptverify>
        <div class="pad-grid">
          <div class="pad-col">
            <label>File</label>
            <label class="dropzone" @dragover.prevent @drop.prevent="drop('dv', $event)">
              <input type="file" class="hidden" @change="pick('dv', $event)" />
              <UIcon name="i-lucide-file" class="dropzone-icon" />
              <span v-if="dvFile">{{ dvFile.name }} · {{ fmtSize(dvFile.size) }}</span>
              <span v-else class="muted">Drop an encrypted or signed file here</span>
            </label>

            <label>Detached signature (optional — to verify)</label>
            <label class="dropzone dropzone-sm">
              <input type="file" accept=".sig,.asc,.gpg" class="hidden" @change="pick('dvsig', $event)" />
              <span v-if="dvSigFile">{{ dvSigFile.name }}</span>
              <span v-else class="muted">Choose a .sig / .asc signature to verify against the file</span>
            </label>

            <template v-if="!dvSigFile">
              <label>Decrypt with</label>
              <USelect v-model="dvKey" :items="myKeyItems" placeholder="Select your secret key" class="w-full" />
              <UInput v-model="dvPass" type="password" placeholder="Key passphrase (if any)" class="w-full mt-2" />
            </template>

            <UButton block icon="i-lucide-lock-open" class="mt-4" @click="doDecryptVerify">Decrypt / Verify File</UButton>
          </div>

          <div class="pad-col">
            <UAlert
              v-if="dvResult"
              :color="dvResult.ok ? 'success' : 'error'"
              :icon="dvResult.ok ? 'i-lucide-circle-check' : 'i-lucide-circle-x'"
              :title="dvResult.title"
              :description="dvResult.detail"
            />
            <p v-else class="muted">Decrypt a file, or verify it against a detached signature.</p>
          </div>
        </div>
      </template>
    </UTabs>
  </div>
</template>
