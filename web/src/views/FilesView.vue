<script setup lang="ts">
import { computed, ref } from 'vue'
import { useI18n } from 'vue-i18n'
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
const { t } = useI18n()
const tab = ref('signencrypt')
const tabs = computed<TabsItem[]>(() => [
  { label: t('files.tabSignEncrypt'), value: 'signencrypt', slot: 'signencrypt', icon: 'i-lucide-lock' },
  { label: t('files.tabDecryptVerify'), value: 'decryptverify', slot: 'decryptverify', icon: 'i-lucide-lock-open' },
])

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
  { label: t('files.dontSign'), value: 'none' },
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
  if (!seFile.value) return toastError(t('files.chooseFile'))
  const data = await bytes(seFile.value)
  const hasRecipients = seRecipients.value.length > 0
  const wantSign = seSign.value !== 'none'
  const signer = wantSign ? vault.getSecretKey(seSign.value) : null
  if (wantSign && !signer) return toastError(t('files.couldNotUnlockSigningKey'))

  try {
    if (hasRecipients) {
      const pubs = seRecipients.value
        .map((f) => vault.keyByFingerprint(f)?.publicKey)
        .filter((x): x is string => !!x)
      const out = encryptFile(data, pubs, signer, sePass.value || null, seArmor.value)
      const ext = seArmor.value ? '.asc' : '.gpg'
      downloadBlob(new Blob([out as BlobPart]), seFile.value.name + ext)
      toastSuccess(signer ? t('files.signedAndEncrypted') : t('files.encrypted'))
    } else if (signer) {
      // No recipients → detached signature (Kleopatra signs files detached).
      const sig = signFileDetached(data, signer, sePass.value)
      downloadBlob(new Blob([sig]), seFile.value.name + '.sig.asc')
      toastSuccess(t('files.signedDetached'))
    } else {
      toastError(t('files.chooseRecipientsOrKey'))
    }
  } catch (e) {
    toastError(e instanceof Error ? e.message : String(e))
  }
}

async function doDecryptVerify() {
  if (!dvFile.value) return toastError(t('files.chooseFile'))
  const data = await bytes(dvFile.value)
  try {
    if (dvSigFile.value) {
      // Verify the file against a detached signature.
      if (!vault.keys.length) return toastError(t('files.importSignerPublicKey'))
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
        title: ok ? t('files.validSignature') : t('files.invalidSignature'),
        detail: ok ? t('files.signedBy', { label }) : t('files.noKeyMatches'),
      }
      toastSuccess(ok ? t('files.validSignature') : t('files.signatureCouldNotBeVerified'))
    } else {
      // Decrypt the file.
      const sk = dvKey.value ? vault.getSecretKey(dvKey.value) : null
      if (!sk) return toastError(t('files.selectOneSecretKey'))
      const out = decryptFile(data, sk, dvPass.value)
      const name = dvFile.value.name.replace(/\.(gpg|pgp|asc)$/i, '') || 'decrypted'
      downloadBlob(new Blob([out as BlobPart]), name)
      dvResult.value = { ok: true, title: t('files.decrypted'), detail: t('files.savedAs', { name }) }
      toastSuccess(t('files.decrypted'))
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
    <div class="view-head"><h1>{{ t('files.heading') }}</h1></div>

    <UTabs v-model="tab" :items="tabs" class="w-full">
      <template #signencrypt>
        <div class="pad-grid">
          <div class="pad-col">
            <label>{{ t('files.file') }}</label>
            <label
              class="dropzone"
              @dragover.prevent
              @drop.prevent="drop('se', $event)"
            >
              <input type="file" class="hidden" @change="pick('se', $event)" />
              <UIcon name="i-lucide-upload" class="dropzone-icon" />
              <span v-if="seFile">{{ seFile.name }} · {{ fmtSize(seFile.size) }}</span>
              <span v-else class="muted">{{ t('files.dropFile') }}</span>
            </label>

            <label>{{ t('files.encryptFor') }}</label>
            <USelect v-model="seRecipients" multiple :items="allKeyItems" :placeholder="t('files.noRecipients')" class="w-full" />

            <label>{{ t('files.signAs') }}</label>
            <USelect v-model="seSign" :items="signItems" class="w-full" />
            <UInput v-if="seSign !== 'none'" v-model="sePass" type="password" :placeholder="t('files.signingPassphrase')" class="w-full mt-2" />

            <div class="armor-row mt-3">
              <USwitch v-model="seArmor" />
              <span>{{ t('files.asciiArmor') }}</span>
            </div>

            <UButton block icon="i-lucide-lock" class="mt-4" @click="doSignEncrypt">{{ t('files.signEncryptButton') }}</UButton>
            <p class="hint">{{ t('files.hint') }}</p>
          </div>
          <div class="pad-col"></div>
        </div>
      </template>

      <template #decryptverify>
        <div class="pad-grid">
          <div class="pad-col">
            <label>{{ t('files.file') }}</label>
            <label class="dropzone" @dragover.prevent @drop.prevent="drop('dv', $event)">
              <input type="file" class="hidden" @change="pick('dv', $event)" />
              <UIcon name="i-lucide-file" class="dropzone-icon" />
              <span v-if="dvFile">{{ dvFile.name }} · {{ fmtSize(dvFile.size) }}</span>
              <span v-else class="muted">{{ t('files.dropEncryptedOrSigned') }}</span>
            </label>

            <label>{{ t('files.detachedSignature') }}</label>
            <label class="dropzone dropzone-sm">
              <input type="file" accept=".sig,.asc,.gpg" class="hidden" @change="pick('dvsig', $event)" />
              <span v-if="dvSigFile">{{ dvSigFile.name }}</span>
              <span v-else class="muted">{{ t('files.dropSignature') }}</span>
            </label>

            <template v-if="!dvSigFile">
              <label>{{ t('files.decryptWith') }}</label>
              <USelect v-model="dvKey" :items="myKeyItems" :placeholder="t('files.selectSecretKey')" class="w-full" />
              <UInput v-model="dvPass" type="password" :placeholder="t('files.keyPassphrase')" class="w-full mt-2" />
            </template>

            <UButton block icon="i-lucide-lock-open" class="mt-4" @click="doDecryptVerify">{{ t('files.decryptVerifyButton') }}</UButton>
          </div>

          <div class="pad-col">
            <UAlert
              v-if="dvResult"
              :color="dvResult.ok ? 'success' : 'error'"
              :icon="dvResult.ok ? 'i-lucide-circle-check' : 'i-lucide-circle-x'"
              :title="dvResult.title"
              :description="dvResult.detail"
            />
            <p v-else class="muted">{{ t('files.emptyState') }}</p>
          </div>
        </div>
      </template>
    </UTabs>
  </div>
</template>
