<script setup lang="ts">
import { computed, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import type { TabsItem } from '@nuxt/ui'
import { useVault } from '@/stores/vault'
import { decrypt, encrypt, signCleartext, verifyCleartext } from '@/crypto/core'
import { downloadText } from '@/lib/gnupg'
import { toastError, toastSuccess } from '@/lib/toast'

const { t } = useI18n()
const vault = useVault()
const tab = ref('signencrypt')

const tabs = computed<TabsItem[]>(() => [
  { label: t('notepad.tabSignEncrypt'), value: 'signencrypt', slot: 'signencrypt', icon: 'i-lucide-lock' },
  { label: t('notepad.tabDecryptVerify'), value: 'decryptverify', slot: 'decryptverify', icon: 'i-lucide-lock-open' },
])

// --- Sign / Encrypt ---
const input = ref('')
const recipients = ref<string[]>([])
const signWith = ref('none')
const signPass = ref('')
const output = ref('')

// --- Decrypt / Verify ---
const cipherIn = ref('')
const decryptKey = ref('')
const decryptPass = ref('')

interface NotepadResult {
  text: string
  encrypted: boolean
  signatures: { label: string; valid: boolean }[]
}
const result = ref<NotepadResult | null>(null)

const allKeyItems = computed(() =>
  vault.keys.map((k) => ({ label: `${k.info.userIds[0] || k.keyId} (${k.keyId.slice(-8)})`, value: k.fingerprint })),
)
const signItems = computed(() => [
  { label: t('notepad.dontSign'), value: 'none' },
  ...vault.ownKeys.map((k) => ({ label: k.info.userIds[0] || k.keyId, value: k.fingerprint })),
])
const myKeyItems = computed(() =>
  vault.ownKeys.map((k) => ({ label: k.info.userIds[0] || k.keyId, value: k.fingerprint })),
)

function doSignEncrypt() {
  if (!input.value) return toastError(t('notepad.nothingToSign'))
  const hasRecipients = recipients.value.length > 0
  const wantSign = signWith.value !== 'none'
  const signer = wantSign ? vault.getSecretKey(signWith.value) : null
  if (wantSign && !signer) return toastError(t('notepad.couldNotUnlock'))

  try {
    if (hasRecipients) {
      const pubs = recipients.value
        .map((f) => vault.keyByFingerprint(f)?.publicKey)
        .filter((x): x is string => !!x)
      output.value = encrypt(input.value, pubs, signer, signPass.value || null, true)
      toastSuccess(signer ? t('notepad.signedEncrypted') : t('notepad.encrypted'))
    } else if (signer) {
      // Sign-only with no recipients → clearsigned message
      // (-----BEGIN PGP SIGNED MESSAGE-----), matching Kleopatra's Notepad.
      output.value = signCleartext(input.value, signer, signPass.value)
      toastSuccess(t('notepad.signed'))
    } else {
      return toastError(t('notepad.chooseRecipients'))
    }
  } catch (e) {
    toastError(e instanceof Error ? e.message : String(e))
  }
}

function doDecryptVerify() {
  const inp = cipherIn.value.trim()
  if (!inp) return toastError(t('notepad.pasteFirst'))

  try {
    if (inp.includes('BEGIN PGP SIGNED MESSAGE')) {
      // Cleartext-signed message: find a key in the ring that validates it.
      if (!vault.keys.length) return toastError(t('notepad.importSignerKey'))
      let text = ''
      let valid = false
      let label = 'unknown signer'
      for (const key of vault.keys) {
        const r = verifyCleartext(inp, key.publicKey)
        text = r.text
        if (r.valid) {
          valid = true
          label = key.info.userIds[0] || key.keyId
          break
        }
      }
      result.value = { text, encrypted: false, signatures: [{ label, valid }] }
      toastSuccess(valid ? t('notepad.validSignature') : t('notepad.signatureNotVerified'))
    } else {
      const sk = decryptKey.value ? vault.getSecretKey(decryptKey.value) : null
      if (!sk) return toastError(t('notepad.selectOwnSecretKey'))
      const d = decrypt(inp, sk, decryptPass.value, vault.keys.map((k) => k.publicKey))
      result.value = {
        text: d.data,
        encrypted: d.wasEncrypted,
        signatures: d.signatures.map((s) => ({ label: s.keyId.slice(-16), valid: s.valid })),
      }
      toastSuccess(t('notepad.decrypted'))
    }
  } catch (e) {
    toastError(e instanceof Error ? e.message : String(e))
  }
}

async function copyOut() {
  await navigator.clipboard.writeText(output.value)
  toastSuccess(t('notepad.copied'))
}

const isClearsign = computed(() => cipherIn.value.includes('BEGIN PGP SIGNED MESSAGE'))
</script>

<template>
  <div class="view">
    <div class="view-head"><h1>{{ t('notepad.title') }}</h1></div>

    <UTabs v-model="tab" :items="tabs" class="w-full">
      <template #signencrypt>
        <div class="pad-grid">
          <div class="pad-col">
            <label>{{ t('notepad.message') }}</label>
            <UTextarea v-model="input" :rows="11" class="w-full" :placeholder="t('notepad.messagePlaceholder')" />

            <label>{{ t('notepad.encryptFor') }}</label>
            <USelect
              v-model="recipients"
              multiple
              :items="allKeyItems"
              :placeholder="t('notepad.noRecipients')"
              class="w-full"
            />

            <label>{{ t('notepad.signAs') }}</label>
            <USelect v-model="signWith" :items="signItems" class="w-full" />
            <UInput
              v-if="signWith !== 'none'"
              v-model="signPass"
              type="password"
              :placeholder="t('notepad.signingPassphrase')"
              class="w-full mt-2"
            />

            <UButton block icon="i-lucide-pen-line" class="mt-4" @click="doSignEncrypt">
              {{ t('notepad.signEncryptBtn') }}
            </UButton>
            <p class="hint">
              {{ t('notepad.signEncryptHint') }}
            </p>
          </div>

          <div class="pad-col">
            <label>{{ t('notepad.output') }}</label>
            <UTextarea :model-value="output" :rows="18" readonly class="w-full mono" :placeholder="t('notepad.resultAppearsHere')" />
            <div class="row mt-2">
              <UButton color="neutral" variant="subtle" :disabled="!output" icon="i-lucide-copy" @click="copyOut">{{ t('notepad.copy') }}</UButton>
              <UButton color="neutral" variant="subtle" :disabled="!output" icon="i-lucide-download" @click="downloadText(output, 'message.asc')">{{ t('notepad.downloadAsc') }}</UButton>
            </div>
          </div>
        </div>
      </template>

      <template #decryptverify>
        <div class="pad-grid">
          <div class="pad-col">
            <label>{{ t('notepad.pgpMessageOrSigned') }}</label>
            <UTextarea v-model="cipherIn" :rows="11" class="w-full mono" placeholder="-----BEGIN PGP MESSAGE----- or -----BEGIN PGP SIGNED MESSAGE-----" />

            <template v-if="!isClearsign">
              <label>{{ t('notepad.decryptWith') }}</label>
              <USelect v-model="decryptKey" :items="myKeyItems" :placeholder="t('notepad.selectSecretKey')" class="w-full" />
              <UInput v-model="decryptPass" type="password" :placeholder="t('notepad.keyPassphrase')" class="w-full mt-2" />
            </template>
            <p v-else class="hint">{{ t('notepad.clearsignHint') }}</p>

            <UButton block icon="i-lucide-lock-open" class="mt-4" @click="doDecryptVerify">
              {{ t('notepad.decryptVerifyBtn') }}
            </UButton>
          </div>

          <div class="pad-col">
            <label>{{ t('notepad.result') }}</label>
            <UTextarea :model-value="result?.text ?? ''" :rows="13" readonly class="w-full" :placeholder="t('notepad.decryptedAppearsHere')" />
            <UCard v-if="result" class="mt-3">
              <div class="kv"><span>{{ t('notepad.encryptedLabel') }}</span><span>{{ result.encrypted ? t('notepad.yes') : t('notepad.no') }}</span></div>
              <template v-if="result.signatures.length">
                <div class="sig-title">{{ t('notepad.signatures') }}</div>
                <div v-for="(s, i) in result.signatures" :key="i" class="sig-row">
                  <UBadge :color="s.valid ? 'success' : 'error'" variant="subtle">
                    {{ s.valid ? t('notepad.validSig') : t('notepad.invalidSig') }}
                  </UBadge>
                  <span class="small">{{ s.label }}</span>
                </div>
              </template>
              <p v-else class="muted small">{{ t('notepad.noSignatures') }}</p>
            </UCard>
          </div>
        </div>
      </template>
    </UTabs>
  </div>
</template>
