<script setup lang="ts">
import { computed, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import type { TabsItem } from '@nuxt/ui'
import { useVault } from '@/stores/vault'
import { signCleartext, signDetached, verifyCleartext, verifyDetached } from '@/crypto/core'
import { downloadText } from '@/lib/gnupg'
import { toastError, toastSuccess } from '@/lib/toast'

const { t } = useI18n()
const vault = useVault()
const sigStyle = ref<'cleartext' | 'detached'>('cleartext')
const styles = computed<{ key: 'cleartext' | 'detached'; label: string }[]>(() => [
  { key: 'cleartext', label: t('sign.cleartext') },
  { key: 'detached', label: t('sign.detached') },
])

const tabs = computed<TabsItem[]>(() => [
  { label: t('sign.tabSign'), value: 'sign', slot: 'sign', icon: 'i-lucide-signature' },
  { label: t('sign.tabVerify'), value: 'verify', slot: 'verify', icon: 'i-lucide-badge-check' },
])
const tab = ref('sign')

const text = ref('')
const signKey = ref('')
const signPass = ref('')
const output = ref('')

const vText = ref('')
const vSig = ref('')
const vKey = ref('')
const vResult = ref<{ ok: boolean; detail: string } | null>(null)

const myKeyItems = computed(() =>
  vault.ownKeys.map((k) => ({ label: k.info.userIds[0] || k.keyId, value: k.fingerprint })),
)
const allKeyItems = computed(() =>
  vault.keys.map((k) => ({ label: k.info.userIds[0] || k.keyId, value: k.fingerprint })),
)

function doSign() {
  const sk = signKey.value ? vault.getSecretKey(signKey.value) : null
  if (!sk) return toastError(t('sign.selectSecretKey'))
  if (!text.value) return toastError(t('sign.nothingToSign'))
  try {
    output.value =
      sigStyle.value === 'cleartext'
        ? signCleartext(text.value, sk, signPass.value)
        : signDetached(text.value, sk, signPass.value)
    toastSuccess(t('sign.signed'))
  } catch (e) {
    toastError(e instanceof Error ? e.message : String(e))
  }
}

function doVerify() {
  const pub = vKey.value ? vault.keyByFingerprint(vKey.value)?.publicKey : undefined
  if (!pub) return toastError(t('sign.selectSignersKey'))
  try {
    if (sigStyle.value === 'cleartext') {
      const r = verifyCleartext(vText.value, pub)
      vResult.value = {
        ok: r.valid,
        detail: r.valid ? t('sign.validSignature') : t('sign.invalidSignature'),
      }
    } else {
      const ok = verifyDetached(vText.value, vSig.value, pub)
      vResult.value = {
        ok,
        detail: ok ? t('sign.validSignature') : t('sign.invalidOrMismatched'),
      }
    }
  } catch (e) {
    toastError(e instanceof Error ? e.message : String(e))
  }
}
</script>

<template>
  <div class="view">
    <div class="view-head"><h1>{{ t('sign.title') }}</h1></div>

    <UButtonGroup class="mb-4">
      <UButton
        v-for="s in styles"
        :key="s.key"
        :color="sigStyle === s.key ? 'primary' : 'neutral'"
        :variant="sigStyle === s.key ? 'solid' : 'outline'"
        @click="sigStyle = s.key"
      >
        {{ s.label }}
      </UButton>
    </UButtonGroup>

    <UTabs v-model="tab" :items="tabs" class="w-full">
      <template #sign>
        <div class="pad-grid">
          <div class="pad-col">
            <label>{{ t('sign.text') }}</label>
            <UTextarea v-model="text" :rows="11" class="w-full" :placeholder="t('sign.textToSignPlaceholder')" />
            <label>{{ t('sign.signWith') }}</label>
            <USelect v-model="signKey" :items="myKeyItems" :placeholder="t('sign.selectSecretKeyPlaceholder')" class="w-full" />
            <UInput v-model="signPass" type="password" :placeholder="t('sign.keyPassphrasePlaceholder')" class="w-full mt-2" />
            <UButton block icon="i-lucide-signature" class="mt-4" @click="doSign">{{ t('sign.signButton') }}</UButton>
          </div>
          <div class="pad-col">
            <label>{{ t('sign.signatureOutput') }}</label>
            <UTextarea :model-value="output" :rows="18" readonly class="w-full mono" />
            <UButton
              color="neutral"
              variant="subtle"
              :disabled="!output"
              icon="i-lucide-download"
              class="mt-2"
              @click="downloadText(output, sigStyle === 'detached' ? 'message.sig.asc' : 'message.asc')"
            >
              {{ t('sign.download') }}
            </UButton>
          </div>
        </div>
      </template>

      <template #verify>
        <div class="pad-grid">
          <div class="pad-col">
            <label>{{ sigStyle === 'cleartext' ? t('sign.signedMessage') : t('sign.originalText') }}</label>
            <UTextarea v-model="vText" :rows="9" class="w-full mono" />
            <template v-if="sigStyle === 'detached'">
              <label>{{ t('sign.detachedSignature') }}</label>
              <UTextarea v-model="vSig" :rows="6" class="w-full mono" placeholder="-----BEGIN PGP SIGNATURE-----" />
            </template>
            <label>{{ t('sign.signersKey') }}</label>
            <USelect v-model="vKey" :items="allKeyItems" :placeholder="t('sign.selectKeyPlaceholder')" class="w-full" />
            <UButton block icon="i-lucide-badge-check" class="mt-4" @click="doVerify">{{ t('sign.verifyButton') }}</UButton>
          </div>
          <div class="pad-col">
            <UAlert
              v-if="vResult"
              :color="vResult.ok ? 'success' : 'error'"
              :icon="vResult.ok ? 'i-lucide-circle-check' : 'i-lucide-circle-x'"
              :title="vResult.detail"
              :description="vResult.ok ? t('sign.signatureMatches') : t('sign.doNotTrust')"
            />
            <p v-else class="muted">{{ t('sign.emptyState') }}</p>
          </div>
        </div>
      </template>
    </UTabs>
  </div>
</template>
