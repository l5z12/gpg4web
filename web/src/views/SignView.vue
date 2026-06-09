<script setup lang="ts">
import { computed, ref } from 'vue'
import type { TabsItem } from '@nuxt/ui'
import { useVault } from '@/stores/vault'
import { signCleartext, signDetached, verifyCleartext, verifyDetached } from '@/crypto/core'
import { downloadText } from '@/lib/gnupg'
import { toastError, toastSuccess } from '@/lib/toast'

const vault = useVault()
const sigStyle = ref<'cleartext' | 'detached'>('cleartext')
const styles = [
  { key: 'cleartext', label: 'Cleartext' },
  { key: 'detached', label: 'Detached' },
] as const

const tabs: TabsItem[] = [
  { label: 'Sign', value: 'sign', slot: 'sign', icon: 'i-lucide-signature' },
  { label: 'Verify', value: 'verify', slot: 'verify', icon: 'i-lucide-badge-check' },
]
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
  if (!sk) return toastError('Select your secret key')
  if (!text.value) return toastError('Nothing to sign')
  try {
    output.value =
      sigStyle.value === 'cleartext'
        ? signCleartext(text.value, sk, signPass.value)
        : signDetached(text.value, sk, signPass.value)
    toastSuccess('Signed')
  } catch (e) {
    toastError(e instanceof Error ? e.message : String(e))
  }
}

function doVerify() {
  const pub = vKey.value ? vault.keyByFingerprint(vKey.value)?.publicKey : undefined
  if (!pub) return toastError('Select the signer’s key')
  try {
    if (sigStyle.value === 'cleartext') {
      const r = verifyCleartext(vText.value, pub)
      vResult.value = { ok: r.valid, detail: r.valid ? 'Valid signature' : 'Invalid signature' }
    } else {
      const ok = verifyDetached(vText.value, vSig.value, pub)
      vResult.value = { ok, detail: ok ? 'Valid signature' : 'Invalid or mismatched signature' }
    }
  } catch (e) {
    toastError(e instanceof Error ? e.message : String(e))
  }
}
</script>

<template>
  <div class="view">
    <div class="view-head"><h1>Sign &amp; Verify</h1></div>

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
            <label>Text</label>
            <UTextarea v-model="text" :rows="11" class="w-full" placeholder="Text to sign…" />
            <label>Sign with</label>
            <USelect v-model="signKey" :items="myKeyItems" placeholder="Select your secret key" class="w-full" />
            <UInput v-model="signPass" type="password" placeholder="Key passphrase (if any)" class="w-full mt-2" />
            <UButton block icon="i-lucide-signature" class="mt-4" @click="doSign">Sign</UButton>
          </div>
          <div class="pad-col">
            <label>Signature output</label>
            <UTextarea :model-value="output" :rows="18" readonly class="w-full mono" />
            <UButton
              color="neutral"
              variant="subtle"
              :disabled="!output"
              icon="i-lucide-download"
              class="mt-2"
              @click="downloadText(output, sigStyle === 'detached' ? 'message.sig.asc' : 'message.asc')"
            >
              Download
            </UButton>
          </div>
        </div>
      </template>

      <template #verify>
        <div class="pad-grid">
          <div class="pad-col">
            <label>{{ sigStyle === 'cleartext' ? 'Signed message' : 'Original text' }}</label>
            <UTextarea v-model="vText" :rows="9" class="w-full mono" />
            <template v-if="sigStyle === 'detached'">
              <label>Detached signature</label>
              <UTextarea v-model="vSig" :rows="6" class="w-full mono" placeholder="-----BEGIN PGP SIGNATURE-----" />
            </template>
            <label>Signer’s key</label>
            <USelect v-model="vKey" :items="allKeyItems" placeholder="Select a key" class="w-full" />
            <UButton block icon="i-lucide-badge-check" class="mt-4" @click="doVerify">Verify</UButton>
          </div>
          <div class="pad-col">
            <UAlert
              v-if="vResult"
              :color="vResult.ok ? 'success' : 'error'"
              :icon="vResult.ok ? 'i-lucide-circle-check' : 'i-lucide-circle-x'"
              :title="vResult.detail"
              :description="vResult.ok ? 'The signature matches this key.' : 'Do not trust this content.'"
            />
            <p v-else class="muted">Run a verification to see the result.</p>
          </div>
        </div>
      </template>
    </UTabs>
  </div>
</template>
