<script setup lang="ts">
import { computed, ref } from 'vue'
import { useVault } from '@/stores/vault'
import {
  signCleartext,
  signDetached,
  verifyCleartext,
  verifyDetached,
} from '@/crypto/core'
import { downloadText } from '@/lib/gnupg'
import { toastError, toastSuccess } from '@/lib/toast'

const vault = useVault()
const mode = ref<'sign' | 'verify'>('sign')
const sigStyle = ref<'cleartext' | 'detached'>('cleartext')

const text = ref('')
const signKey = ref('')
const signPass = ref('')
const output = ref('')

// verify
const vText = ref('')
const vSig = ref('')
const vKey = ref('')
const vResult = ref<{ ok: boolean; detail: string } | null>(null)

const myKeys = computed(() => vault.ownKeys)
const allKeys = computed(() => vault.keys)

function doSign() {
  const sk = vault.keyByFingerprint(signKey.value)?.secretKey
  if (!sk) {
    toastError('Select your secret key')
    return
  }
  if (!text.value) {
    toastError('Nothing to sign')
    return
  }
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
  const pub = vault.keyByFingerprint(vKey.value)?.publicKey
  if (!pub) {
    toastError('Select the signer’s key')
    return
  }
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
    <div class="view-head">
      <h1>Sign &amp; Verify</h1>
      <div class="seg">
        <button :class="{ on: mode === 'sign' }" @click="mode = 'sign'">Sign</button>
        <button :class="{ on: mode === 'verify' }" @click="mode = 'verify'">Verify</button>
      </div>
    </div>

    <div class="seg small-seg">
      <button :class="{ on: sigStyle === 'cleartext' }" @click="sigStyle = 'cleartext'">
        Cleartext
      </button>
      <button :class="{ on: sigStyle === 'detached' }" @click="sigStyle = 'detached'">
        Detached
      </button>
    </div>

    <!-- SIGN -->
    <div v-if="mode === 'sign'" class="pad-grid">
      <div class="pad-col">
        <label>Text</label>
        <textarea v-model="text" rows="12" placeholder="Text to sign…" />
        <label>Sign with</label>
        <select v-model="signKey">
          <option value="">Select your secret key</option>
          <option v-for="k in myKeys" :key="k.fingerprint" :value="k.fingerprint">
            {{ k.info.userIds[0] || k.keyId }}
          </option>
        </select>
        <input v-model="signPass" type="password" placeholder="Key passphrase (if any)" />
        <button class="primary block" @click="doSign">✍️ Sign</button>
      </div>
      <div class="pad-col">
        <label>Signature output</label>
        <textarea :value="output" rows="20" readonly class="mono" />
        <button class="ghost" :disabled="!output" @click="downloadText(output, sigStyle === 'detached' ? 'message.sig.asc' : 'message.asc')">
          Download
        </button>
      </div>
    </div>

    <!-- VERIFY -->
    <div v-else class="pad-grid">
      <div class="pad-col">
        <label>{{ sigStyle === 'cleartext' ? 'Signed message' : 'Original text' }}</label>
        <textarea v-model="vText" rows="10" class="mono" />
        <template v-if="sigStyle === 'detached'">
          <label>Detached signature</label>
          <textarea v-model="vSig" rows="6" class="mono" placeholder="-----BEGIN PGP SIGNATURE-----" />
        </template>
        <label>Signer’s key</label>
        <select v-model="vKey">
          <option value="">Select a key</option>
          <option v-for="k in allKeys" :key="k.fingerprint" :value="k.fingerprint">
            {{ k.info.userIds[0] || k.keyId }}
          </option>
        </select>
        <button class="primary block" @click="doVerify">Verify</button>
      </div>
      <div class="pad-col">
        <label>Result</label>
        <div v-if="vResult" class="result-box" :class="vResult.ok ? 'good' : 'bad'">
          <div class="result-icon">{{ vResult.ok ? '✓' : '✕' }}</div>
          <div>{{ vResult.detail }}</div>
        </div>
        <p v-else class="muted">Run a verification to see the result.</p>
      </div>
    </div>
  </div>
</template>
