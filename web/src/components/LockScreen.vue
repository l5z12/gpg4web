<script setup lang="ts">
import { computed, ref } from 'vue'
import { useVault } from '@/stores/vault'
import { toastError, toastSuccess } from '@/lib/toast'

const vault = useVault()
const password = ref('')
const confirm = ref('')
const busy = ref(false)

const isSetup = computed(() => !vault.hasVault)

const strength = computed(() => {
  const p = password.value
  let score = 0
  if (p.length >= 8) score++
  if (p.length >= 12) score++
  if (/[A-Z]/.test(p) && /[a-z]/.test(p)) score++
  if (/\d/.test(p)) score++
  if (/[^A-Za-z0-9]/.test(p)) score++
  return Math.min(score, 4)
})
const strengthLabel = ['Very weak', 'Weak', 'Fair', 'Good', 'Strong']

async function submit() {
  if (busy.value) return
  busy.value = true
  try {
    if (isSetup.value) {
      if (password.value.length < 8) {
        toastError('Master password must be at least 8 characters')
        return
      }
      if (password.value !== confirm.value) {
        toastError('Passwords do not match')
        return
      }
      await vault.createVault(password.value)
      toastSuccess('Vault created and unlocked')
    } else {
      const ok = await vault.unlock(password.value)
      if (!ok) {
        toastError(vault.error ?? 'Unlock failed')
        return
      }
      toastSuccess('Vault unlocked')
    }
    password.value = ''
    confirm.value = ''
  } catch (e) {
    toastError(e instanceof Error ? e.message : String(e))
  } finally {
    busy.value = false
  }
}

function resetVault() {
  if (confirm.value !== 'DELETE' && !window.confirm('This permanently deletes your local vault and all stored keys. Continue?'))
    return
  vault.destroyVault()
  password.value = ''
  confirm.value = ''
  toastSuccess('Vault deleted. You can create a new one.')
}
</script>

<template>
  <div class="lock-screen">
    <div class="lock-card">
      <div class="lock-logo">🔐</div>
      <h1>gpg4web</h1>
      <p class="lock-sub">GnuPG in your browser, powered by Rust + WebAssembly</p>

      <form @submit.prevent="submit">
        <h2>{{ isSetup ? 'Create your vault' : 'Unlock your vault' }}</h2>
        <p class="lock-note">
          Your keyring is stored locally and sealed with a
          <strong>post-quantum</strong> envelope (ML-KEM-768 + AES-256-GCM,
          unlocked by your master password via Argon2id).
        </p>

        <label>Master password</label>
        <input
          v-model="password"
          type="password"
          autocomplete="current-password"
          placeholder="Enter master password"
          autofocus
        />

        <template v-if="isSetup">
          <div class="strength">
            <div
              v-for="i in 4"
              :key="i"
              class="strength-bar"
              :class="{ on: i <= strength }"
            />
          </div>
          <span class="strength-label">{{ strengthLabel[strength] }}</span>

          <label>Confirm password</label>
          <input
            v-model="confirm"
            type="password"
            autocomplete="new-password"
            placeholder="Repeat master password"
          />
          <p class="warn">
            ⚠ There is no recovery. If you forget this password your keys are
            unrecoverable.
          </p>
        </template>

        <button class="primary" type="submit" :disabled="busy">
          {{ busy ? 'Working…' : isSetup ? 'Create vault' : 'Unlock' }}
        </button>
      </form>

      <button v-if="!isSetup" class="link danger-link" @click="resetVault">
        Forgot password? Delete vault and start over
      </button>
    </div>
  </div>
</template>
