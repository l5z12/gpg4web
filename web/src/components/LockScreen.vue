<script setup lang="ts">
import { computed, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { useVault } from '@/stores/vault'
import { toastError, toastSuccess } from '@/lib/toast'
import logoUrl from '@/assets/mark.svg'

const { t } = useI18n()
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
const strengthLabel = computed(() => [
  t('lock.strengthVeryWeak'),
  t('lock.strengthWeak'),
  t('lock.strengthFair'),
  t('lock.strengthGood'),
  t('lock.strengthStrong'),
])
// Red → orange → amber → green as the score climbs.
const strengthColors = ['#f87171', '#f87171', '#fb923c', '#fbbf24', '#34d399']
const strengthColor = computed(() => strengthColors[strength.value])

async function submit() {
  if (busy.value) return
  busy.value = true
  try {
    if (isSetup.value) {
      if (password.value.length < 8) {
        toastError(t('lock.passwordTooShort'))
        return
      }
      if (password.value !== confirm.value) {
        toastError(t('lock.passwordsDoNotMatch'))
        return
      }
      await vault.createVault(password.value)
      toastSuccess(t('lock.vaultCreated'))
    } else {
      const ok = await vault.unlock(password.value)
      if (!ok) {
        toastError(vault.error ?? t('lock.unlockFailed'))
        return
      }
      toastSuccess(t('lock.vaultUnlocked'))
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
  if (!window.confirm(t('lock.resetConfirm')))
    return
  vault.destroyVault()
  password.value = ''
  confirm.value = ''
  toastSuccess(t('lock.vaultDeleted'))
}
</script>

<template>
  <div class="lock-screen">
    <UCard class="lock-card">
      <img :src="logoUrl" class="lock-logo" alt="gpg4web" width="76" height="76" />
      <h1>gpg4web</h1>
      <p class="lock-sub">{{ t('lock.tagline') }}</p>

      <h2>{{ isSetup ? t('lock.createVaultHeading') : t('lock.unlockVaultHeading') }}</h2>
      <p class="lock-note">
        {{ t('lock.postQuantumNote') }}
      </p>

      <label>{{ t('lock.masterPassword') }}</label>
      <UInput
        v-model="password"
        type="password"
        icon="i-lucide-lock"
        :placeholder="t('lock.enterPassword')"
        size="lg"
        class="w-full"
        @keyup.enter="submit"
      />

      <template v-if="isSetup">
        <div class="strength">
          <div
            v-for="i in 4"
            :key="i"
            class="strength-bar"
            :class="{ on: i <= strength }"
            :style="i <= strength ? { background: strengthColor } : undefined"
          />
        </div>
        <span class="strength-label" :style="{ color: strengthColor }">
          {{ strengthLabel[strength] }}
        </span>

        <label>{{ t('lock.confirmPassword') }}</label>
        <UInput
          v-model="confirm"
          type="password"
          icon="i-lucide-lock"
          :placeholder="t('lock.repeatPassword')"
          size="lg"
          class="w-full"
          @keyup.enter="submit"
        />
        <p class="warn">
          {{ t('lock.noRecoveryWarning') }}
        </p>
      </template>

      <UButton block size="lg" :loading="busy" class="lock-submit" @click="submit">
        {{ isSetup ? t('lock.createVault') : t('lock.unlock') }}
      </UButton>

      <div v-if="!isSetup" class="lock-reset">
        <UButton variant="link" color="neutral" size="sm" @click="resetVault">
          {{ t('lock.forgotPassword') }}
        </UButton>
      </div>
    </UCard>
  </div>
</template>
