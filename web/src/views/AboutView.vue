<script setup lang="ts">
import { useI18n } from 'vue-i18n'
import { coreVersion } from '@/crypto/core'

const { t } = useI18n()
</script>

<template>
  <div class="view">
    <div class="view-head"><h1>{{ t('about.title') }}</h1></div>

    <UCard class="panel">
      <p>
        {{ t('about.intro') }}
      </p>
      <div class="kv"><span>{{ t('about.cryptoCore') }}</span><span class="mono">{{ coreVersion() }}</span></div>
    </UCard>

    <UCard class="panel">
      <template #header><span>{{ t('about.features') }}</span></template>
      <ul class="feature-list">
        <li>{{ t('about.feature1') }}</li>
        <li>{{ t('about.feature2') }}</li>
        <li>{{ t('about.feature3') }}</li>
        <li>{{ t('about.feature4') }}</li>
        <li>{{ t('about.feature5') }}</li>
        <li>{{ t('about.feature6') }}</li>
        <li>{{ t('about.feature7') }}</li>
      </ul>
    </UCard>

    <UCard class="panel">
      <template #header><span>{{ t('about.pqVault') }}</span></template>
      <p>{{ t('about.pqVaultIntro') }}</p>
      <ul class="feature-list">
        <li>{{ t('about.pqVault1') }}</li>
        <li>{{ t('about.pqVault2') }}</li>
        <li>{{ t('about.pqVault3') }}</li>
      </ul>
      <p class="hint">
        {{ t('about.pqVaultHint') }}
      </p>
    </UCard>

    <UCard class="panel">
      <template #header><span>{{ t('about.sourceLicense') }}</span></template>
      <p>
        {{ t('about.sourceLicenseBody') }}
      </p>
      <div class="row mt-3">
        <UButton
          icon="i-lucide-github"
          color="neutral"
          variant="subtle"
          to="https://github.com/l5z12/gpg4web"
          target="_blank"
          rel="noopener noreferrer"
        >
          github.com/l5z12/gpg4web
        </UButton>
        <UButton
          icon="i-lucide-scale"
          color="neutral"
          variant="subtle"
          to="https://www.gnu.org/licenses/gpl-3.0.html"
          target="_blank"
          rel="noopener noreferrer"
        >
          GPL-3.0-or-later
        </UButton>
      </div>
    </UCard>

    <UCard class="panel">
      <template #header><span>{{ t('about.builtWith') }}</span></template>
      <p class="muted">rPGP · ml-kem · aes-gcm · argon2 · wasm-bindgen · Vue 3 · Nuxt UI · Vite · Pinia</p>
    </UCard>
  </div>
</template>
