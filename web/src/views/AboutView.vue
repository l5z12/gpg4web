<script setup lang="ts">
// This view is intentionally component-free: the content is static markup, so
// it renders without instantiating any Nuxt UI components. The only runtime
// bits are unavoidable — the i18n strings (the active language is chosen at
// runtime) and coreVersion() (read from the WASM build).
import { useI18n } from 'vue-i18n'
import { coreVersion } from '@/crypto/core'

const { t } = useI18n()
</script>

<template>
  <div class="view">
    <div class="view-head"><h1>{{ t('about.title') }}</h1></div>

    <section class="about-card">
      <p class="lead">{{ t('about.intro') }}</p>
      <div class="kv"><span>{{ t('about.cryptoCore') }}</span><span class="mono">{{ coreVersion() }}</span></div>
    </section>

    <section class="about-card">
      <h2 class="card-head">{{ t('about.features') }}</h2>
      <ul class="feature-list">
        <li>{{ t('about.feature1') }}</li>
        <li>{{ t('about.feature2') }}</li>
        <li>{{ t('about.feature3') }}</li>
        <li>{{ t('about.feature4') }}</li>
        <li>{{ t('about.feature5') }}</li>
        <li>{{ t('about.feature6') }}</li>
        <li>{{ t('about.feature7') }}</li>
      </ul>
    </section>

    <section class="about-card">
      <h2 class="card-head">{{ t('about.pqVault') }}</h2>
      <p>{{ t('about.pqVaultIntro') }}</p>
      <ul class="feature-list">
        <li>{{ t('about.pqVault1') }}</li>
        <li>{{ t('about.pqVault2') }}</li>
        <li>{{ t('about.pqVault3') }}</li>
      </ul>
      <p class="hint">{{ t('about.pqVaultHint') }}</p>
    </section>

    <section class="about-card">
      <h2 class="card-head">{{ t('about.sourceLicense') }}</h2>
      <p>{{ t('about.sourceLicenseBody') }}</p>
      <div class="row mt-3">
        <a
          class="link-btn"
          href="https://github.com/l5z12/gpg4web"
          target="_blank"
          rel="noopener noreferrer"
        >
          <!-- lucide: github -->
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
            <path d="M15 22v-4a4.8 4.8 0 0 0-1-3.5c3 0 6-2 6-5.5.08-1.25-.27-2.48-1-3.5.28-1.15.28-2.35 0-3.5 0 0-1 0-3 1.5-2.64-.5-5.36-.5-8 0C4 2 3 2 3 2c-.3 1.15-.3 2.35 0 3.5A5.403 5.403 0 0 0 2 9c0 3.5 3 5.5 6 5.5-.39.49-.68 1.05-.85 1.65-.17.6-.22 1.23-.15 1.85v4"/>
            <path d="M9 18c-4.51 2-5-2-7-2"/>
          </svg>
          github.com/l5z12/gpg4web
        </a>
        <a
          class="link-btn"
          href="https://www.gnu.org/licenses/gpl-3.0.html"
          target="_blank"
          rel="noopener noreferrer"
        >
          <!-- lucide: scale -->
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
            <path d="m16 16 3-8 3 8c-.87.65-1.92 1-3 1s-2.13-.35-3-1Z"/>
            <path d="m2 16 3-8 3 8c-.87.65-1.92 1-3 1s-2.13-.35-3-1Z"/>
            <path d="M7 21h10"/>
            <path d="M12 3v18"/>
            <path d="M3 7h2c2 0 5-1 7-2 2 1 5 2 7 2h2"/>
          </svg>
          GPL-3.0-or-later
        </a>
      </div>
    </section>

    <section class="about-card">
      <h2 class="card-head">{{ t('about.builtWith') }}</h2>
      <p class="muted">rPGP · ml-kem · aes-gcm · argon2 · wasm-bindgen · Vue 3 · Nuxt UI · Vite · Pinia</p>
    </section>
  </div>
</template>

<style scoped>
/* Self-contained card chrome so this view needs no Nuxt UI component. Mirrors
   the elevated-surface tokens used elsewhere, so it follows light/dark. */
.about-card {
  background: var(--ui-bg-elevated);
  border: 1px solid var(--ui-border);
  border-radius: 10px;
  padding: 16px 18px;
  margin-bottom: 18px;
}
.card-head {
  margin: 0 0 10px;
  font-size: 0.9rem;
  font-weight: 600;
}
.lead {
  margin-top: 0;
}
.link-btn {
  display: inline-flex;
  align-items: center;
  gap: 7px;
  padding: 6px 12px;
  border-radius: 7px;
  border: 1px solid var(--ui-border);
  background: var(--ui-bg-elevated);
  color: var(--ui-text);
  text-decoration: none;
  font-size: 0.85rem;
  font-weight: 500;
  transition: background 0.15s, border-color 0.15s;
}
.link-btn:hover {
  background: var(--ui-bg-muted);
  border-color: var(--ui-border-accented, var(--ui-border));
}
.link-btn svg {
  width: 16px;
  height: 16px;
  flex-shrink: 0;
}
</style>
