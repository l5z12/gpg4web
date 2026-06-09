<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { useVault } from '@/stores/vault'
import { useAutoLock } from '@/composables/useAutoLock'
import { toast } from '@/lib/toast'
import LockScreen from '@/components/LockScreen.vue'
import AppSidebar from '@/components/AppSidebar.vue'
import AppToaster from '@/components/AppToaster.vue'
import WarningBanner from '@/components/WarningBanner.vue'

const vault = useVault()
const { t } = useI18n()
const bootError = ref<string | null>(null)
const sidebarOpen = ref(false)

// Lock the vault after a period of inactivity (configurable in Settings).
const { reset: resetIdle } = useAutoLock({
  isUnlocked: () => vault.unlocked,
  getMinutes: () => vault.settings.autoLockMinutes ?? 15,
  onLock: () => {
    vault.lock()
    toast(t('app.lockedInactivity'), 'info')
  },
})
// Start the idle window fresh whenever the vault is unlocked.
watch(
  () => vault.unlocked,
  (unlocked) => {
    if (unlocked) resetIdle()
  },
)

// Effective theme: follows the unlocked vault's setting, dark otherwise.
// Nuxt UI keys its tokens off the `.dark` class on <html>.
const isLight = computed(() => vault.unlocked && vault.settings.theme === 'light')
watch(
  isLight,
  (light) => document.documentElement.classList.toggle('dark', !light),
  { immediate: true },
)

onMounted(async () => {
  try {
    await vault.boot()
  } catch (e) {
    bootError.value = String(e)
  }
})
</script>

<template>
  <UApp>
    <AppToaster />

    <div class="app-root">
      <WarningBanner />

      <div class="app-main">
        <div v-if="bootError" class="fatal">
          <h1>{{ t('app.failedToStart') }}</h1>
          <pre>{{ bootError }}</pre>
        </div>

        <div v-else-if="!vault.ready" class="splash">
          <UIcon name="i-lucide-loader-circle" class="size-8 animate-spin" />
          <p>{{ t('app.loadingEngine') }}</p>
        </div>

        <LockScreen v-else-if="!vault.unlocked" />

        <div v-else class="shell">
        <header class="topbar">
          <UButton
            icon="i-lucide-menu"
            color="neutral"
            variant="ghost"
            :aria-label="t('app.menu')"
            @click="sidebarOpen = !sidebarOpen"
          />
          <span class="topbar-title">gpg4web</span>
          <UButton
            icon="i-lucide-lock"
            color="neutral"
            variant="soft"
            size="sm"
            :label="t('app.lock')"
            @click="vault.lock()"
          />
        </header>
        <div class="body">
          <AppSidebar :open="sidebarOpen" @navigate="sidebarOpen = false" />
          <div v-if="sidebarOpen" class="scrim" @click="sidebarOpen = false" />
          <main class="content">
            <router-view />
          </main>
        </div>
        </div>
      </div>
    </div>
  </UApp>
</template>
