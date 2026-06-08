<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { useVault } from '@/stores/vault'
import LockScreen from '@/components/LockScreen.vue'
import AppSidebar from '@/components/AppSidebar.vue'
import ToastHost from '@/components/ToastHost.vue'

const vault = useVault()
const bootError = ref<string | null>(null)
const sidebarOpen = ref(false)

onMounted(async () => {
  try {
    await vault.boot()
  } catch (e) {
    bootError.value = String(e)
  }
})
</script>

<template>
  <div class="app-root">
    <div v-if="bootError" class="fatal">
      <h1>Failed to start</h1>
      <pre>{{ bootError }}</pre>
    </div>

    <div v-else-if="!vault.ready" class="splash">
      <div class="splash-logo">🔐</div>
      <p>Loading crypto engine…</p>
    </div>

    <LockScreen v-else-if="!vault.unlocked" />

    <div v-else class="shell">
      <header class="topbar">
        <button class="hamburger" aria-label="Menu" @click="sidebarOpen = !sidebarOpen">☰</button>
        <span class="topbar-title">gpg4web</span>
        <button class="lock-btn" title="Lock vault" @click="vault.lock()">Lock 🔒</button>
      </header>
      <div class="body">
        <AppSidebar :open="sidebarOpen" @navigate="sidebarOpen = false" />
        <div v-if="sidebarOpen" class="scrim" @click="sidebarOpen = false" />
        <main class="content">
          <router-view />
        </main>
      </div>
    </div>

    <ToastHost />
  </div>
</template>
