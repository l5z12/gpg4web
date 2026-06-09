<script setup lang="ts">
import type { NavigationMenuItem } from '@nuxt/ui'
import { coreVersion } from '@/crypto/core'

defineProps<{ open: boolean }>()
const emit = defineEmits<{ navigate: [] }>()

const items: NavigationMenuItem[] = [
  { label: 'Certificates', icon: 'i-lucide-key-round', to: '/keys' },
  { label: 'Notepad', icon: 'i-lucide-notebook-pen', to: '/notepad' },
  { label: 'Files', icon: 'i-lucide-file-lock', to: '/files' },
  { label: 'Sign / Verify', icon: 'i-lucide-signature', to: '/sign' },
  { label: 'Console', icon: 'i-lucide-terminal', to: '/console' },
  { label: 'Settings', icon: 'i-lucide-settings', to: '/settings' },
  { label: 'About', icon: 'i-lucide-info', to: '/about' },
]
</script>

<template>
  <aside class="sidebar" :class="{ open }">
    <div class="sidebar-brand">
      <span class="brand-mark">🔐</span>
      <div>
        <div class="brand-name">gpg4web</div>
        <div class="brand-tag">Kleopatra, on the web</div>
      </div>
    </div>
    <UNavigationMenu
      orientation="vertical"
      :items="items"
      class="sidebar-nav"
      @click="emit('navigate')"
    />
    <div class="sidebar-foot">
      <a
        class="sidebar-repo"
        href="https://github.com/l5z12/gpg4web"
        target="_blank"
        rel="noopener noreferrer"
      >
        <UIcon name="i-lucide-github" /> l5z12/gpg4web
      </a>
      <div>{{ coreVersion() }} · GPL-3.0</div>
    </div>
  </aside>
</template>
