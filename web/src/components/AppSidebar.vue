<script setup lang="ts">
import { coreVersion } from '@/crypto/core'

defineProps<{ open: boolean }>()
const emit = defineEmits<{ navigate: [] }>()

const links = [
  { to: '/keys', label: 'Certificates', icon: '🗝️' },
  { to: '/notepad', label: 'Notepad', icon: '📝' },
  { to: '/sign', label: 'Sign / Verify', icon: '✍️' },
  { to: '/settings', label: 'Settings', icon: '⚙️' },
  { to: '/about', label: 'About', icon: 'ℹ️' },
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
    <nav>
      <router-link
        v-for="l in links"
        :key="l.to"
        :to="l.to"
        class="nav-item"
        active-class="active"
        @click="emit('navigate')"
      >
        <span class="nav-icon">{{ l.icon }}</span>
        <span>{{ l.label }}</span>
      </router-link>
    </nav>
    <div class="sidebar-foot">{{ coreVersion() }}</div>
  </aside>
</template>
