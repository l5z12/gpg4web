<script setup lang="ts">
import type { NavigationMenuItem } from '@nuxt/ui'
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'
import { coreVersion } from '@/crypto/core'
import logoDark from '@/assets/logo-horizontal-dark.svg'
import logoLight from '@/assets/logo-horizontal-light.svg'

defineProps<{ open: boolean }>()
const emit = defineEmits<{ navigate: [] }>()
const { t } = useI18n()

const items = computed<NavigationMenuItem[]>(() => [
  { label: t('nav.certificates'), icon: 'i-lucide-key-round', to: '/keys' },
  { label: t('nav.notepad'), icon: 'i-lucide-notebook-pen', to: '/notepad' },
  { label: t('nav.files'), icon: 'i-lucide-file-lock', to: '/files' },
  { label: t('nav.signVerify'), icon: 'i-lucide-signature', to: '/sign' },
  { label: t('nav.console'), icon: 'i-lucide-terminal', to: '/console' },
  { label: t('nav.settings'), icon: 'i-lucide-settings', to: '/settings' },
  { label: t('nav.about'), icon: 'i-lucide-info', to: '/about' },
])
</script>

<template>
  <aside class="sidebar" :class="{ open }">
    <div class="sidebar-brand">
      <img :src="logoDark" class="brand-lockup brand-lockup-dark" alt="gpg4web" />
      <img :src="logoLight" class="brand-lockup brand-lockup-light" alt="gpg4web" />
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
