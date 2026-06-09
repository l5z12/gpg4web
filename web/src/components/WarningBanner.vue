<script setup lang="ts">
import { ref } from 'vue'
import { isOfficialDomain, officialDomains } from '@/lib/domain'

const DISMISS_KEY = 'gpg4web.unofficial.dismissed'

const unofficial = !isOfficialDomain()
const host = window.location.hostname || 'this origin'
const dismissed = ref(sessionStorage.getItem(DISMISS_KEY) === '1')

function dismiss() {
  dismissed.value = true
  sessionStorage.setItem(DISMISS_KEY, '1')
}
</script>

<template>
  <div v-if="unofficial && !dismissed" class="warn-banner" role="alert">
    <UIcon name="i-lucide-triangle-alert" class="warn-banner-icon" />
    <span class="warn-banner-text">
      <strong>Unofficial deployment.</strong>
      You're running gpg4web on <code>{{ host }}</code>, not an official
      {{ officialDomains.join(' / ') }} domain. This copy may have been modified —
      verify the source before entering your master password or secret keys.
    </span>
    <UButton
      icon="i-lucide-x"
      color="neutral"
      variant="ghost"
      size="xs"
      aria-label="Dismiss warning"
      class="warn-banner-close"
      @click="dismiss"
    />
  </div>
</template>
