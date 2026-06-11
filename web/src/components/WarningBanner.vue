<script setup lang="ts">
import { ref } from 'vue'
// I18nT is imported locally (not globally registered) because __VUE_I18N_FULL_INSTALL__
// is off — this is the only component that needs vue-i18n's interpolation component.
import { useI18n, I18nT } from 'vue-i18n'
import { isOfficialDomain, officialDomains } from '@/lib/domain'

const { t } = useI18n()

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
      <strong>{{ t('warning.title') }}</strong>
      <I18nT keypath="warning.body" tag="span" scope="global">
        <template #host><code>{{ host }}</code></template>
        <template #domains>{{ officialDomains.join(' / ') }}</template>
      </I18nT>
    </span>
    <UButton
      icon="i-lucide-x"
      color="neutral"
      variant="ghost"
      size="xs"
      :aria-label="t('warning.dismiss')"
      class="warn-banner-close"
      @click="dismiss"
    />
  </div>
</template>
