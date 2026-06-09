<script setup lang="ts">
import { ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { registerConfirm, type ConfirmOptions } from '@/lib/confirm'

const { t } = useI18n()

const open = ref(false)
const opts = ref<ConfirmOptions>({ title: '', message: '' })
let resolver: ((v: boolean) => void) | null = null

registerConfirm(
  (o) =>
    new Promise<boolean>((resolve) => {
      opts.value = o
      resolver = resolve
      open.value = true
    }),
)

function settle(result: boolean) {
  open.value = false
  const r = resolver
  resolver = null
  r?.(result)
}

// Esc / overlay close → treat as Cancel (the non-destructive choice).
function onOpenChange(v: boolean) {
  if (!v) settle(false)
}
</script>

<template>
  <!-- No header close button, so the Cancel button is the first focusable
       element — the modal autofocuses it (the non-destructive option). -->
  <UModal :open="open" :title="opts.title" :close="false" :dismissible="true" @update:open="onOpenChange">
    <template #body>
      <p class="confirm-message">{{ opts.message }}</p>
    </template>
    <template #footer>
      <div class="modal-actions">
        <UButton color="neutral" variant="ghost" autofocus @click="settle(false)">
          {{ opts.cancelLabel || t('dialog.cancel') }}
        </UButton>
        <UButton :color="opts.danger ? 'error' : 'primary'" @click="settle(true)">
          {{ opts.confirmLabel || t('dialog.confirm') }}
        </UButton>
      </div>
    </template>
  </UModal>
</template>

<style scoped>
.confirm-message {
  white-space: pre-wrap;
  line-height: 1.55;
}
</style>
