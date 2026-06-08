<script setup lang="ts">
import { ref } from 'vue'
import { useVault } from '@/stores/vault'
import { toastError, toastSuccess } from '@/lib/toast'

const emit = defineEmits<{ close: [] }>()
const vault = useVault()
const text = ref('')
const open = ref(true)
const fileInput = ref<HTMLInputElement | null>(null)

function splitArmored(input: string): string[] {
  const re = /-----BEGIN PGP [^-]+-----[\s\S]*?-----END PGP [^-]+-----/g
  return input.match(re) ?? []
}

async function onFile(e: Event) {
  const f = (e.target as HTMLInputElement).files?.[0]
  if (f) text.value = await f.text()
}

function doImport() {
  const blocks = splitArmored(text.value)
  if (blocks.length === 0) return toastError('No PGP key blocks found in the input')
  let ok = 0
  for (const block of blocks) {
    try {
      vault.importArmored(block)
      ok++
    } catch (e) {
      toastError(e instanceof Error ? e.message : String(e))
    }
  }
  if (ok > 0) {
    toastSuccess(`Imported ${ok} key${ok === 1 ? '' : 's'}`)
    emit('close')
  }
}
</script>

<template>
  <UModal
    :open="open"
    title="Import keys"
    description="Paste an armored public or secret key (or a bundle), or load a file."
    :ui="{ content: 'sm:max-w-2xl' }"
    @update:open="(v: boolean) => !v && emit('close')"
  >
    <template #body>
      <input ref="fileInput" type="file" accept=".asc,.gpg,.pgp,.key,.txt" class="hidden" @change="onFile" />
      <UButton
        icon="i-lucide-upload"
        color="neutral"
        variant="subtle"
        class="mb-3"
        @click="fileInput?.click()"
      >
        Load file…
      </UButton>
      <UTextarea
        v-model="text"
        :rows="14"
        class="w-full mono"
        placeholder="-----BEGIN PGP PUBLIC KEY BLOCK-----&#10;…"
      />
    </template>

    <template #footer>
      <div class="modal-actions">
        <UButton color="neutral" variant="ghost" @click="emit('close')">Cancel</UButton>
        <UButton :disabled="!text.trim()" icon="i-lucide-download" @click="doImport">Import</UButton>
      </div>
    </template>
  </UModal>
</template>
