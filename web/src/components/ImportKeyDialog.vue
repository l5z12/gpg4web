<script setup lang="ts">
import { ref } from 'vue'
import AppModal from './AppModal.vue'
import { useVault } from '@/stores/vault'
import { toastError, toastSuccess } from '@/lib/toast'

const emit = defineEmits<{ close: []; imported: [] }>()
const vault = useVault()
const text = ref('')

function splitArmored(input: string): string[] {
  // Split a bundle into individual armored blocks.
  const re = /-----BEGIN PGP [^-]+-----[\s\S]*?-----END PGP [^-]+-----/g
  return input.match(re) ?? []
}

async function onFile(e: Event) {
  const input = e.target as HTMLInputElement
  const file = input.files?.[0]
  if (!file) return
  text.value = await file.text()
}

function doImport() {
  const blocks = splitArmored(text.value)
  if (blocks.length === 0) {
    toastError('No PGP key blocks found in the input')
    return
  }
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
    emit('imported')
    emit('close')
  }
}
</script>

<template>
  <AppModal title="Import keys" wide @close="emit('close')">
    <p class="hint">Paste an armored public or secret key (or a bundle of several), or load a file.</p>
    <input type="file" accept=".asc,.gpg,.pgp,.key,.txt" @change="onFile" />
    <textarea
      v-model="text"
      class="mono"
      rows="14"
      placeholder="-----BEGIN PGP PUBLIC KEY BLOCK-----&#10;…"
    />
    <template #footer>
      <button class="ghost" @click="emit('close')">Cancel</button>
      <button class="primary" :disabled="!text.trim()" @click="doImport">Import</button>
    </template>
  </AppModal>
</template>
