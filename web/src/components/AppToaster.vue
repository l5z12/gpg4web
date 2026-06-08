<script setup lang="ts">
// Captures Nuxt UI's toast API and exposes it to the plain `toast()` helpers.
// Imported explicitly (rather than relying on the Vite plugin's auto-import
// global) so type-checking works on a fresh checkout where the generated
// auto-imports.d.ts doesn't exist yet. Renders nothing; must live inside <UApp>.
import { useToast } from '@nuxt/ui/composables'
import { registerToast } from '@/lib/toast'

const toast = useToast()
registerToast((payload) => toast.add(payload))
</script>

<template><span /></template>
