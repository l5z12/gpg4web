<script setup lang="ts">
// Captures Nuxt UI's toast API and exposes it to the plain `toast()` helpers.
// `useToast` is auto-imported by the Nuxt UI Vite plugin (typed via the
// generated auto-imports.d.ts). Renders nothing; must live inside <UApp>.
import { registerToast } from '@/lib/toast'

const toast = useToast()
registerToast((payload) => toast.add(payload))
</script>

<template><span /></template>
