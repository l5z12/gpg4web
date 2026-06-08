<script setup lang="ts">
defineProps<{ title: string; wide?: boolean }>()
const emit = defineEmits<{ close: [] }>()
</script>

<template>
  <div class="modal-backdrop" @click.self="emit('close')">
    <div class="modal" :class="{ wide }">
      <header class="modal-head">
        <h2>{{ title }}</h2>
        <button class="icon-btn" aria-label="Close" @click="emit('close')">✕</button>
      </header>
      <div class="modal-body">
        <slot />
      </div>
      <footer class="modal-foot">
        <slot name="footer" />
      </footer>
    </div>
  </div>
</template>
