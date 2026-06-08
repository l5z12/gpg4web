<script setup lang="ts">
import { useToasts, dismiss } from '@/lib/toast'
const state = useToasts()
</script>

<template>
  <div class="toast-host">
    <transition-group name="toast">
      <div
        v-for="t in state.toasts"
        :key="t.id"
        class="toast"
        :class="`toast-${t.kind}`"
        @click="dismiss(t.id)"
      >
        <span class="toast-icon">
          {{ t.kind === 'success' ? '✓' : t.kind === 'error' ? '✕' : 'ℹ' }}
        </span>
        <span class="toast-msg">{{ t.message }}</span>
      </div>
    </transition-group>
  </div>
</template>
