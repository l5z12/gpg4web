import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import ui from '@nuxt/ui/vite'
import { fileURLToPath, URL } from 'node:url'

// gpg4web is a fully client-side app. The base is relative so it can be hosted
// from any sub-path (GitHub Pages, static buckets, etc.).
export default defineConfig({
  base: './',
  plugins: [
    vue(),
    ui({
      ui: {
        colors: {
          primary: 'blue',
          neutral: 'slate',
        },
      },
    }),
  ],
  resolve: {
    alias: {
      '@': fileURLToPath(new URL('./src', import.meta.url)),
    },
  },
  // The hand-built .wasm is large; let Vite serve it as an asset.
  assetsInclude: ['**/*.wasm'],
  build: {
    target: 'es2022',
    chunkSizeWarningLimit: 6000,
  },
})
