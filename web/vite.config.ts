import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import ui from '@nuxt/ui/vite'
import vueI18n from '@intlify/unplugin-vue-i18n/vite'
import { fileURLToPath, URL } from 'node:url'

// gpg4web is a fully client-side app. The base is relative so it can be hosted
// from any sub-path (GitHub Pages, static buckets, etc.).
export default defineConfig({
  base: './',
  // Compile-time flags: strip vue-i18n's legacy (Options) API and prod devtools
  // hooks from the browser bundle — we only use the Composition API.
  define: {
    __VUE_I18N_FULL_INSTALL__: false,
    __VUE_I18N_LEGACY_API__: false,
    __INTLIFY_PROD_DEVTOOLS__: false,
  },
  plugins: [
    vue(),
    // Pre-compile the locale catalogs (src/i18n/locales/*.json) into message
    // functions at build time so the browser never ships vue-i18n's runtime
    // message compiler. `runtimeOnly` aliases vue-i18n to its compiler-free
    // build; the catalogs are code-split and loaded one locale at a time.
    vueI18n({
      include: [fileURLToPath(new URL('./src/i18n/locales/**', import.meta.url))],
      runtimeOnly: true,
      compositionOnly: true,
      fullInstall: false,
      strictMessage: false,
      escapeHtml: false,
    }),
    ui({
      // Fluent-style palette: a pure neutral grey base + blue accent. The exact
      // colour ramps are applied via CSS variables in src/assets/styles.css
      // (overriding --ui-color-neutral-* / --ui-color-primary-*).
      ui: {
        colors: {
          primary: 'blue',
          neutral: 'neutral',
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
