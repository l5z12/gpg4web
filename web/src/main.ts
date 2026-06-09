import { createApp } from 'vue'
import { createPinia } from 'pinia'
import ui from '@nuxt/ui/vue-plugin'
import { addCollection } from '@iconify/vue'
import App from './App.vue'
import { router } from './router'
import { i18n, initLocale } from './i18n'
import lucideIcons from './assets/lucide-icons.json'
import './assets/main.css'

// Register the bundled Lucide subset so icons resolve locally — no runtime
// calls to the Iconify API (keeps the app offline-capable and CSP-friendly).
addCollection(lucideIcons as Parameters<typeof addCollection>[0])

initLocale()

createApp(App).use(createPinia()).use(router).use(ui).use(i18n).mount('#app')
