// Internationalization (vue-i18n).
//
// Catalogs live in locales/<locale>.json and are pre-compiled into message
// functions at build time by @intlify/unplugin-vue-i18n — so the browser ships
// no runtime message compiler. Each locale is a separate code-split chunk and
// is fetched only when it becomes active, so the first paint downloads just one
// language's strings (not every translation).
//
// The active locale is persisted in plain localStorage (it is not sensitive),
// so the choice also applies on the lock screen before the vault is unlocked.

import { createI18n } from 'vue-i18n'

export type Locale = 'en' | 'zh-CN'

export const availableLocales: { value: Locale; label: string }[] = [
  { value: 'en', label: 'English' },
  { value: 'zh-CN', label: '简体中文' },
]

// Static specifiers keep each catalog a distinct, pre-compiled chunk that Vite
// can resolve and load on demand.
const loaders: Record<Locale, () => Promise<{ default: Record<string, unknown> }>> = {
  en: () => import('./locales/en.json'),
  'zh-CN': () => import('./locales/zh-CN.json'),
}

const LS_KEY = 'gpg4web.locale'

function detectLocale(): Locale {
  const saved = localStorage.getItem(LS_KEY)
  if (saved === 'en' || saved === 'zh-CN') return saved
  return navigator.language?.toLowerCase().startsWith('zh') ? 'zh-CN' : 'en'
}

export const i18n = createI18n({
  legacy: false,
  locale: detectLocale(),
  fallbackLocale: 'en',
  // Messages are attached lazily by loadLocaleMessages() so only the active
  // language's catalog is downloaded.
  messages: {},
})

const loaded = new Set<Locale>()

/** Fetch and install a locale's pre-compiled catalog (no-op if already loaded). */
export async function loadLocaleMessages(locale: Locale): Promise<void> {
  if (loaded.has(locale)) return
  const mod = await loaders[locale]()
  i18n.global.setLocaleMessage(locale, mod.default as never)
  loaded.add(locale)
}

/** Switch the active locale, persist it, and update the <html lang> attribute. */
export async function setLocale(locale: Locale): Promise<void> {
  await loadLocaleMessages(locale)
  i18n.global.locale.value = locale
  localStorage.setItem(LS_KEY, locale)
  document.documentElement.setAttribute('lang', locale)
}

/**
 * Load the active locale's catalog and apply it to the document. Awaited before
 * the app mounts so the first render has its strings. The English fallback is
 * fetched in the background (non-blocking) for non-English users so the rare
 * missing key still resolves.
 */
export async function initLocale(): Promise<void> {
  const locale = i18n.global.locale.value as Locale
  await loadLocaleMessages(locale)
  document.documentElement.setAttribute('lang', locale)
  if (locale !== 'en') void loadLocaleMessages('en')
}
