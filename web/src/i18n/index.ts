// Internationalization (vue-i18n).
//
// Each UI namespace lives in its own file under locales/<locale>/<ns>.ts so the
// English and Simplified-Chinese catalogs stay side by side and easy to extend.
// The active locale is persisted in plain localStorage (it is not sensitive),
// so the choice also applies on the lock screen before the vault is unlocked.

import { createI18n } from 'vue-i18n'

import enApp from './locales/en/app'
import enNav from './locales/en/nav'
import enDialog from './locales/en/dialog'
import enLock from './locales/en/lock'
import enWarning from './locales/en/warning'
import enKeys from './locales/en/keys'
import enKeyDetail from './locales/en/keyDetail'
import enNotepad from './locales/en/notepad'
import enFiles from './locales/en/files'
import enSign from './locales/en/sign'
import enConsole from './locales/en/console'
import enSettings from './locales/en/settings'
import enAbout from './locales/en/about'
import enGenerate from './locales/en/generate'
import enImport from './locales/en/import'

import zhApp from './locales/zh-CN/app'
import zhNav from './locales/zh-CN/nav'
import zhDialog from './locales/zh-CN/dialog'
import zhLock from './locales/zh-CN/lock'
import zhWarning from './locales/zh-CN/warning'
import zhKeys from './locales/zh-CN/keys'
import zhKeyDetail from './locales/zh-CN/keyDetail'
import zhNotepad from './locales/zh-CN/notepad'
import zhFiles from './locales/zh-CN/files'
import zhSign from './locales/zh-CN/sign'
import zhConsole from './locales/zh-CN/console'
import zhSettings from './locales/zh-CN/settings'
import zhAbout from './locales/zh-CN/about'
import zhGenerate from './locales/zh-CN/generate'
import zhImport from './locales/zh-CN/import'

export type Locale = 'en' | 'zh-CN'

export const availableLocales: { value: Locale; label: string }[] = [
  { value: 'en', label: 'English' },
  { value: 'zh-CN', label: '简体中文' },
]

const LS_KEY = 'gpg4web.locale'

function detectLocale(): Locale {
  const saved = localStorage.getItem(LS_KEY)
  if (saved === 'en' || saved === 'zh-CN') return saved
  return navigator.language?.toLowerCase().startsWith('zh') ? 'zh-CN' : 'en'
}

const messages = {
  en: {
    app: enApp,
    nav: enNav,
    dialog: enDialog,
    lock: enLock,
    warning: enWarning,
    keys: enKeys,
    keyDetail: enKeyDetail,
    notepad: enNotepad,
    files: enFiles,
    sign: enSign,
    console: enConsole,
    settings: enSettings,
    about: enAbout,
    generate: enGenerate,
    import: enImport,
  },
  'zh-CN': {
    app: zhApp,
    nav: zhNav,
    dialog: zhDialog,
    lock: zhLock,
    warning: zhWarning,
    keys: zhKeys,
    keyDetail: zhKeyDetail,
    notepad: zhNotepad,
    files: zhFiles,
    sign: zhSign,
    console: zhConsole,
    settings: zhSettings,
    about: zhAbout,
    generate: zhGenerate,
    import: zhImport,
  },
}

export const i18n = createI18n({
  legacy: false,
  locale: detectLocale(),
  fallbackLocale: 'en',
  messages,
})

/** Switch the active locale, persist it, and update the <html lang> attribute. */
export function setLocale(locale: Locale) {
  i18n.global.locale.value = locale
  localStorage.setItem(LS_KEY, locale)
  document.documentElement.setAttribute('lang', locale)
}

/** Apply the persisted/detected locale to the document on startup. */
export function initLocale() {
  document.documentElement.setAttribute('lang', i18n.global.locale.value)
}
