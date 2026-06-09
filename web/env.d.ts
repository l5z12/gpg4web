/// <reference types="vite/client" />

interface ImportMetaEnv {
  /** Comma-separated list of official domains (and their subdomains). */
  readonly VITE_OFFICIAL_DOMAINS?: string
}
interface ImportMeta {
  readonly env: ImportMetaEnv
}

declare module '*.vue' {
  import type { DefineComponent } from 'vue'
  const component: DefineComponent<Record<string, unknown>, Record<string, unknown>, unknown>
  export default component
}

declare module '*.wasm?url' {
  const url: string
  export default url
}
