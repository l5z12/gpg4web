import type { KeyInfo } from '@/crypto/core'

/** A key as persisted in the encrypted vault. */
export interface StoredKey {
  /** Stable id (the fingerprint). */
  fingerprint: string
  keyId: string
  /** Armored public key (always present). */
  publicKey: string
  /** Armored secret key, present only for our own key pairs. */
  secretKey?: string
  /** Cached metadata for display, recomputed on import. */
  info: KeyInfo
  /** User-assigned owner trust / favourite flag. */
  trusted?: boolean
  /** ISO timestamp this key was added to the vault. */
  addedAt: string
}

/** Everything we persist inside the post-quantum vault. */
export interface VaultData {
  keys: StoredKey[]
  settings: AppSettings
}

export interface AppSettings {
  defaultAlgorithm: string
  defaultSignKey: string | null
  theme: 'dark' | 'light'
}

export const DEFAULT_SETTINGS: AppSettings = {
  defaultAlgorithm: 'curve25519',
  defaultSignKey: null,
  theme: 'dark',
}
