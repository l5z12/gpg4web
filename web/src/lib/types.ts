import type { KeyInfo, VaultEnvelope } from '@/crypto/core'

/** A key as persisted in the encrypted vault. */
export interface StoredKey {
  /** Stable id (the fingerprint). */
  fingerprint: string
  keyId: string
  /** Armored public key (always present, not sensitive). */
  publicKey: string
  /**
   * The armored secret key, kept individually post-quantum-encrypted even
   * while the vault is unlocked. It is only decrypted on demand for the
   * specific key being used, so unused secret keys never sit in plaintext in
   * memory. Present only for our own key pairs.
   */
  secretKeyEnc?: VaultEnvelope
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
  /** Lock the vault after this many minutes of inactivity (0 = never). */
  autoLockMinutes: number
}

export const DEFAULT_SETTINGS: AppSettings = {
  defaultAlgorithm: 'curve25519',
  defaultSignKey: null,
  theme: 'dark',
  autoLockMinutes: 15,
}
