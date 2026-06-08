import { defineStore } from 'pinia'
import {
  initCrypto,
  inspectKey,
  extractPublicKey,
  vaultCreate,
  vaultDecrypt,
  vaultEncrypt,
  vaultVerifyPassword,
  type VaultEnvelope,
  type VaultIdentity,
} from '@/crypto/core'
import { DEFAULT_SETTINGS, type AppSettings, type StoredKey, type VaultData } from '@/lib/types'

const ID_KEY = 'gpg4web.vault.identity'
const ENV_KEY = 'gpg4web.vault.envelope'

function loadIdentity(): VaultIdentity | null {
  const raw = localStorage.getItem(ID_KEY)
  return raw ? (JSON.parse(raw) as VaultIdentity) : null
}

function loadEnvelope(): VaultEnvelope | null {
  const raw = localStorage.getItem(ENV_KEY)
  return raw ? (JSON.parse(raw) as VaultEnvelope) : null
}

interface State {
  initialized: boolean
  ready: boolean
  unlocked: boolean
  hasVault: boolean
  identity: VaultIdentity | null
  data: VaultData | null
  error: string | null
}

function emptyData(): VaultData {
  return { keys: [], settings: { ...DEFAULT_SETTINGS } }
}

export const useVault = defineStore('vault', {
  state: (): State => ({
    initialized: false,
    ready: false,
    unlocked: false,
    hasVault: false,
    identity: null,
    data: null,
    error: null,
  }),

  getters: {
    keys: (s): StoredKey[] => s.data?.keys ?? [],
    settings: (s): AppSettings => s.data?.settings ?? { ...DEFAULT_SETTINGS },
    ownKeys: (s): StoredKey[] => (s.data?.keys ?? []).filter((k) => k.secretKey),
    publicOnlyKeys: (s): StoredKey[] => (s.data?.keys ?? []).filter((k) => !k.secretKey),
    keyByFingerprint: (s) => (fpr: string) =>
      (s.data?.keys ?? []).find((k) => k.fingerprint === fpr) ?? null,
  },

  actions: {
    /** One-time WASM init + detect whether a vault already exists. */
    async boot() {
      if (this.initialized) return
      await initCrypto()
      this.identity = loadIdentity()
      this.hasVault = this.identity !== null
      this.ready = true
      this.initialized = true
    },

    /** Create a brand new vault with a master password. */
    async createVault(password: string) {
      await initCrypto()
      const identity = vaultCreate(password)
      this.identity = identity
      this.data = emptyData()
      localStorage.setItem(ID_KEY, JSON.stringify(identity))
      this.persist()
      this.hasVault = true
      this.unlocked = true
      this.error = null
    },

    /** Unlock an existing vault. Returns true on success. */
    async unlock(password: string): Promise<boolean> {
      await initCrypto()
      const identity = this.identity ?? loadIdentity()
      if (!identity) {
        this.error = 'No vault found'
        return false
      }
      if (!vaultVerifyPassword(identity, password)) {
        this.error = 'Incorrect master password'
        return false
      }
      const envelope = loadEnvelope()
      if (!envelope) {
        // Identity exists but no payload yet — treat as empty.
        this.identity = identity
        this.data = emptyData()
        this.persist()
      } else {
        const json = vaultDecrypt(identity, password, envelope)
        this.identity = identity
        this.data = JSON.parse(json) as VaultData
        if (!this.data.settings) this.data.settings = { ...DEFAULT_SETTINGS }
      }
      this.unlocked = true
      this.error = null
      return true
    },

    /** Lock the vault, wiping decrypted data from memory. */
    lock() {
      this.unlocked = false
      this.data = null
    },

    /** Encrypt the current data and persist it to localStorage. */
    persist() {
      if (!this.identity || !this.data) return
      const envelope = vaultEncrypt(this.identity, JSON.stringify(this.data))
      localStorage.setItem(ENV_KEY, JSON.stringify(envelope))
    },

    // ---- Keyring mutations -------------------------------------------------

    /** Add or replace a key from armored text. Auto-detects pub vs secret. */
    importArmored(armored: string): StoredKey {
      const info = inspectKey(armored)
      let publicKey: string
      let secretKey: string | undefined
      if (info.isSecret) {
        secretKey = armored
        publicKey = extractPublicKey(armored)
      } else {
        publicKey = armored
      }
      const existing = this.keyByFingerprint(info.fingerprint)
      const stored: StoredKey = {
        fingerprint: info.fingerprint,
        keyId: info.keyId,
        publicKey,
        secretKey: secretKey ?? existing?.secretKey,
        info,
        trusted: existing?.trusted ?? false,
        addedAt: existing?.addedAt ?? new Date().toISOString(),
      }
      if (!this.data) this.data = emptyData()
      const idx = this.data.keys.findIndex((k) => k.fingerprint === info.fingerprint)
      if (idx >= 0) this.data.keys[idx] = stored
      else this.data.keys.push(stored)
      this.persist()
      return stored
    },

    addGeneratedKey(publicKey: string, secretKey: string) {
      const info = inspectKey(publicKey)
      const stored: StoredKey = {
        fingerprint: info.fingerprint,
        keyId: info.keyId,
        publicKey,
        secretKey,
        info,
        trusted: true,
        addedAt: new Date().toISOString(),
      }
      if (!this.data) this.data = emptyData()
      this.data.keys.unshift(stored)
      this.persist()
      return stored
    },

    removeKey(fingerprint: string) {
      if (!this.data) return
      this.data.keys = this.data.keys.filter((k) => k.fingerprint !== fingerprint)
      this.persist()
    },

    setTrusted(fingerprint: string, trusted: boolean) {
      const k = this.keyByFingerprint(fingerprint)
      if (k) {
        k.trusted = trusted
        this.persist()
      }
    },

    updateSettings(patch: Partial<AppSettings>) {
      if (!this.data) return
      this.data.settings = { ...this.data.settings, ...patch }
      this.persist()
    },

    /** Danger: wipe everything (vault identity + data). */
    destroyVault() {
      localStorage.removeItem(ID_KEY)
      localStorage.removeItem(ENV_KEY)
      this.identity = null
      this.data = null
      this.unlocked = false
      this.hasVault = false
    },
  },
})
