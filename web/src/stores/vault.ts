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

/** A key flattened for export, with its secret material decrypted on demand. */
export interface ExportKey {
  fingerprint: string
  keyId: string
  publicKey: string
  secretKey?: string
  info: StoredKey['info']
  trusted?: boolean
}

interface State {
  initialized: boolean
  ready: boolean
  unlocked: boolean
  hasVault: boolean
  identity: VaultIdentity | null
  data: VaultData | null
  /** Master password, kept in memory only while unlocked so individual secret
   *  keys can be decrypted on demand. Wiped on lock. */
  masterPassword: string | null
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
    masterPassword: null,
    error: null,
  }),

  getters: {
    keys: (s): StoredKey[] => s.data?.keys ?? [],
    settings: (s): AppSettings => s.data?.settings ?? { ...DEFAULT_SETTINGS },
    ownKeys: (s): StoredKey[] => (s.data?.keys ?? []).filter((k) => k.secretKeyEnc),
    publicOnlyKeys: (s): StoredKey[] => (s.data?.keys ?? []).filter((k) => !k.secretKeyEnc),
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
      this.masterPassword = password
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
      this.identity = identity
      this.masterPassword = password
      if (!envelope) {
        // Identity exists but no payload yet — treat as empty.
        this.data = emptyData()
        this.persist()
      } else {
        const json = vaultDecrypt(identity, password, envelope)
        this.data = JSON.parse(json) as VaultData
        if (!this.data.settings) this.data.settings = { ...DEFAULT_SETTINGS }
        this.migrateLegacySecrets()
      }
      this.unlocked = true
      this.error = null
      return true
    },

    /** Lock the vault, wiping decrypted data and the master password. */
    lock() {
      this.unlocked = false
      this.data = null
      this.masterPassword = null
    },

    /** Encrypt the current data and persist it to localStorage. */
    persist() {
      if (!this.identity || !this.data) return
      const envelope = vaultEncrypt(this.identity, JSON.stringify(this.data))
      localStorage.setItem(ENV_KEY, JSON.stringify(envelope))
    },

    /** Wrap an armored secret key into an individually-encrypted envelope. */
    sealSecret(secretArmored: string): VaultEnvelope {
      if (!this.identity) throw new Error('vault not initialized')
      return vaultEncrypt(this.identity, secretArmored)
    },

    /**
     * Decrypt and return the armored secret key for a single fingerprint,
     * on demand. Other keys' secret material stays encrypted in memory.
     * Returns null if the key has no secret part or the vault is locked.
     */
    getSecretKey(fingerprint: string): string | null {
      const key = this.keyByFingerprint(fingerprint)
      if (!key?.secretKeyEnc || !this.identity || !this.masterPassword) return null
      try {
        return vaultDecrypt(this.identity, this.masterPassword, key.secretKeyEnc)
      } catch {
        return null
      }
    },

    /** One-time migration: older vaults stored secret keys in plaintext. */
    migrateLegacySecrets() {
      if (!this.data) return
      let changed = false
      for (const k of this.data.keys as Array<StoredKey & { secretKey?: string }>) {
        if (k.secretKey && !k.secretKeyEnc) {
          k.secretKeyEnc = this.sealSecret(k.secretKey)
          delete k.secretKey
          changed = true
        }
      }
      if (changed) this.persist()
    },

    // ---- Keyring mutations -------------------------------------------------

    /** Add or replace a key from armored text. Auto-detects pub vs secret. */
    importArmored(armored: string): StoredKey {
      const info = inspectKey(armored)
      let publicKey: string
      let secretKeyEnc: VaultEnvelope | undefined
      if (info.isSecret) {
        publicKey = extractPublicKey(armored)
        secretKeyEnc = this.sealSecret(armored)
      } else {
        publicKey = armored
      }
      const existing = this.keyByFingerprint(info.fingerprint)
      const stored: StoredKey = {
        fingerprint: info.fingerprint,
        keyId: info.keyId,
        publicKey,
        secretKeyEnc: secretKeyEnc ?? existing?.secretKeyEnc,
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
        secretKeyEnc: this.sealSecret(secretKey),
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

    /**
     * Flatten all keys for export, decrypting each secret key on demand. This
     * is an explicit, user-initiated bulk operation (e.g. .gnupg export).
     */
    keysForExport(): ExportKey[] {
      return this.keys.map((k) => ({
        fingerprint: k.fingerprint,
        keyId: k.keyId,
        publicKey: k.publicKey,
        secretKey: k.secretKeyEnc ? this.getSecretKey(k.fingerprint) ?? undefined : undefined,
        info: k.info,
        trusted: k.trusted,
      }))
    },

    /** Danger: wipe everything (vault identity + data). */
    destroyVault() {
      localStorage.removeItem(ID_KEY)
      localStorage.removeItem(ENV_KEY)
      this.identity = null
      this.data = null
      this.masterPassword = null
      this.unlocked = false
      this.hasVault = false
    },
  },
})
