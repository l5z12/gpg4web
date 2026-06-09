// Typed wrapper around the Rust/WASM crypto core.
//
// Every function here is a thin, typed pass-through to WebAssembly. All
// cryptography runs locally in the browser; nothing is sent over the network.

import init, * as wasm from '@/wasm/gpg4web_core.js'
import wasmUrl from '@/wasm/gpg4web_core_bg.wasm?url'

let ready: Promise<void> | null = null

/** Initialize the WASM module exactly once. */
export function initCrypto(): Promise<void> {
  if (!ready) {
    ready = init({ module_or_path: wasmUrl }).then(() => undefined)
  }
  return ready
}

// ---------------------------------------------------------------------------
// Types mirrored from the Rust DTOs.
// ---------------------------------------------------------------------------

export type KeyAlgorithm =
  | 'curve25519'
  | 'ed25519'
  | 'rsa2048'
  | 'rsa3072'
  | 'rsa4096'
  | 'nistp256'
  | 'nistp384'
  | 'nistp521'
  | 'pqc'
  | 'mldsa87-mlkem1024'
  | 'slhdsa128s-mlkem768'

export interface GenerateOptions {
  userId: string
  algorithm: KeyAlgorithm
  passphrase?: string
  expireDays?: number
}

export interface GeneratedKey {
  fingerprint: string
  keyId: string
  publicKey: string
  secretKey: string
  algorithm: string
  userIds: string[]
  createdAt: number
  expiresAt: number | null
}

export interface SubkeyInfo {
  keyId: string
  fingerprint: string
  algorithm: string
  canEncrypt: boolean
  canSign: boolean
}

export interface KeyInfo {
  fingerprint: string
  keyId: string
  algorithm: string
  userIds: string[]
  createdAt: number
  expiresAt: number | null
  isSecret: boolean
  canEncrypt: boolean
  canSign: boolean
  bitStrength: number | null
  subkeys: SubkeyInfo[]
}

export interface SignatureCheck {
  keyId: string
  fingerprint: string | null
  valid: boolean
}

export interface DecryptResult {
  data: string
  wasEncrypted: boolean
  signatures: SignatureCheck[]
  filename: string | null
}

export interface CleartextResult {
  text: string
  valid: boolean
}

export interface VaultIdentity {
  version: number
  salt: string
  kemPublic: string
  kemSecretSealed: string
  kemSecretNonce: string
  verifier: string
  verifierNonce: string
}

export interface VaultEnvelope {
  version: number
  kemCiphertext: string
  nonce: string
  data: string
}

// ---------------------------------------------------------------------------
// OpenPGP operations
// ---------------------------------------------------------------------------

export const coreVersion = (): string => wasm.version()

export const generateKey = (opts: GenerateOptions): GeneratedKey =>
  wasm.generate_key(opts) as GeneratedKey

export const inspectKey = (armored: string): KeyInfo => wasm.inspect_key(armored) as KeyInfo

export const extractPublicKey = (secretArmored: string): string =>
  wasm.extract_public_key(secretArmored)

export const encrypt = (
  plaintext: string,
  recipients: string[],
  signSecret?: string | null,
  signPassphrase?: string | null,
  armor = true,
): string => wasm.encrypt(plaintext, recipients, signSecret ?? null, signPassphrase ?? null, armor)

export const decrypt = (
  ciphertext: string,
  secretArmored: string,
  passphrase: string,
  verifyWith: string[] = [],
): DecryptResult => wasm.decrypt(ciphertext, secretArmored, passphrase, verifyWith) as DecryptResult

export const signDetached = (data: string, secretArmored: string, passphrase: string): string =>
  wasm.sign_detached(data, secretArmored, passphrase)

export const verifyDetached = (
  data: string,
  signatureArmored: string,
  publicArmored: string,
): boolean => wasm.verify_detached(data, signatureArmored, publicArmored)

export const signCleartext = (text: string, secretArmored: string, passphrase: string): string =>
  wasm.sign_cleartext(text, secretArmored, passphrase)

export const verifyCleartext = (armored: string, publicArmored: string): CleartextResult =>
  wasm.verify_cleartext(armored, publicArmored) as CleartextResult

// ---------------------------------------------------------------------------
// Post-quantum vault
// ---------------------------------------------------------------------------

export const vaultCreate = (password: string): VaultIdentity =>
  wasm.vault_create(password) as VaultIdentity

export const vaultVerifyPassword = (identity: VaultIdentity, password: string): boolean =>
  wasm.vault_verify_password(identity, password)

/** Unseal the per-session decapsulation key (base64) from the master password. */
export const vaultUnseal = (identity: VaultIdentity, password: string): string =>
  wasm.vault_unseal(identity, password)

export const vaultEncrypt = (identity: VaultIdentity, plaintext: string): VaultEnvelope =>
  wasm.vault_encrypt(identity, plaintext) as VaultEnvelope

export const vaultDecrypt = (
  identity: VaultIdentity,
  password: string,
  envelope: VaultEnvelope,
): string => wasm.vault_decrypt(identity, password, envelope)

/** Decrypt an envelope with a session key from {@link vaultUnseal} (no password). */
export const vaultDecryptWithKey = (sessionKey: string, envelope: VaultEnvelope): string =>
  wasm.vault_decrypt_with_key(sessionKey, envelope)
