export default {
  title: 'About gpg4web',
  intro:
    'gpg4web is a full OpenPGP client that runs entirely in your browser. All cryptography is performed locally by a Rust core compiled to WebAssembly — no key material, passphrase, or plaintext ever leaves your device.',
  cryptoCore: 'Crypto core',
  features: 'Features',
  feature1: 'Generate key pairs: Curve25519, Ed25519, RSA, NIST curves',
  feature2: '🛡 Post-quantum OpenPGP keys (IETF draft): ML-DSA, SLH-DSA, ML-KEM',
  feature3: 'Encrypt & decrypt messages to one or many recipients',
  feature4: 'Sign / encrypt / decrypt / verify files (binary or armored)',
  feature5: 'Inline, detached, and cleartext signatures + verification',
  feature6: 'Import / export armored keys, and a portable .gnupg home archive',
  feature7: 'Works on desktop and mobile',
  pqVault: 'Post-quantum vault',
  pqVaultIntro: 'Your keyring is stored in localStorage, sealed with a post-quantum envelope:',
  pqVault1: 'ML-KEM-768 (NIST FIPS 203) wraps a fresh data key per save',
  pqVault2: 'AES-256-GCM encrypts the payload',
  pqVault3: 'Argon2id seals the KEM secret key under your master password',
  pqVaultHint:
    'An attacker with your storage blob must defeat both Argon2id and ML-KEM — neither broken by a quantum computer.',
  sourceLicense: 'Source & license',
  sourceLicenseBody:
    'gpg4web is free software, released under the GNU General Public License v3.0 (or later). The complete source code is available on GitHub — contributions and audits are welcome.',
  builtWith: 'Built with',
}
