<script setup lang="ts">
import { coreVersion } from '@/crypto/core'
</script>

<template>
  <div class="view">
    <div class="view-head"><h1>About gpg4web</h1></div>

    <UCard class="panel">
      <p>
        <strong>gpg4web</strong> is a full OpenPGP client that runs entirely in your browser. All
        cryptography is performed locally by a Rust core compiled to WebAssembly — no key material,
        passphrase, or plaintext ever leaves your device.
      </p>
      <div class="kv"><span>Crypto core</span><span class="mono">{{ coreVersion() }}</span></div>
    </UCard>

    <UCard class="panel">
      <template #header><span>Features</span></template>
      <ul class="feature-list">
        <li>Generate key pairs: Curve25519, Ed25519, RSA, NIST curves</li>
        <li>🛡 Post-quantum OpenPGP keys (IETF draft): ML-DSA, SLH-DSA, ML-KEM</li>
        <li>Encrypt &amp; decrypt messages to one or many recipients</li>
        <li>Inline, detached, and cleartext signatures + verification</li>
        <li>Import / export armored keys, and a portable <code>.gnupg</code> home archive</li>
        <li>Works on desktop and mobile</li>
      </ul>
    </UCard>

    <UCard class="panel">
      <template #header><span>Post-quantum vault</span></template>
      <p>Your keyring is stored in <code>localStorage</code>, sealed with a post-quantum envelope:</p>
      <ul class="feature-list">
        <li><strong>ML-KEM-768</strong> (NIST FIPS 203) wraps a fresh data key per save</li>
        <li><strong>AES-256-GCM</strong> encrypts the payload</li>
        <li><strong>Argon2id</strong> seals the KEM secret key under your master password</li>
      </ul>
      <p class="hint">
        An attacker with your storage blob must defeat both Argon2id and ML-KEM — neither broken by
        a quantum computer.
      </p>
    </UCard>

    <UCard class="panel">
      <template #header><span>Built with</span></template>
      <p class="muted">rPGP · ml-kem · aes-gcm · argon2 · wasm-bindgen · Vue 3 · Nuxt UI · Vite · Pinia</p>
    </UCard>
  </div>
</template>
