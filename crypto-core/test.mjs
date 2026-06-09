// Runtime test harness for the gpg4web crypto core.
//
// Build the Node target first, then run:
//   wasm-pack build crypto-core --target nodejs --out-dir /tmp/wasm-node
//   GPG4WEB_WASM=/tmp/wasm-node/gpg4web_core.js node crypto-core/test.mjs

const modPath = process.env.GPG4WEB_WASM ?? '/tmp/wasm-node/gpg4web_core.js'
const g = await import(modPath)

function assert(c, m) {
  if (!c) throw new Error('FAIL: ' + m)
  console.log('  ok:', m)
}

console.log('version:', g.version())

console.log('\n[1] generate curve25519 key (passphrase)')
const k = g.generate_key({
  userId: 'Alice <alice@example.com>',
  algorithm: 'curve25519',
  passphrase: 'pw123',
  expireDays: 0,
})
assert(k.fingerprint.length === 40, 'fingerprint len 40')
assert(k.publicKey.includes('BEGIN PGP PUBLIC KEY'), 'public armored')
assert(k.secretKey.includes('BEGIN PGP PRIVATE KEY'), 'secret armored')
assert(k.userIds[0] === 'Alice <alice@example.com>', 'user id')

console.log('\n[2] inspect_key')
const info = g.inspect_key(k.publicKey)
assert(info.canEncrypt && info.canSign, 'caps')
assert(info.subkeys.length >= 1, 'has subkey')

console.log('\n[3] encrypt->decrypt roundtrip with signature')
const ct = g.encrypt('hello post-quantum world', [k.publicKey], k.secretKey, 'pw123', true)
assert(ct.includes('BEGIN PGP MESSAGE'), 'ciphertext armored')
const dec = g.decrypt(ct, k.secretKey, 'pw123', [k.publicKey])
assert(dec.data === 'hello post-quantum world', 'decrypted matches')
assert(dec.wasEncrypted, 'was encrypted')
assert(dec.signatures.length === 1 && dec.signatures[0].valid, 'signature valid')

console.log('\n[4] detached signature')
const sig = g.sign_detached('document body', k.secretKey, 'pw123')
assert(sig.includes('BEGIN PGP SIGNATURE'), 'sig armored')
assert(g.verify_detached('document body', sig, k.publicKey) === true, 'verify good')
assert(g.verify_detached('tampered', sig, k.publicKey) === false, 'verify bad fails')

console.log('\n[5] cleartext signature')
const cs = g.sign_cleartext('clear text msg', k.secretKey, 'pw123')
const cv = g.verify_cleartext(cs, k.publicKey)
assert(cv.valid && cv.text.includes('clear text msg'), 'cleartext verify')

console.log('\n[6] extract public from secret')
assert(g.extract_public_key(k.secretKey).includes('BEGIN PGP PUBLIC KEY'), 'extracted pub')

console.log('\n[7] rsa2048 key + encrypt to multiple recipients')
const r = g.generate_key({ userId: 'Bob <bob@e.com>', algorithm: 'rsa2048', passphrase: '' })
const ct2 = g.encrypt('multi', [k.publicKey, r.publicKey], null, null, true)
assert(g.decrypt(ct2, k.secretKey, 'pw123', []).data === 'multi', 'recipient A decrypts')
assert(g.decrypt(ct2, r.secretKey, '', []).data === 'multi', 'recipient B decrypts')

console.log('\n[8] draft-pqc key (ML-DSA65 + ML-KEM768)')
const pq = g.generate_key({ userId: 'PQ <pq@e.com>', algorithm: 'pqc', passphrase: '' })
const pqct = g.encrypt('quantum safe', [pq.publicKey], pq.secretKey, '', true)
const pqdec = g.decrypt(pqct, pq.secretKey, '', [pq.publicKey])
assert(pqdec.data === 'quantum safe', 'pqc roundtrip')
assert(pqdec.signatures[0].valid, 'pqc signature valid')

console.log('\n[9] post-quantum vault (ML-KEM-768 + AES-256-GCM + Argon2id)')
const id = g.vault_create('master-pass')
assert(g.vault_verify_password(id, 'master-pass') === true, 'pw ok')
assert(g.vault_verify_password(id, 'wrong') === false, 'wrong pw rejected')
const env = g.vault_encrypt(id, JSON.stringify({ keys: [k] }))
assert(JSON.parse(g.vault_decrypt(id, 'master-pass', env)).keys[0].fingerprint === k.fingerprint, 'vault roundtrip')
let threw = false
try {
  g.vault_decrypt(id, 'wrong', env)
} catch {
  threw = true
}
assert(threw, 'vault decrypt with wrong pw throws')

console.log('\n[10] session-key path (no password retained)')
const sessionKey = g.vault_unseal(id, 'master-pass')
assert(typeof sessionKey === 'string' && sessionKey.length > 100, 'unseal returns session key')
assert(
  JSON.parse(g.vault_decrypt_with_key(sessionKey, env)).keys[0].fingerprint === k.fingerprint,
  'decrypt_with_key round-trips without password',
)
let unsealThrew = false
try {
  g.vault_unseal(id, 'wrong')
} catch {
  unsealThrew = true
}
assert(unsealThrew, 'unseal with wrong password throws')

console.log('\n=== ALL TESTS PASSED ===')
