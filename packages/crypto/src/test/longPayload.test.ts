import { Buffer } from 'node:buffer'
import { pack, unpack } from 'msgpackr'
import { describe, expect, test } from 'vitest'
import { asymmetric, hash, signatures, symmetric } from '../index.js'
import { keyToBytes } from '../util/index.js'

// Long UTF-8 strings exercise msgpackr's Buffer write path, which threw
// ERR_OUT_OF_RANGE with msgpackr 1.10.2 on Node 24. These are public test values.
const text = 'Quiet 🌱 — ключи — 鍵 '.repeat(12)
const makePayload = () => ({
  type: 'long-unicode-payload',
  text,
  nested: { count: 42, enabled: true, empty: null, previous: undefined },
  history: [{ text, previous: undefined }],
  bytes: Buffer.from([0, 1, 127, 128, 255]),
})

type TestPayload = ReturnType<typeof makePayload>

function expectPayload(actual: TestPayload) {
  // libsodium returns Uint8Array, while Node's MessagePack reader can return
  // Buffer. Both must preserve every byte and all nested/undefined fields.
  expect(actual.bytes).toBeInstanceOf(Uint8Array)
  expect({ ...actual, bytes: Array.from(actual.bytes) }).toStrictEqual({
    ...makePayload(),
    bytes: Array.from(makePayload().bytes),
  })
}

describe('long Unicode payloads on current Node', () => {
  test('serializes nested values, undefined fields and binary bytes without truncation', () => {
    expect(Buffer.byteLength(text, 'utf8')).toBeGreaterThan(64)
    for (let index = 0; index < 3; index++) {
      // Repeated packing also exercises writes at different offsets in the
      // serializer's reusable buffer, rather than only its first allocation.
      expectPayload(unpack(pack(makePayload())))
    }
  })

  test('hashes every field deterministically and distinguishes changed payloads', () => {
    const purpose = 'public-node24-regression-hash'
    const digest = hash(purpose, makePayload())
    expect(keyToBytes(digest)).toHaveLength(32)
    expect(hash(purpose, makePayload())).toBe(digest)
    expect(hash(purpose, { ...makePayload(), text: text + '!' })).not.toBe(digest)
    expect(hash('another-node24-hash-purpose', makePayload())).not.toBe(digest)
  })

  test('signs the full payload and rejects text, nested-field and binary tampering', () => {
    const signer = signatures.keyPair('public-node24-regression-signer')
    const payload = makePayload()
    const signature = signatures.sign(payload, signer.secretKey)
    expect(signatures.sign(makePayload(), signer.secretKey)).toBe(signature)
    expect(signatures.verify({ payload, signature, publicKey: signer.publicKey })).toBe(true)
    const changed = [
      { ...makePayload(), text: text + '!' },
      { ...makePayload(), nested: { ...payload.nested, count: 43 } },
      { ...makePayload(), bytes: Buffer.from([0, 1, 127, 128, 254]) },
    ]
    for (const tampered of changed) {
      expect(signatures.verify({ payload: tampered, signature, publicKey: signer.publicKey })).toBe(
        false
      )
    }
  })

  test('symmetrically encrypts and decrypts the payload and rejects modified ciphertext', () => {
    const password = 'public-node24-regression-password'
    const cipher = symmetric.encrypt(makePayload(), password)
    expectPayload(symmetric.decrypt(cipher, password))
    expect(() => symmetric.decrypt(cipher, 'a-different-test-password')).toThrow()

    const cipherBytes = symmetric.encryptBytes(makePayload(), password)
    expectPayload(symmetric.decryptBytes(cipherBytes, password))
    const modified = unpack(cipherBytes)
    modified.message[0] ^= 1
    expect(() => symmetric.decryptBytes(pack(modified), password)).toThrow()
  })

  test.each(['provided', 'ephemeral'] as const)(
    'asymmetric round trip with a %s sender key',
    mode => {
      const recipient = asymmetric.keyPair('public-node24-regression-recipient')
      const sender = asymmetric.keyPair('public-node24-regression-sender')
      const wrongRecipient = asymmetric.keyPair('public-node24-regression-wrong-recipient')
      const cipher = asymmetric.encrypt({
        secret: makePayload(),
        recipientPublicKey: recipient.publicKey,
        senderSecretKey: mode === 'provided' ? sender.secretKey : undefined,
      })
      const senderPublicKey = mode === 'provided' ? sender.publicKey : undefined
      expectPayload(
        asymmetric.decrypt({ cipher, senderPublicKey, recipientSecretKey: recipient.secretKey })
      )
      expect(() =>
        asymmetric.decrypt({
          cipher,
          senderPublicKey,
          recipientSecretKey: wrongRecipient.secretKey,
        })
      ).toThrow()
    }
  )
})
