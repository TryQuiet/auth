import { describe, expect, it } from 'vitest'
import {
  asymmetric,
  base58,
  isBase58KeyOfLength,
  isValidEncryptionKeypair,
  isValidSignatureKeypair,
  keyToBytes,
  signatures,
} from '../index.js'

describe('keypair validation', () => {
  it('accepts generated encryption and signature keypairs', () => {
    const encryption = asymmetric.keyPair('encryption keypair validation vector')
    const signature = signatures.keyPair('signature keypair validation vector')

    expect(isValidEncryptionKeypair(encryption)).toBe(true)
    expect(asymmetric.keyPairIsValid(encryption)).toBe(true)
    expect(isValidSignatureKeypair(signature)).toBe(true)
    expect(signatures.keyPairIsValid(signature)).toBe(true)
  })

  it('rejects encryption keypairs with mismatched or incorrectly sized keys', () => {
    const alice = asymmetric.keyPair('alice encryption validation vector')
    const bob = asymmetric.keyPair('bob encryption validation vector')

    expect(isValidEncryptionKeypair({ ...alice, publicKey: bob.publicKey })).toBe(false)
    expect(isValidEncryptionKeypair({ ...alice, secretKey: bob.secretKey })).toBe(false)
    expect(
      isValidEncryptionKeypair({
        ...alice,
        publicKey: base58.encode(keyToBytes(alice.publicKey).slice(1)),
      })
    ).toBe(false)
    expect(isValidEncryptionKeypair({ ...alice, secretKey: 'not base58!' })).toBe(false)
  })

  it('rejects signature keys when either half of the secret or the public key is changed', () => {
    const pair = signatures.keyPair('signature validation vector')
    const other = signatures.keyPair('other signature validation vector')
    const changedSeed = keyToBytes(pair.secretKey).slice()
    changedSeed[0] = changedSeed[0] === 0 ? 1 : 0
    const changedEmbeddedPublicKey = keyToBytes(pair.secretKey).slice()
    const lastIndex = changedEmbeddedPublicKey.length - 1
    changedEmbeddedPublicKey[lastIndex] = changedEmbeddedPublicKey[lastIndex] === 0 ? 1 : 0

    expect(isValidSignatureKeypair({ ...pair, publicKey: other.publicKey })).toBe(false)
    expect(isValidSignatureKeypair({ ...pair, secretKey: base58.encode(changedSeed) })).toBe(false)
    expect(
      isValidSignatureKeypair({
        ...pair,
        secretKey: base58.encode(changedEmbeddedPublicKey),
      })
    ).toBe(false)
  })

  it('checks decoded byte length rather than Base58 character count', () => {
    const key = asymmetric.keyPair('decoded length validation vector').publicKey

    expect(isBase58KeyOfLength(key, 32)).toBe(true)
    expect(isBase58KeyOfLength(key, 31)).toBe(false)
    expect(isBase58KeyOfLength('not base58!', 32)).toBe(false)
  })
})
