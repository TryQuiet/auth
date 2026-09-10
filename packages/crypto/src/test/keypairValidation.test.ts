import { afterEach, describe, expect, it, vi } from 'vitest'
import sodium from 'libsodium-wrappers-sumo'
import {
  asymmetric,
  base58,
  isBase58KeyOfLength,
  isValidEncryptionKeypair,
  isValidSignatureKeypair,
  keyToBytes,
  signatures,
} from '../index.js'

afterEach(() => {
  vi.restoreAllMocks()
})

describe('keypair validation', () => {
  it.each(['encryption', 'signature'] as const)(
    'reuses successful %s correspondence checks but rechecks shape and changed key material',
    kind => {
      const pair = kind === 'encryption' ? asymmetric.keyPair() : signatures.keyPair()
      const other = kind === 'encryption' ? asymmetric.keyPair() : signatures.keyPair()
      const validate = kind === 'encryption' ? isValidEncryptionKeypair : isValidSignatureKeypair
      const derive = vi.spyOn(
        sodium,
        kind === 'encryption' ? 'crypto_scalarmult_base' : 'crypto_sign_seed_keypair'
      )
      expect(validate(pair)).toBe(true)
      expect(validate({ ...pair })).toBe(true)
      expect(derive).toHaveBeenCalledTimes(1)
      expect(validate({ ...pair, extra: undefined })).toBe(false)
      pair.publicKey = other.publicKey
      expect(validate(pair)).toBe(false)
      expect(derive).toHaveBeenCalledTimes(2)
      pair.secretKey = other.secretKey
      expect(validate(pair)).toBe(true)
      expect(derive).toHaveBeenCalledTimes(3)
      const corrupted = keyToBytes(pair.secretKey).slice()
      corrupted[corrupted.length - 1] ^= 1
      expect(validate({ ...pair, secretKey: base58.encode(corrupted) })).toBe(false)
    }
  )

  it.each(['encryption', 'signature'] as const)('bounds retained %s validation results', kind => {
    const generate = kind === 'encryption' ? asymmetric.keyPair : signatures.keyPair
    const validate = kind === 'encryption' ? isValidEncryptionKeypair : isValidSignatureKeypair
    const first = generate()
    expect(validate(first)).toBe(true)
    for (let i = 0; i < 256; i++) expect(validate(generate())).toBe(true)
    const derive = vi.spyOn(
      sodium,
      kind === 'encryption' ? 'crypto_scalarmult_base' : 'crypto_sign_seed_keypair'
    )
    expect(validate(first)).toBe(true)
    expect(derive).toHaveBeenCalledTimes(1)
  })
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
