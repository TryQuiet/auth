import { describe, expect, test } from 'vitest'
import { asymmetric, randomKey, signatures } from '../index.js'
import { type Base58, type SignedMessage } from '../types.js'

const { keyPair, sign, verify } = signatures

// A domain-separation context is required for every signature. These tests use fixed tags; the
// real domain constants live in `../domains.ts`.
const context = 'test/context-a'
const otherContext = 'test/context-b'

describe('crypto', () => {
  describe('signatures', () => {
    const payload = 'one if by day, two if by night'

    test('alice signs with her secret key', () => {
      const alice = keyPair('alice')
      const signature = sign(payload, alice.secretKey, context)
      expect(signature).toMatchInlineSnapshot(
        `"3LVccwBWq98uJvd7NfEG9ZnCSxnDhecu2UuTsUEfn6v7wSiMMRtGZU2KpYN4qBUhfCXAdzLGzbRiJMjetQG4cdaw"`
      )
    })

    test("bob verifies using alice's public key", () => {
      const alice = keyPair('alice')
      const signature = sign(payload, alice.secretKey, context)
      const { publicKey } = alice
      const isLegit = verify({ payload, signature, publicKey, context })
      expect(isLegit).toBe(true)
    })

    test('round trip with bytes payload', () => {
      const alice = keyPair('alice')
      const payload = randomKey()
      const { secretKey, publicKey } = alice
      const signature = sign(payload, secretKey, context)
      const isLegit = verify({ payload, signature, publicKey, context })
      expect(isLegit).toBe(true)
    })

    test('round trip with JSON payload', () => {
      const payload = {
        type: 0,
        payload: { team: 'Spies Я Us' },
        user: 'alice',
        client: { name: 'test', version: '0' },
        timestamp: 1_588_335_904_711,
        index: 0,
        prev: undefined,
      }
      const alice = keyPair('alice')
      const { secretKey, publicKey } = alice
      const signature = sign(payload, secretKey, context)
      const isLegit = verify({ payload, signature, publicKey, context })
      expect(isLegit).toBe(true)
    })

    test('Eve tampers with the message, but Bob is not fooled', () => {
      // Alice signs a message
      const alice = keyPair('alice')
      const signedMessage: SignedMessage = {
        payload,
        signature: sign(payload, alice.secretKey, context),
        publicKey: alice.publicKey,
        context,
      }

      // Eve tampers with the contents of the message
      const tamperedContent = payload //
        .replace('one', 'forty-two')
        .replace('two', 'seventy-twelve')
      const tamperedMessage = {
        ...signedMessage,
        payload: tamperedContent,
      }

      // Bob is not fooled
      const isLegit = verify(tamperedMessage)
      expect(isLegit).toBe(false)
    })

    test('a signature made for one context does not verify under another', () => {
      // Alice signs a message under one domain-separation context...
      const alice = keyPair('alice')
      const signature = sign(payload, alice.secretKey, context)
      const { publicKey } = alice

      // ...it verifies under that same context...
      expect(verify({ payload, signature, publicKey, context })).toBe(true)

      // ...but the very same signature is rejected when verified under a different context. This is
      // the property that prevents a signature harvested from one context (e.g. an identity
      // challenge) from being replayed as valid in another (e.g. link authorship).
      expect(verify({ payload, signature, publicKey, context: otherContext })).toBe(false)
    })

    test('signing requires a non-empty context', () => {
      const alice = keyPair('alice')
      expect(() => sign(payload, alice.secretKey, '')).toThrow()
    })

    test('fails verification if signature is wrong', () => {
      const alice = keyPair('alice')
      const signedMessage: SignedMessage = {
        payload,
        signature: sign(payload, alice.secretKey, context),
        publicKey: alice.publicKey,
        context,
      }

      const badSignature =
        '5VanBWz6kBnV2wfJZaPgv81Mj7QtAsPmq3QZgc3zZqbYZEzEdZQ9r24BGZpN6mt6djyr7W2v1eKYnnG3KSHtCD67' as Base58
      const badMessage = {
        ...signedMessage,
        signature: badSignature,
      }
      const isLegit = verify(badMessage)
      expect(isLegit).toBe(false)
    })

    test('fails verification if public key is wrong', () => {
      const alice = keyPair('alice')
      const signedMessage: SignedMessage = {
        payload,
        signature: sign(payload, alice.secretKey, context),
        publicKey: alice.publicKey,
        context,
      }
      const badKey = 'AAAAAnDzHhf26V8KcmQdxquK4fWUNDRy3MA6Sqf5hSma' as Base58
      const badMessage = {
        ...signedMessage,
        publicKey: badKey,
      }
      const isLegit = verify(badMessage)
      expect(isLegit).toBe(false)
    })

    test('fwiw: cannot use encryption keys to sign', () => {
      const keysForAnotherPurpose = asymmetric.keyPair()
      const tryToSignWithEncryptionKeys = () =>
        signatures.sign(payload, keysForAnotherPurpose.secretKey, context)
      expect(tryToSignWithEncryptionKeys).toThrow()
    })

    test('keypair generated from seed is deterministic', () => {
      // Alice signs a message
      const seed = 'passw0rd'
      const keys = keyPair(seed)
      expect(keys).toMatchInlineSnapshot(`
        {
          "publicKey": "BWWvjmQtJKHNMKqENTPDjjHzme33TmyXLxi7hXzMQyDk",
          "secretKey": "34ZMB3SxAtAYabMGG9bfMppTP9FXJxSWb9n8RLRVDHt6hTiaSvXMeB7fNri5ZAh8BKBoGsUNBXwtUgTcZCnqMypv",
        }
      `)
    })
  })
})
