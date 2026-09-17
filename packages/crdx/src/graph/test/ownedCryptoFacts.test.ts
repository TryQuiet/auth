import { asymmetric, signatures } from '@localfirst/crypto'
import {
  createGraph,
  append,
  decryptLink,
  getHead,
  getSequence,
  verifyLinkSignature,
} from 'graph/index.js'
import { createTestSigner, TEST_GRAPH_KEYS as keys } from 'util/testing/setup.js'
import { describe, expect, it, vi } from 'vitest'

const alice = createTestSigner('owned-facts-alice')
const eve = createTestSigner('owned-facts-eve')
const build = () =>
  append({
    graph: createGraph<any>({ signer: alice, name: 'owned facts', keys }),
    action: { type: 'DATA', payload: { bytes: Uint8Array.from([1, 2, 3]) } },
    signer: alice,
    keys,
  })

describe('owned immutable cryptographic facts', () => {
  it('anchors sequenced signature facts to the retained graph link without relying on WeakRef', () => {
    const graph = build()
    const original = getHead(graph)[0]
    const sequenced = getSequence(graph).find(link => link.hash === original.hash)!
    const input = {
      hash: original.hash,
      signature: original.signature,
      publicKey: alice.keys.signature.publicKey,
    }
    const verify = vi.spyOn(signatures, 'verify')
    vi.stubGlobal('WeakRef', undefined)
    try {
      expect(sequenced).not.toBe(original)
      expect(verifyLinkSignature({ ...input, owner: sequenced })).toBe(true)
      expect(verifyLinkSignature({ ...input, owner: original })).toBe(true)
      expect(verify).toHaveBeenCalledTimes(1)
      expect(
        verifyLinkSignature({ ...input, owner: original, publicKey: eve.keys.signature.publicKey })
      ).toBe(false)
      expect(verify).toHaveBeenCalledTimes(2)
    } finally {
      vi.unstubAllGlobals()
      verify.mockRestore()
    }
  })
  it('reuses a link signature across replay objects but binds hash, signature and resolved key', () => {
    const graph = build()
    const link = getHead(graph)[0]
    const verify = vi.spyOn(signatures, 'verify')
    try {
      const input = {
        hash: link.hash,
        signature: link.signature,
        publicKey: alice.keys.signature.publicKey,
      }
      expect(verifyLinkSignature({ ...input, owner: link })).toBe(true)
      for (let n = 0; n < 1000; n++)
        expect(verifyLinkSignature({ ...input, owner: { ...link } })).toBe(true)
      expect(verify).toHaveBeenCalledTimes(1)
      expect(
        verifyLinkSignature({ ...input, owner: link, publicKey: eve.keys.signature.publicKey })
      ).toBe(false)
      expect(verifyLinkSignature({ ...input, owner: link, hash: graph.root })).toBe(false)
      expect(
        verifyLinkSignature({ ...input, owner: link, signature: graph.links[graph.root].signature })
      ).toBe(false)
      expect(verifyLinkSignature({ ...input, owner: link })).toBe(true)
      expect(verify).toHaveBeenCalledTimes(4)
    } finally {
      verify.mockRestore()
    }
  })

  it('reuses ciphertext decryption while keeping nested plaintext bytes private', () => {
    const graph = build()
    const input = graph.encryptedLinks[getHead(graph)[0].hash]
    const decrypt = vi.spyOn(asymmetric, 'decryptBytes')
    try {
      const first = decryptLink<any, any>(input, keys)
      first.body.payload.bytes[0] = 9
      for (let n = 0; n < 1000; n++) {
        const decoded = decryptLink<any, any>(
          { ...input, encryptedBody: Uint8Array.from(input.encryptedBody) },
          keys
        )
        expect([...decoded.body.payload.bytes]).toEqual([1, 2, 3])
        decoded.body.payload.bytes[0] = 8
      }
      expect(decrypt).toHaveBeenCalledTimes(1)
    } finally {
      decrypt.mockRestore()
    }
  })

  it('remains correct when the runtime has no WeakRef', () => {
    const graph = build()
    const link = getHead(graph)[0]
    const input = graph.encryptedLinks[link.hash]
    vi.stubGlobal('WeakRef', undefined)
    try {
      const args = {
        hash: link.hash,
        signature: link.signature,
        publicKey: alice.keys.signature.publicKey,
      }
      expect(verifyLinkSignature({ ...args, owner: link })).toBe(true)
      expect(verifyLinkSignature({ ...args, owner: link })).toBe(true)
      expect(verifyLinkSignature({ ...args, owner: { ...link } })).toBe(true)
      expect(decryptLink(input, keys)).toEqual(decryptLink({ ...input }, keys))
    } finally {
      vi.unstubAllGlobals()
    }
  })

  it('rejects changed cipher, sender key and secret key after a cached decryption', () => {
    const graph = build()
    const input = graph.encryptedLinks[getHead(graph)[0].hash]
    decryptLink(input, keys)
    const cipher = Uint8Array.from(input.encryptedBody)
    cipher[0] = (cipher[0] + 1) % 256
    expect(() => decryptLink({ ...input, encryptedBody: cipher }, keys)).toThrow()
    expect(() =>
      decryptLink({ ...input, senderPublicKey: eve.keys.encryption.publicKey }, keys)
    ).toThrow()
    const wrongKeys = {
      ...keys,
      encryption: { ...keys.encryption, secretKey: eve.keys.encryption.secretKey },
    }
    expect(() => decryptLink(input, wrongKeys)).toThrow()
    // Signature changes cannot be hidden by a cached body: callers validate the current signature.
    const changed = decryptLink({ ...input, signature: graph.links[graph.root].signature }, keys)
    expect(changed.signature).toBe(graph.links[graph.root].signature)
    expect(
      verifyLinkSignature({
        hash: changed.hash,
        signature: changed.signature,
        publicKey: alice.keys.signature.publicKey,
        owner: changed,
      })
    ).toBe(false)
  })
})
