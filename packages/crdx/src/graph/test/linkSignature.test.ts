import { asymmetric, signatures, LINK_AUTHORSHIP } from '@localfirst/crypto'
import { describe, expect, it } from 'vitest'
import {
  append,
  createGraph,
  decryptLink,
  deserialize,
  getHead,
  getRoot,
  hashEncryptedLink,
  serialize,
  verifyLinkSignature,
  type EncryptedLink,
} from 'graph/index.js'
import { validate } from 'validator/index.js'
import { createTestSigner, TEST_GRAPH_KEYS as keys } from 'util/testing/setup.js'
import 'util/testing/expect/toBeValid'

const alice = createTestSigner('alice')
const eve = createTestSigner('eve')

const buildGraph = () => {
  const graph = createGraph<any>({ signer: alice, name: 'test graph', keys })
  return append({ graph, action: { type: 'FOO', payload: 'bar' }, signer: alice, keys })
}

describe('link signatures', () => {
  it('signs every link it appends', () => {
    const graph = buildGraph()

    for (const link of Object.values(graph.links)) {
      expect(link.signature).toBeDefined()

      // the same signature rides along on the encrypted link, which is what peers actually exchange
      expect(graph.encryptedLinks[link.hash].signature).toBe(link.signature)

      expect(
        verifyLinkSignature({
          hash: link.hash,
          signature: link.signature,
          publicKey: alice.keys.signature.publicKey,
        })
      ).toBe(true)
    }
  })

  it('names its signer in the link body', () => {
    const graph = buildGraph()
    expect(getRoot(graph).body.signer).toEqual(alice.info)
    expect(getHead(graph)[0].body.signer).toEqual(alice.info)
  })

  it('rejects a signature checked against the wrong key', () => {
    const link = getHead(buildGraph())[0]

    // 🦹‍♀️ Eve's key doesn't verify Alice's signature — this is what stops a link from claiming to
    // come from a signer that didn't make it
    expect(
      verifyLinkSignature({
        hash: link.hash,
        signature: link.signature,
        publicKey: eve.keys.signature.publicKey,
      })
    ).toBe(false)
  })

  it('rejects a signature checked against a different hash', () => {
    const graph = buildGraph()
    const [head] = getHead(graph)
    const root = getRoot(graph)

    // a signature is only good for the exact hash it was made over, so it can't be lifted from one
    // link and pasted onto another
    expect(
      verifyLinkSignature({
        hash: root.hash,
        signature: head.signature,
        publicKey: alice.keys.signature.publicKey,
      })
    ).toBe(false)
  })

  it('rejects a missing or malformed signature', () => {
    const link = getHead(buildGraph())[0]
    const { publicKey } = alice.keys.signature

    expect(verifyLinkSignature({ hash: link.hash, signature: undefined, publicKey })).toBe(false)
    expect(
      verifyLinkSignature({ hash: link.hash, signature: link.signature, publicKey: undefined })
    ).toBe(false)
    expect(
      verifyLinkSignature({ hash: link.hash, signature: 'not-a-signature' as any, publicKey })
    ).toBe(false)
  })

  it('changes the hash when the encrypted body is tampered with', () => {
    const graph = buildGraph()
    const [head] = getHead(graph)
    const original = graph.encryptedLinks[head.hash]

    // 🦹‍♀️ Eve flips a byte of the ciphertext
    const tamperedBody = Uint8Array.from(original.encryptedBody)
    tamperedBody.set([255 - tamperedBody.at(-1)!], tamperedBody.length - 1)

    // the hash covers the ciphertext, so the link no longer hashes to the value the graph records
    expect(hashEncryptedLink(tamperedBody)).not.toBe(head.hash)

    // and the signature Alice made over the old hash doesn't cover the new one
    expect(
      verifyLinkSignature({
        hash: hashEncryptedLink(tamperedBody),
        signature: original.signature,
        publicKey: alice.keys.signature.publicKey,
      })
    ).toBe(false)

    graph.encryptedLinks[head.hash] = { ...original, encryptedBody: tamperedBody }
    expect(validate(graph)).not.toBeValid()
  })

  it('a forged link is signed by whoever forged it, not by whoever it names', () => {
    const graph = buildGraph()
    const [head] = getHead(graph)

    // 🦹‍♀️ Eve holds the graph keys, so she can build a well-formed replacement link that names
    // Alice as its signer, and she can sign it — but only with her own key
    const body = { ...head.body, signer: alice.info, payload: 'forged' }
    const encryptedBody = asymmetric.encryptBytes({
      secret: body,
      recipientPublicKey: keys.encryption.publicKey,
      senderSecretKey: eve.keys.encryption.secretKey,
    })
    const hash = hashEncryptedLink(encryptedBody)
    const forged: EncryptedLink = {
      encryptedBody,
      signature: signatures.sign(hash, eve.keys.signature.secretKey, LINK_AUTHORSHIP),
      recipientPublicKey: keys.encryption.publicKey,
      senderPublicKey: eve.keys.encryption.publicKey,
    }

    // the forgery is self-consistent, and crdx will happily decrypt it...
    const decrypted = decryptLink<any, any>(forged, keys)
    expect(decrypted.body.signer).toEqual(alice.info)

    // ...but it does not verify against the key registered for the signer it names, which is the
    // check the application is expected to make before authorizing anything
    expect(
      verifyLinkSignature({
        hash: decrypted.hash,
        signature: decrypted.signature,
        publicKey: alice.keys.signature.publicKey,
      })
    ).toBe(false)
  })

  it('survives a serialization round trip', () => {
    const graph = buildGraph()
    const rehydrated = deserialize(serialize(graph), keys)

    expect(validate(rehydrated)).toBeValid()

    for (const link of Object.values(graph.links)) {
      const rehydratedLink = rehydrated.links[link.hash]
      expect(rehydratedLink.signature).toBe(link.signature)
      expect(
        verifyLinkSignature({
          hash: rehydratedLink.hash,
          signature: rehydratedLink.signature,
          publicKey: alice.keys.signature.publicKey,
        })
      ).toBe(true)
    }
  })

  it('carries the signature through decryptLink', () => {
    const graph = buildGraph()

    for (const link of Object.values(graph.links)) {
      const decrypted = decryptLink<any, any>(graph.encryptedLinks[link.hash], keys)
      expect(decrypted.signature).toBe(link.signature)
      expect(decrypted.hash).toBe(link.hash)
    }
  })
})
