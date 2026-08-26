import { createKeyset } from '@localfirst/crdx'
import { asymmetric, base58, keyToBytes } from '@localfirst/crypto'
import { pack, unpack } from 'msgpackr'
import { describe, expect, it } from 'vitest'
import {
  create,
  isKeyManifest,
  isRecipientManifest,
  keysetCommitment,
  open,
  rotate,
  type Lockbox,
} from 'lockbox/index.js'
import { ADMIN } from 'role/index.js'
import { KeyType } from 'util/index.js'
import { setup } from 'util/testing/index.js'

const { bob, eve } = setup('alice', 'bob', { user: 'eve', member: false })
const MANAGERS = 'managers'

describe('lockbox', () => {
  it('can be opened by the intended recipient', () => {
    const adminKeys = createKeyset({ type: KeyType.ROLE, name: ADMIN })

    // Alice creates a lockbox for Bob containing the admin keys
    const lockbox = create(adminKeys, bob.user.keys)

    // Bob opens the lockbox and gets the admin keys
    const keys = open(lockbox, bob.user.keys)
    expect(keys).toEqual(adminKeys)
  })

  it('uses a deterministic, complete-keyset commitment', () => {
    const keys = createKeyset(
      { type: KeyType.ROLE, name: ADMIN },
      'lockbox keyset commitment vector'
    )

    expect(keysetCommitment(keys)).toMatchInlineSnapshot(
      `"Hp2bTccn1BsfpHpYZ7wk5kzG2iMCsgRZtnADb5DTH8CF"`
    )

    const other = createKeyset(
      { type: KeyType.ROLE, name: ADMIN },
      'lockbox keyset commitment alternate'
    )
    const variants = [
      { ...keys, type: 'OTHER' },
      { ...keys, name: 'OTHER' },
      { ...keys, generation: 1 },
      { ...keys, encryption: other.encryption },
      { ...keys, signature: other.signature },
      { ...keys, secretKey: other.secretKey },
    ]

    expect(new Set([keysetCommitment(keys), ...variants.map(keysetCommitment)]).size).toBe(7)
  })

  it('survives a MsgPack serialization round trip', () => {
    const adminKeys = createKeyset({ type: KeyType.ROLE, name: ADMIN })
    const box = create(adminKeys, bob.user.keys)
    const roundTripped = unpack(pack(box)) as Lockbox

    expect(isRecipientManifest(roundTripped.recipient)).toBe(true)
    expect(isKeyManifest(roundTripped.contents)).toBe(true)
    expect(roundTripped).toEqual(box)
    expect(open(roundTripped, bob.user.keys)).toEqual(adminKeys)
  })

  it("can't be opened by anyone else", () => {
    const adminKeys = createKeyset({ type: KeyType.ROLE, name: ADMIN })

    // Alice creates a lockbox for Bob containing the admin keys
    const lockbox = create(adminKeys, bob.user.keys)

    // Eve tries to open the lockbox but can't
    const eveTriesToOpen = () => open(lockbox, eve.user.keys)
    expect(eveTriesToOpen).toThrow()
  })

  // A lockbox has two representations of its contents: the public manifest (`contents`), which
  // authorization rules read, and the sealed payload, which only recipients can decrypt. `open`
  // must bind the two — otherwise an author could advertise an established key in the manifest to
  // pass authorization while sealing a different keyset inside (see
  // team/test/sameGenerationLockboxReplacement.test.ts for the attack this enables).
  it('rejects encrypted contents that do not match the public manifest', () => {
    const adminKeys = createKeyset({ type: KeyType.ROLE, name: ADMIN })
    const forgedManifestKeys = createKeyset({ type: KeyType.ROLE, name: ADMIN })
    const box = create(adminKeys, bob.user.keys)
    box.contents.publicKey = forgedManifestKeys.encryption.publicKey

    expect(() => open(box, bob.user.keys)).toThrow('The lockbox contents do not match its manifest')
  })

  it.each([
    ['type', 'OTHER'],
    ['name', 'OTHER'],
    ['generation', 1],
  ] as const)('rejects a substituted manifest %s', (field, value) => {
    const adminKeys = createKeyset({ type: KeyType.ROLE, name: ADMIN })
    const box = create(adminKeys, bob.user.keys)
    box.contents = { ...box.contents, [field]: value }

    expect(() => open(box, bob.user.keys)).toThrow('The lockbox contents do not match its manifest')
  })

  it('rejects a substituted manifest commitment', () => {
    const adminKeys = createKeyset({ type: KeyType.ROLE, name: ADMIN })
    const otherKeys = createKeyset({ type: KeyType.ROLE, name: ADMIN })
    const box = create(adminKeys, bob.user.keys)
    box.contents.commitment = keysetCommitment(otherKeys)

    expect(() => open(box, bob.user.keys)).toThrow('The lockbox contents do not match its manifest')
  })

  it.each([
    [
      'symmetric secret',
      (keys: typeof legitimateKeys, other: typeof legitimateKeys) => ({
        ...keys,
        secretKey: other.secretKey,
      }),
    ],
    [
      'encryption keypair',
      (keys: typeof legitimateKeys, other: typeof legitimateKeys) => ({
        ...keys,
        encryption: other.encryption,
      }),
    ],
    [
      'signature keypair',
      (keys: typeof legitimateKeys, other: typeof legitimateKeys) => ({
        ...keys,
        signature: other.signature,
      }),
    ],
    ['scope', (keys: typeof legitimateKeys) => ({ ...keys, type: 'OTHER', name: 'OTHER' })],
    ['generation', (keys: typeof legitimateKeys) => ({ ...keys, generation: 1 })],
    [
      'symmetric secret and signature keypair',
      (keys: typeof legitimateKeys, other: typeof legitimateKeys) => ({
        ...keys,
        secretKey: other.secretKey,
        signature: other.signature,
      }),
    ],
  ])(
    'rejects substituted %s even when the manifest advertises the established encryption key',
    (_description, substitute) => {
      const legitimateBox = create(legitimateKeys, bob.user.keys)
      const other = createKeyset({ type: KeyType.ROLE, name: ADMIN })
      const poisoned = create(substitute(legitimateKeys, other), bob.user.keys)

      // Authorization sees the established manifest, while the ciphertext contains the substitute.
      poisoned.contents = { ...legitimateBox.contents }

      expect(() => open(poisoned, bob.user.keys)).toThrow(
        'The lockbox contents do not match its manifest'
      )
    }
  )

  it('does not cache a successful open across later manifest mutation', () => {
    const adminKeys = createKeyset({ type: KeyType.ROLE, name: ADMIN })
    const box = create(adminKeys, bob.user.keys)
    expect(open(box, bob.user.keys)).toEqual(adminKeys)

    box.contents.commitment = keysetCommitment(createKeyset({ type: KeyType.ROLE, name: ADMIN }))
    expect(() => open(box, bob.user.keys)).toThrow('The lockbox contents do not match its manifest')
  })

  it('rejects recipient metadata that does not match the decryption keyset', () => {
    const adminKeys = createKeyset({ type: KeyType.ROLE, name: ADMIN })
    const box = create(adminKeys, bob.user.keys)
    box.recipient = { ...box.recipient, name: 'someone-else' }

    expect(() => open(box, bob.user.keys)).toThrow(
      'The lockbox recipient does not match its decryption keys'
    )
  })

  it('strips a content commitment when a KeyManifest is reused as a recipient', () => {
    const originalKeys = createKeyset({ type: KeyType.ROLE, name: ADMIN })
    const original = create(originalKeys, bob.user.keys)
    const nextKeys = createKeyset({ type: KeyType.ROLE, name: MANAGERS })
    const next = create(nextKeys, original.contents)

    expect(next.recipient).toEqual({
      type: original.contents.type,
      name: original.contents.name,
      generation: original.contents.generation,
      publicKey: original.contents.publicKey,
    })
    expect(Object.keys(next.recipient).sort()).toEqual(['generation', 'name', 'publicKey', 'type'])
  })

  it('rejects malformed and mismatched content keypairs at creation', () => {
    const keys = createKeyset({ type: KeyType.ROLE, name: ADMIN })
    const other = createKeyset({ type: KeyType.ROLE, name: ADMIN })
    const badEncryption = {
      ...keys,
      encryption: { ...keys.encryption, secretKey: other.encryption.secretKey },
    }
    const badSignature = {
      ...keys,
      signature: { ...keys.signature, publicKey: other.signature.publicKey },
    }
    const shortSymmetric = {
      ...keys,
      secretKey: base58.encode(keyToBytes(keys.secretKey).slice(1)),
    }

    expect(() => create(badEncryption, bob.user.keys)).toThrow(
      'The lockbox contents must be a valid keyset'
    )
    expect(() => create(badSignature, bob.user.keys)).toThrow(
      'The lockbox contents must be a valid keyset'
    )
    expect(() => create(shortSymmetric, bob.user.keys)).toThrow(
      'The lockbox contents must be a valid keyset'
    )
  })

  it('rejects malformed and mismatched recipient keypairs at creation', () => {
    const keys = createKeyset({ type: KeyType.ROLE, name: ADMIN })
    const mismatchedRecipient = {
      ...bob.user.keys,
      encryption: { ...bob.user.keys.encryption, secretKey: eve.user.keys.encryption.secretKey },
    }

    expect(() => create(keys, mismatchedRecipient)).toThrow(
      'The lockbox recipient keys are invalid'
    )
  })

  it('rejects malformed decrypted structures and keypairs at opening', () => {
    const keys = createKeyset({ type: KeyType.ROLE, name: ADMIN })
    const other = createKeyset({ type: KeyType.ROLE, name: ADMIN })
    const box = create(keys, bob.user.keys)
    const malformed = {
      ...keys,
      encryption: { ...keys.encryption, secretKey: other.encryption.secretKey },
    }
    reseal(box, malformed)

    expect(() => open(box, bob.user.keys)).toThrow('The lockbox contents are not a valid keyset')
  })

  it('can only be rotated with a keyset of the same type', () => {
    const adminKeys = createKeyset({ type: KeyType.ROLE, name: ADMIN })

    // Alice creates a lockbox for Bob containing the admin keys
    const lockbox = create(adminKeys, bob.user.keys)

    const newKeys = createKeyset({ type: KeyType.ROLE, name: MANAGERS })
    const tryToRotate = () => rotate({ oldLockbox: lockbox, newContents: newKeys })
    expect(tryToRotate).toThrow()
  })
})

const legitimateKeys = createKeyset({ type: KeyType.ROLE, name: ADMIN })

const reseal = (box: Lockbox, contents: unknown) => {
  const ephemeral = asymmetric.keyPair()
  box.encryptionKey.publicKey = ephemeral.publicKey
  box.encryptedPayload = asymmetric.encryptBytes({
    secret: contents,
    recipientPublicKey: bob.user.keys.encryption.publicKey,
    senderSecretKey: ephemeral.secretKey,
  })
}
