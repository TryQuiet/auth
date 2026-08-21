import { createKeyset } from '@localfirst/crdx'
import { describe, expect, it } from 'vitest'
import { create, open, rotate } from 'lockbox/index.js'
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

  it('can only be rotated with a keyset of the same type', () => {
    const adminKeys = createKeyset({ type: KeyType.ROLE, name: ADMIN })

    // Alice creates a lockbox for Bob containing the admin keys
    const lockbox = create(adminKeys, bob.user.keys)

    const newKeys = createKeyset({ type: KeyType.ROLE, name: MANAGERS })
    const tryToRotate = () => rotate({ oldLockbox: lockbox, newContents: newKeys })
    expect(tryToRotate).toThrow()
  })
})
