/**
 * This test verifies that lockbox functionality is properly exported
 * from the public API of @localfirst/auth
 */
import { createKeyset } from '@localfirst/crdx'
import { describe, expect, it } from 'vitest'
import { lockbox, type Lockbox, type KeyManifest } from '../../index.js'
import { KeyType } from 'util/index.js'
import { setup } from 'util/testing/index.js'

const { bob, eve } = setup('alice', 'bob', { user: 'eve', member: false })

describe('lockbox public API exports', () => {
    it('lockbox.create and lockbox.open work via public API', () => {
        const adminKeys = createKeyset({ type: KeyType.ROLE, name: 'ADMIN' })

        // Create a lockbox using the public API
        const box: Lockbox = lockbox.create(adminKeys, bob.user.keys)

        // Verify the lockbox structure matches expected types
        expect(box.encryptionKey).toBeDefined()
        expect(box.recipient).toBeDefined()
        expect(box.contents).toBeDefined()
        expect(box.encryptedPayload).toBeDefined()

        // Verify recipient and contents are KeyManifest objects
        const recipient: KeyManifest = box.recipient
        expect(recipient.publicKey).toBeDefined()

        // Open the lockbox using the public API
        const keys = lockbox.open(box, bob.user.keys)
        expect(keys).toEqual(adminKeys)
    })

    it('lockbox.rotate works via public API', () => {
        const originalKeys = createKeyset({ type: KeyType.ROLE, name: 'MANAGERS' })
        const newKeys = createKeyset({ type: KeyType.ROLE, name: 'MANAGERS' })

        // Create a lockbox
        const box = lockbox.create(originalKeys, bob.user.keys)

        // Rotate the lockbox with new keys
        const rotatedBox: Lockbox = lockbox.rotate({ oldLockbox: box, newContents: newKeys })

        // The rotated lockbox should contain the new keys
        const retrievedKeys = lockbox.open(rotatedBox, bob.user.keys)
        expect(retrievedKeys).toEqual(newKeys)
        expect(retrievedKeys).not.toEqual(originalKeys)
    })

    it("lockbox.open throws when wrong keys are used", () => {
        const adminKeys = createKeyset({ type: KeyType.ROLE, name: 'ADMIN' })

        // Create a lockbox for Bob
        const box = lockbox.create(adminKeys, bob.user.keys)

        // Eve tries to open it
        expect(() => lockbox.open(box, eve.user.keys)).toThrow()
    })
})
