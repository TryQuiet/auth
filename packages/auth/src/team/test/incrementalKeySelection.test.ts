import { createKeyset } from '@localfirst/crdx'
import { asymmetric } from '@localfirst/crypto'
import { create, open } from 'lockbox/index.js'
import { appendLockboxes, snapshotLockboxes } from 'lockbox/snapshot.js'
import { keyMap } from 'team/selectors/keyMap.js'
import { type TeamState } from 'team/types.js'
import { removeMemberRole } from 'team/transforms/removeMemberRole.js'
import { setup } from 'util/testing/index.js'
import { describe, expect, it, vi } from 'vitest'

const stateWith = (lockboxes: TeamState['lockboxes']) => ({ lockboxes }) as TeamState

describe('immutable key selection cache', () => {
  it('opens an existing key path once for 1,000 lookups and protects returned keys', () => {
    const recipient = createKeyset({ type: 'DEVICE', name: 'phone' })
    const role = createKeyset({ type: 'ROLE', name: 'member' })
    const state = stateWith(snapshotLockboxes([create(role, recipient)]))
    const decrypt = vi.spyOn(asymmetric, 'decryptBytes')
    try {
      for (let i = 0; i < 1000; i++) expect(keyMap(state, recipient).ROLE.member[0]).toEqual(role)
      expect(decrypt).toHaveBeenCalledTimes(1)
      expect(() => {
        keyMap(state, recipient).ROLE.member[0].secretKey = recipient.secretKey
      }).toThrow()
      expect(() => {
        keyMap(state, recipient).ROLE.member[0].encryption.secretKey =
          recipient.encryption.secretKey
      }).toThrow()
    } finally {
      decrypt.mockRestore()
    }
  })

  it('reuses already opened immutable boxes after an unrelated collection extension', () => {
    const recipient = createKeyset({ type: 'DEVICE', name: 'phone' })
    const other = createKeyset({ type: 'DEVICE', name: 'other' })
    const role = createKeyset({ type: 'ROLE', name: 'member' })
    const base = snapshotLockboxes([create(role, recipient)])
    const unrelated = create(role, other)
    const decrypt = vi.spyOn(asymmetric, 'decryptBytes')
    try {
      expect(keyMap(stateWith(base), recipient).ROLE.member[0]).toEqual(role)
      const extended = appendLockboxes(base, [unrelated])
      expect(keyMap(stateWith(extended), recipient).ROLE.member[0]).toEqual(role)
      expect(decrypt).toHaveBeenCalledTimes(1)
    } finally {
      decrypt.mockRestore()
    }
  })

  it('does not alias mutable ciphertext, manifests, or device secret keys', () => {
    const recipient = createKeyset({ type: 'DEVICE', name: 'phone' })
    const role = createKeyset({ type: 'ROLE', name: 'member' })
    const original = create(role, recipient)
    const state = stateWith(snapshotLockboxes([original]))
    expect(keyMap(state, recipient).ROLE.member[0]).toEqual(role)
    original.encryptedPayload[0] = (original.encryptedPayload[0] + 1) % 256
    original.contents.name = 'attacker'
    state.lockboxes[0].encryptedPayload[0] = (state.lockboxes[0].encryptedPayload[0] + 1) % 256
    expect(keyMap(state, recipient).ROLE.member[0]).toEqual(role)
    expect(open(state.lockboxes[0], recipient)).toEqual(role)
    expect(() => {
      state.lockboxes[0].contents.name = 'attacker'
    }).toThrow()
    const other = createKeyset({ type: 'DEVICE', name: 'phone' })
    recipient.encryption.secretKey = other.encryption.secretKey
    expect(() => keyMap(state, recipient)).toThrow()
  })

  it('does not memoize caller-owned arrays, including after ciphertext mutation', () => {
    const recipient = createKeyset({ type: 'DEVICE', name: 'phone' })
    const role = createKeyset({ type: 'ROLE', name: 'member' })
    const state = stateWith([create(role, recipient)])
    expect(keyMap(state, recipient).ROLE.member[0]).toEqual(role)
    state.lockboxes[0].encryptedPayload[0] = (state.lockboxes[0].encryptedPayload[0] + 1) % 256
    expect(keyMap(state, recipient).ROLE).toBeUndefined()
  })

  it('separates branches and key generations and forgets removed access', () => {
    const recipient = createKeyset({ type: 'DEVICE', name: 'phone' })
    const role = createKeyset({ type: 'ROLE', name: 'member' })
    const rotated = { ...createKeyset({ type: 'ROLE', name: 'member' }), generation: 1 }
    const base = snapshotLockboxes([create(role, recipient)])
    const left = stateWith(snapshotLockboxes([...base, create(rotated, recipient)]))
    const right = stateWith(snapshotLockboxes([]))
    expect(keyMap(left, recipient).ROLE.member).toEqual([role, rotated])
    expect(keyMap(right, recipient).ROLE).toBeUndefined()
    expect(keyMap(stateWith(base), recipient).ROLE.member).toEqual([role])
  })

  it('keeps real team role grants and the removal transform key selection correct', () => {
    const { alice, bob } = setup('alice', { user: 'bob', admin: false })
    alice.team.addRole('private')
    alice.team.addMemberRole(bob.user.userId, 'private')
    bob.team.merge(alice.team.graph)
    expect(bob.team.roleKeys('private')).toEqual(alice.team.roleKeys('private'))
    // Protocol 4 disables removal dispatch, but its retained transform must still invalidate.
    const removed = removeMemberRole(bob.user.userId, 'private')(bob.team.state)
    expect(keyMap(removed, bob.localContext.device.keys).ROLE?.private).toBeUndefined()
  })
})
