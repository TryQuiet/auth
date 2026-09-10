import { createKeyset } from '@localfirst/crdx'
import * as invitation from 'invitation/index.js'
import * as lockbox from 'lockbox/index.js'
import * as teams from 'team/index.js'
import { ADMIN } from 'role/index.js'
import { setup } from 'util/testing/index.js'
import { KeyType } from 'util/index.js'
import { describe, expect, it } from 'vitest'

const MEMBER = 'MEMBER'

describe('invitation role grants', () => {
  it('lets an invitation holder self-assign the declared role with every key generation', () => {
    const { alice, bob } = setup('alice', { user: 'bob', admin: false })
    alice.team.addRole(MEMBER)
    alice.team.addMemberRole(alice.userId, MEMBER)
    alice.team.removeMemberRole(alice.userId, MEMBER)
    alice.team.addMemberRole(alice.userId, MEMBER)

    const { seed } = alice.team.inviteMember({ roleNames: [MEMBER] })
    const acceptanceKeys = invitation.generateStarterKeys(seed)
    const roleGrantKeys = invitation.generateRoleGrantKeys(seed)
    expect(roleGrantKeys.encryption.publicKey).not.toBe(acceptanceKeys.encryption.publicKey)
    expect(alice.team.allKeys(acceptanceKeys)[KeyType.ROLE]?.[MEMBER]).toBeUndefined()
    bob.team = teams.load(alice.team.save(), bob.localContext, alice.team.teamKeyring())

    expect(bob.team.memberHasRole(bob.userId, MEMBER)).toBe(false)
    expect(bob.team.addMemberRoleFromInvitation(MEMBER, seed)).toBe(true)
    expect(bob.team.memberHasRole(bob.userId, MEMBER)).toBe(true)
    expect(bob.team.roleKeysAllGenerations(MEMBER)).toEqual(
      alice.team.roleKeysAllGenerations(MEMBER)
    )
  })

  it('refuses to put arbitrary or administrator role keys on an invitation', () => {
    const { alice } = setup('alice')
    alice.team.addRole('PRIVATE_CHANNEL')

    expect(() => alice.team.inviteMember({ roleNames: ['PRIVATE_CHANNEL'] })).toThrow(
      /non-self-assignable role/
    )
    expect(() => alice.team.inviteMember({ roleNames: [ADMIN] })).toThrow(
      /admin role cannot be granted/
    )
  })

  it('rejects a stale grant before assigning the role', () => {
    const { alice, bob } = setup('alice', { user: 'bob', admin: false })
    alice.team.addRole(MEMBER)
    alice.team.addMemberRole(alice.userId, MEMBER)
    const { seed } = alice.team.inviteMember({ roleNames: [MEMBER] })

    // Removing the only explicit role member rotates MEMBER to generation 1. The invitation has
    // only generation 0, so using it must not create role membership without the current key.
    alice.team.removeMemberRole(alice.userId, MEMBER)
    bob.team = teams.load(alice.team.save(), bob.localContext, alice.team.teamKeyring())

    expect(() => bob.team.addMemberRoleFromInvitation(MEMBER, seed)).toThrow(/incomplete or stale/)
    expect(bob.team.memberHasRole(bob.userId, MEMBER)).toBe(false)
  })

  it('drops arbitrary keys and key rotations smuggled onto an invitation action', () => {
    const { alice, bob } = setup('alice', { user: 'bob', admin: false })
    alice.team.addRole(MEMBER)
    alice.team.addMemberRole(alice.userId, MEMBER)

    const seed = 'attempted-invitation-lockbox-smuggling'
    const roleGrantKeys = invitation.generateRoleGrantKeys(seed)
    const invitationRecord = invitation.create({ seed, roleNames: [MEMBER] })
    const replacementMemberKeys = createKeyset(
      { type: KeyType.ROLE, name: MEMBER },
      'unauthorized-member-rotation'
    )
    replacementMemberKeys.generation = 1

    alice.team.dispatch({
      type: 'INVITE_MEMBER',
      payload: {
        invitation: invitationRecord,
        lockboxes: [
          lockbox.create(alice.team.teamKeys(), roleGrantKeys),
          lockbox.create(replacementMemberKeys, roleGrantKeys),
        ],
      },
    })

    expect(alice.team.roleKeys(MEMBER).generation).toBe(0)
    expect(alice.team.allKeys(roleGrantKeys)).toEqual({})

    bob.team = teams.load(alice.team.save(), bob.localContext, alice.team.teamKeyring())
    expect(() => bob.team.addMemberRoleFromInvitation(MEMBER, seed)).toThrow(/incomplete or stale/)
    expect(bob.team.memberHasRole(bob.userId, MEMBER)).toBe(false)
  })

  it('rejects a member invitation authored by a non-admin', () => {
    const { bob } = setup('alice', { user: 'bob', admin: false })
    const invitationRecord = invitation.create({ seed: 'non-admin-invitation' })

    expect(() => {
      bob.team.dispatch({
        type: 'INVITE_MEMBER',
        payload: { invitation: invitationRecord, lockboxes: [] },
      })
    }).toThrow(/not an admin/)
  })
})
