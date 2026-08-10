import { ADMIN } from 'role/index.js'
import { setup } from 'util/testing/index.js'
import 'util/testing/expect/toLookLikeKeyset.js'
import { describe, expect, it } from 'vitest'
import { redactUser } from '../redactUser.js'

describe('Team', () => {
  describe('members', () => {
    it('has Alice as a root member', () => {
      const { alice } = setup('alice')
      expect(alice.team.members().length).toBe(1)
      const A = alice.team.members(alice.userId)
      expect(A.userName).toBe('alice')
    })

    it('has lockboxes for Alice containing the admin and team secrets', () => {
      const { alice } = setup('alice')
      const adminKeyset = alice.team.roleKeys(ADMIN)
      expect(adminKeyset).toLookLikeKeyset()

      const teamKeys = alice.team.teamKeys()
      expect(teamKeys).toLookLikeKeyset()
    })

    it('adds a member', () => {
      const { alice, bob } = setup('alice', 'bob')
      expect(alice.team.members().length).toBe(2)

      // look bob up by userId
      const bob2 = alice.team.members(bob.userId)
      expect(bob2.userName).toBe('bob')
    })

    it('fails to add a member when no lockboxes provided', () => {
      const { alice, bob, eve } = setup('alice', 'bob', { user: 'eve', addToTeam: false, admin: false, member: false })
      expect(alice.team.members().length).toBe(2)

      const potentialMember = redactUser(eve.user)

      const tryToAddMemberWithoutLockboxesEmpty = () => {
        alice.team.dispatch({
          type: 'ADD_MEMBER',
          payload: {
            member: potentialMember,
            lockboxes: [],
          },
        })
      }

      const tryToAddMemberWithoutLockboxesNullish = () => {
        alice.team.dispatch({
          type: 'ADD_MEMBER',
          payload: {
            member: potentialMember,
            lockboxes: undefined,
          } as any,
        })
      }

      expect(tryToAddMemberWithoutLockboxesEmpty).toThrow()
      expect(tryToAddMemberWithoutLockboxesNullish).toThrow()
    })

    it('makes lockboxes for added members', () => {
      // Alice creates a team, adds Bob
      const { bob } = setup('alice', { user: 'bob', admin: false })

      // Bob has team keys
      const teamKeys = bob.team.teamKeys()
      expect(teamKeys).toLookLikeKeyset()

      // Bob is not an admin so he doesn't have admin keys
      const bobLooksForAdminKeys = () => bob.team.roleKeys(ADMIN)
      expect(bobLooksForAdminKeys).toThrow()
    })

    it('makes an admin lockbox for an added admin member', () => {
      // Alice creates a team, adds Bob as an admin
      const { bob } = setup('alice', { user: 'bob', admin: true })

      // Bob is an admin and has admin keys
      const adminKeyset = bob.team.roleKeys(ADMIN)
      expect(adminKeyset).toLookLikeKeyset()
    })

    it("doesn't care if you add a member twice", () => {
      const { alice, bob } = setup('alice', { user: 'bob', addToTeam: false })

      const addBob = () => {
        alice.team.addForTesting(bob.user)
      }

      expect(addBob).not.toThrow()

      // Try adding bob again
      const addBobAgain = () => {
        alice.team.addForTesting(bob.user)
      }

      expect(addBobAgain).not.toThrow()
    })

    it('removes a member', () => {
      const { alice, bob, charlie } = setup('alice', 'bob', { user: 'charlie', addToTeam: false })

      expect(alice.team.has(bob.userId)).toBe(true)
      expect(alice.team.memberWasRemoved(bob.userId)).toBe(false)

      alice.team.remove(bob.userId)
      expect(alice.team.has(bob.userId)).toBe(false)

      // memberWasRemoved works as expected
      expect(alice.team.memberWasRemoved(alice.userId)).toBe(false) // Alice is still a member
      expect(alice.team.memberWasRemoved(bob.userId)).toBe(true) // Bob is no longer a member
      expect(alice.team.memberWasRemoved(charlie.userId)).toBe(false) // Charlie was never a member
    })

    it('only admins can remove members', () => {
      const { alice, bob, charlie } = setup('alice', { user: 'bob', admin: false }, 'charlie')

      // Bob can't remove Charlie because Bob's not an admin
      expect(() => bob.team.remove(charlie.userId)).toThrow()

      // Alice can remove Charlie because Alice is an admin
      expect(() => alice.team.remove(charlie.userId)).not.toThrow()
    })

    it('rotates keys after removing a member', () => {
      const { alice, bob } = setup('alice', { user: 'bob', admin: true })

      // Keys have never been rotated
      expect(alice.team.teamKeys().generation).toBe(0)
      expect(alice.team.adminKeys().generation).toBe(0)

      // Remove bob from team
      alice.team.remove(bob.userId)

      // Team keys & admin keys have now been rotated once
      expect(alice.team.teamKeys().generation).toBe(1)
      expect(alice.team.adminKeys().generation).toBe(1)

      // Doesn't update user keys on bob's member record after rotation
      const bobUser = alice.team.members(bob.userId)
      expect(bobUser.keys.generation).toBe(0)
      expect(bobUser.keysHistory).toHaveLength(1)
    })

    it('fails to remove a member when no lockboxes provided', () => {
      const { alice, bob } = setup('alice', 'bob')
      expect(alice.team.members().length).toBe(2)

      const tryToRemoveMemberWithoutLockboxesEmpty = () => {
        alice.team.dispatch({
          type: 'REMOVE_MEMBER',
          payload: {
            userId: bob.userId,
            lockboxes: [],
          },
        })
      }

      const tryToRemoveMemberWithoutLockboxesNullish = () => {
        alice.team.dispatch({
          type: 'REMOVE_MEMBER',
          payload: {
            userId: bob.userId,
            lockboxes: undefined,
          } as any,
        })
      }

      expect(tryToRemoveMemberWithoutLockboxesEmpty).toThrow()
      expect(tryToRemoveMemberWithoutLockboxesNullish).toThrow()
    })

    it('allows ADD_MEMBER_TEST when flag is set', () => {
      const { alice, bob } = setup('alice', { user: 'bob', addToTeam: false })
      expect(alice.team.members().length).toBe(1)

      const tryToAddMemberTest = () => {
        const ogFlag = process.env.ALLOW_ADD_MEMBER_TEST
        try {
          process.env.ALLOW_ADD_MEMBER_TEST = 'true'
          alice.team.dispatch({
            type: 'ADD_MEMBER_TEST',
            payload: {
              member: redactUser(bob.user),
              lockboxes: [],
            },
          })
        } finally {
          process.env.ALLOW_ADD_MEMBER_TEST = ogFlag
        }
      }

      expect(tryToAddMemberTest).not.toThrow()
    })

    it('does not allow ADD_MEMBER_TEST when flag is not set', () => {
      const { alice, bob } = setup('alice', { user: 'bob', addToTeam: false })
      expect(alice.team.members().length).toBe(1)

      const tryToAddMemberTest = () => {
        const ogFlag = process.env.ALLOW_ADD_MEMBER_TEST
        try {
          process.env.ALLOW_ADD_MEMBER_TEST = undefined
          alice.team.dispatch({
            type: 'ADD_MEMBER_TEST',
            payload: {
              member: redactUser(bob.user),
              lockboxes: [],
            },
          })
        } finally {
          process.env.ALLOW_ADD_MEMBER_TEST = ogFlag
        }
      }

      expect(tryToAddMemberTest).toThrow()
    })

    it("doesn't do anything if asked to remove a nonexistent member", () => {
      const { alice } = setup('alice')

      // Try removing bob although he hasn't been added
      const removeBob = () => {
        alice.team.remove('bob')
      }

      expect(removeBob).not.toThrow()
    })

    it('gets an individual member', () => {
      const { alice, bob } = setup('alice', 'bob')
      const member = alice.team.members(bob.userId)
      expect(member.userName).toBe('bob')
    })

    it('throws if asked to get a nonexistent member', () => {
      const { alice } = setup('alice', 'bob')

      const getNed = () => alice.team.members('ned')
      expect(getNed).toThrow(/not found/)
    })

    it('lists all members', () => {
      const { alice, bob, charlie } = setup([
        'alice',
        { user: 'bob', addToTeam: false },
        { user: 'charlie', addToTeam: false },
      ])

      expect(alice.team.members()).toHaveLength(1)
      expect(alice.team.members().map(m => m.userName)).toEqual(['alice'])

      alice.team.addForTesting(bob.user)
      alice.team.addForTesting(charlie.user)
      expect(alice.team.members()).toHaveLength(3)
      expect(alice.team.members().map(m => m.userName)).toEqual(['alice', 'bob', 'charlie'])
    })
  })
})
