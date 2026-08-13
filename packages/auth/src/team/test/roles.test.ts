import { AddRoleInput, ADMIN, MEMBER } from 'role/index.js'
import * as teams from 'team/index.js'
import { setup } from 'util/testing/index.js'
import 'util/testing/expect/toLookLikeKeyset.js'
import { randomBytes, symmetric } from '@localfirst/crypto'
import { describe, expect, it } from 'vitest'
import { randomUUID } from 'crypto'
import { createKeyset, KeyScope } from '@localfirst/crdx'

const MANAGERS = 'managers'
const managers: AddRoleInput = { roleName: MANAGERS }

const FOOBAR = 'foobar'
const foobar: AddRoleInput = { roleName: FOOBAR }

describe('Team', () => {
  describe('roles', () => {
    it('Alice is admin', () => {
      const { alice } = setup('alice')
      expect(alice.team.memberIsAdmin(alice.userId)).toBe(true)
    })

    it('Bob is not admin', () => {
      const { alice, bob } = setup('alice', { user: 'bob', admin: false })
      expect(alice.team.memberIsAdmin(bob.userId)).toBe(false)
    })

    it('Bob is admin', () => {
      const { alice, bob } = setup('alice', { user: 'bob', admin: true })
      expect(alice.team.memberIsAdmin(bob.userId)).toBe(true)
    })

    it('adds a role', () => {
      const { alice, bob } = setup('alice', 'bob')

      // We only have default roles to start out
      expect(alice.team.roles().map(r => r.roleName)).toEqual([ADMIN, MEMBER])
      expect(alice.team.hasRole(ADMIN)).toBe(true)
      expect(alice.team.hasRole(MANAGERS)).toBe(false)

      // 👩🏾 Alice adds the managers role
      alice.team.addRole(managers)
      expect(alice.team.roles().map(r => r.roleName)).toEqual([ADMIN, MEMBER, MANAGERS])
      expect(alice.team.roles(MANAGERS).roleName).toBe(MANAGERS)
      expect(alice.team.roles(MANAGERS).createdBy).toBe(alice.userId)
      expect(alice.team.hasRole(MANAGERS)).toBe(true)

      // 👩🏾 Alice adds 👨🏻‍🦲 Bob to the managers role
      alice.team.addMemberRole(bob.userId, MANAGERS)
      expect(alice.team.membersInRole(MANAGERS).map(m => m.userName)).toEqual(['alice', 'bob'])
    })

    it('fails to add a role when no lockboxes provided', () => {
      const { alice, bob } = setup('alice', { user: 'bob', admin: false })
      expect(alice.team.members().length).toBe(2)

      // Managers role doesn't exist yet
      expect(alice.team.hasRole(MANAGERS))

      const tryToAddRoleWithoutLockboxesEmpty = () => {
        alice.team.dispatch({
          type: 'ADD_ROLE',
          payload: {
            roleName: ADMIN,
            createdBy: alice.userId,
            permissions: undefined,
            lockboxes: [],
          },
        })
      }

      const tryToAddRoleWithoutLockboxesNullish = () => {
        alice.team.dispatch({
          type: 'ADD_ROLE',
          payload: {
            roleName: ADMIN,
            createdBy: alice.userId,
            permissions: undefined,
            lockboxes: undefined,
          } as any,
        })
      }

      expect(tryToAddRoleWithoutLockboxesEmpty).toThrow()
      expect(tryToAddRoleWithoutLockboxesNullish).toThrow()

      // Managers role still doesn't exist
      expect(alice.team.hasRole(MANAGERS)).toBe(false)
    })

    it('admins have access to all role keys', () => {
      const { alice } = setup('alice')

      // 👩🏾 Alice adds the managers role
      alice.team.addRole(managers)

      // 👩🏾 Alice is a member of the managers role by default
      expect(alice.team.memberHasRole(alice.userId, MANAGERS)).toBe(true)

      // But she does have access to the managers' keys
      const managersKeys = alice.team.roleKeys(MANAGERS)
      expect(managersKeys).toLookLikeKeyset()
    })

    it('adds a member to a role', () => {
      const { alice, bob } = setup('alice', { user: 'bob', admin: false })

      // 👨🏻‍🦲 Bob isn't an admin yet
      expect(alice.team.memberIsAdmin(bob.userId)).toBe(false)

      // 👩🏾 Alice makes 👨🏻‍🦲 Bob an admin
      alice.team.addMemberRole(bob.userId, ADMIN)

      // Now 👨🏻‍🦲 Bob is an admin
      expect(alice.team.memberIsAdmin(bob.userId)).toBe(true)

      // Alice persists the team
      const savedTeam = alice.team.save()

      // 👨🏻‍🦲 Bob loads the team
      bob.team = teams.load(savedTeam, bob.localContext, alice.team.teamKeys())

      // 👨🏻‍🦲 Bob has admin keys
      const bobsAdminKeys = bob.team.roleKeys(ADMIN)
      expect(bobsAdminKeys).toLookLikeKeyset()
    })

    it('fails to add a member to role when no lockboxes provided', () => {
      const { alice, bob } = setup('alice', { user: 'bob', admin: false })
      expect(alice.team.members().length).toBe(2)

      // 👨🏻‍🦲 Bob isn't an admin yet
      expect(alice.team.memberIsAdmin(bob.userId)).toBe(false)

      const tryToAddMemberWithoutLockboxesEmpty = () => {
        alice.team.dispatch({
          type: 'ADD_MEMBER_ROLE',
          payload: {
            userId: bob.userId,
            roleName: ADMIN,
            lockboxes: [],
          },
        })
      }

      const tryToAddMemberWithoutLockboxesNullish = () => {
        alice.team.dispatch({
          type: 'ADD_MEMBER_ROLE',
          payload: {
            userId: bob.userId,
            roleName: ADMIN,
            lockboxes: undefined,
          } as any,
        })
      }

      expect(tryToAddMemberWithoutLockboxesEmpty).toThrow()
      expect(tryToAddMemberWithoutLockboxesNullish).toThrow()

      // 👨🏻‍🦲 Bob still isn't an admin
      expect(alice.team.memberIsAdmin(bob.userId)).toBe(false)
    })

    it('removes a member from a role', () => {
      const { alice, bob } = setup('alice', 'bob')

      // Alice creates manager role and add 👨🏻‍🦲 Bob to it
      alice.team.addRole(managers)
      alice.team.addMemberRole(bob.userId, MANAGERS)

      // 👨🏻‍🦲 Bob is an admin
      expect(alice.team.memberIsAdmin(bob.userId)).toBe(true)

      // Alice removes 👨🏻‍🦲 Bob's admin role
      alice.team.removeMemberRole(bob.userId, ADMIN)

      // 👨🏻‍🦲 Bob is no longer an admin
      expect(alice.team.memberIsAdmin(bob.userId)).toBe(false)
      expect(alice.team.memberHasRole(bob.userId, MANAGERS)).toBe(true)

      // Alice persists the team
      const savedTeam = alice.team.save()

      // 👨🏻‍🦲 Bob loads the team
      bob.team = teams.load(savedTeam, bob.localContext, alice.team.teamKeys())

      // On his side, 👨🏻‍🦲 Bob can see that he is no longer an admin
      expect(bob.team.memberIsAdmin(bob.userId)).toBe(false)

      // 👨🏻‍🦲 Bob doesn't have admin keys any more
      const bobLooksForAdminKeys = () => bob.team.roleKeys(ADMIN)
      expect(bobLooksForAdminKeys).toThrow()
    })

    it('fails to remove a member from role when no lockboxes provided', () => {
      const { alice, bob } = setup('alice', 'bob')
      expect(alice.team.members().length).toBe(2)

      // 👨🏻‍🦲 Bob is an admin
      expect(alice.team.memberIsAdmin(bob.userId)).toBe(true)

      const tryToRemoveMemberWithoutLockboxesEmpty = () => {
        alice.team.dispatch({
          type: 'REMOVE_MEMBER_ROLE',
          payload: {
            userId: bob.userId,
            roleName: ADMIN,
            lockboxes: [],
          },
        })
      }

      const tryToRemoveMemberWithoutLockboxesNullish = () => {
        alice.team.dispatch({
          type: 'REMOVE_MEMBER_ROLE',
          payload: {
            userId: bob.userId,
            roleName: ADMIN,
            lockboxes: undefined,
          } as any,
        })
      }

      expect(tryToRemoveMemberWithoutLockboxesEmpty).toThrow()
      expect(tryToRemoveMemberWithoutLockboxesNullish).toThrow()

      // 👨🏻‍🦲 Bob is still an admin
      expect(alice.team.memberIsAdmin(bob.userId)).toBe(true)
    })

    it('self-assigns a role using pre-shared keys', () => {
      const { alice, bob } = setup('alice', { user: 'bob', admin: false, member: false })

      // 👩🏾 Alice is a MEMBER
      expect(alice.team.hasRole(MEMBER)).toBe(true)
      expect(alice.team.memberHasRole(alice.userId, MEMBER)).toBe(true)

      // 👩🏾 Alice creates a lockbox for MEMBER keys under arbitrary keys
      const randomSeed = randomUUID()
      const arbitraryScope: KeyScope = { type: 'TESTING', name: 'TESTING' }
      const keySet = createKeyset(arbitraryScope, randomSeed)
      alice.team.createLockbox(MEMBER, keySet)
      
      // 👩🏾 Alice persists the team
      const savedTeam = alice.team.save()

      // 👨🏻‍🦲 Bob loads the team
      bob.team = teams.load(savedTeam, bob.localContext, alice.team.teamKeys())

      // 👨🏻‍🦲 Bob doesn't have the MEMBER role
      expect(bob.team.memberHasRole(bob.userId, MEMBER)).toBe(false)

      // 👨🏻‍🦲 Bob self-assigns the MEMBER role
      bob.team.addMemberRoleToSelf(MEMBER, keySet)

      // 👨🏻‍🦲 Bob has the MEMBER role keys
      const bobsMemberKeys = bob.team.roleKeys(MEMBER)
      expect(bobsMemberKeys).toLookLikeKeyset()
    })

    it(`attempts to self-assign a role that can't be self-assigned`, () => {
      const { alice, bob } = setup('alice', 'bob')
      
      // 👩🏾 Alice creates FOOBAR role
      alice.team.addRole('FOOBAR')
      alice.team.addMemberRole(alice.userId, 'FOOBAR')

      // 👩🏾 Alice is a FOOBAR
      expect(alice.team.hasRole('FOOBAR')).toBe(true)
      expect(alice.team.memberHasRole(alice.userId, 'FOOBAR')).toBe(true)

      // 👩🏾 Alice creates a lockbox for FOOBAR keys under arbitrary keys
      const randomSeed = randomUUID()
      const arbitraryScope: KeyScope = { type: 'TESTING', name: 'TESTING' }
      const keySet = createKeyset(arbitraryScope, randomSeed)
      alice.team.createLockbox('FOOBAR', keySet)
      
      // 👩🏾 Alice persists the team
      const savedTeam = alice.team.save()

      // 👨🏻‍🦲 Bob loads the team
      bob.team = teams.load(savedTeam, bob.localContext, alice.team.teamKeys())

      // 👨🏻‍🦲 Bob doesn't have the FOOBAR role
      expect(bob.team.memberHasRole(bob.userId, 'FOOBAR')).toBe(false)

      // 👨🏻‍🦲 Bob attempts to self-assign the FOOBAR role
      const attemptToSelfAssignRole = () => {
        bob.team.addMemberRoleToSelf('FOOBAR', keySet)
      }
      expect(attemptToSelfAssignRole).toThrow()
    })

    it('removes a role', () => {
      const { alice } = setup('alice')

      // 👩🏾 Alice adds the managers role
      alice.team.addRole(managers)
      expect(alice.team.roles().map(r => r.roleName)).toEqual([ADMIN, MEMBER, MANAGERS])
      expect(alice.team.roles(MANAGERS).roleName).toBe(MANAGERS)

      // 👩🏾 Alice removes the managers role
      alice.team.removeRole(MANAGERS)
      expect(alice.team.roles().length).toBe(2) // admin, managers
    })

    it("won't remove the admin role", () => {
      const { alice } = setup('alice')

      // 👩🏾 Alice tries to remove the admin role
      const attemptToRemoveAdminRole = () => {
        alice.team.removeRole(ADMIN)
      }

      // She can't because that would be ridiculous
      expect(attemptToRemoveAdminRole).toThrow()
    })

    it('gets an individual role', () => {
      const { alice } = setup('alice')
      const adminRole = alice.team.roles(ADMIN)
      expect(adminRole.roleName).toBe(ADMIN)
    })

    it('throws if asked to get a nonexistent role', () => {
      const { alice } = setup('alice')
      const getNonexistentRole = () => alice.team.roles('spatula')
      expect(getNonexistentRole).toThrow(/not found/)
    })

    it('lists all roles', () => {
      const { alice } = setup('alice')
      alice.team.addRole(managers)
      const roles = alice.team.roles()
      expect(roles).toHaveLength(3) // admin, member, managers
      expect(roles.map(role => role.roleName)).toEqual([ADMIN, MEMBER, MANAGERS])
    })

    it('lists all members in a role ', () => {
      const { alice } = setup('alice', { user: 'bob', admin: true })

      // 👩🏾 Alice and 👨🏻‍🦲 Bob are members
      expect(alice.team.membersInRole(ADMIN).map(m => m.userName)).toEqual(['alice', 'bob'])
      expect(alice.team.admins().map(m => m.userName)).toEqual(['alice', 'bob'])
    })

    it(`excludes member from members in a role when they don't have a lockbox for that role`, () => {
      const { alice, bob } = setup('alice', { user: 'bob', admin: false, rolesWithoutLockboxes: [ADMIN] })

      // 👩🏾 Alice is the only member
      expect(alice.team.membersInRole(ADMIN).map(m => m.userName)).toEqual(['alice'])
      expect(alice.team.admins().map(m => m.userName)).toEqual(['alice'])
      expect(bob.team.memberHasRoleMarker(bob.userId, ADMIN)).toBe(true)
      expect(alice.team.memberHasRoleMarker(bob.userId, ADMIN)).toBe(true)
    })

    it('returns true for memberHasRole if user has role marker and lockbox', () => {
      const { alice } = setup('alice', { user: 'bob', admin: true })

      // 👩🏾 Alice and 👨🏻‍🦲 Bob are members
      expect(alice.team.memberHasRole(alice.userId, ADMIN)).toBe(true)
    })

    it('returns false for memberHasRole if user has no role marker or lockbox', () => {
      const { alice, bob } = setup('alice', { user: 'bob', admin: false })

      // 👩🏾 Alice and 👨🏻‍🦲 Bob are members
      expect(alice.team.memberHasRole(bob.userId, ADMIN)).toBe(false)
    })

    it('returns false for memberHasRole if user does not exist', () => {
      const { alice, bob } = setup('alice', { user: 'bob', admin: false })

      // 👩🏾 Alice and 👨🏻‍🦲 Bob are members
      expect(alice.team.memberHasRole('NOT_A_USER', ADMIN)).toBe(false)
    })

    it('returns false for memberHasRole if user has role marker but no lockbox', () => {
      const { alice, bob } = setup('alice', { user: 'bob', admin: false, rolesWithoutLockboxes: [ADMIN] })

      // 👩🏾 Alice and 👨🏻‍🦲 Bob are members
      expect(alice.team.memberHasRole(bob.userId, ADMIN)).toBe(false)
      expect(bob.team.memberHasRoleMarker(bob.userId, ADMIN)).toBe(true)
      expect(alice.team.memberHasRoleMarker(bob.userId, ADMIN)).toBe(true)
    })

    it('allows an admin other than Alice to add a member', () => {
      const { bob, charlie } = setup(
        'alice',
        { user: 'bob', admin: true },
        { user: 'charlie', member: false }
      )

      // 👨🏻‍🦲 Bob tries to add 👳🏽‍♂️ Charlie to the team
      const attemptToAddUser = () => {
        bob.team.addForTesting(charlie.user)
      }

      // 👨🏻‍🦲 Bob is allowed because he is an admin
      expect(attemptToAddUser).not.toThrow()
    })

    it('does not allow a non-admin to add a member', () => {
      const { bob, charlie } = setup(
        'alice',
        { user: 'bob', admin: false },
        { user: 'charlie', addToTeam: false }
      )

      // 👨🏻‍🦲 Bob tries to add 👳🏽‍♂️ Charlie to the team
      const addUser = () => {
        bob.team.addForTesting(charlie.user)
      }

      // 👨🏻‍🦲 Bob can't because he is not an admin
      expect(addUser).toThrow()
    })

    it('does not allow a non-admin to remove a member', () => {
      const { bob, charlie } = setup(
        'alice',
        { user: 'bob', admin: false },
        { user: 'charlie', admin: false }
      )

      // 👨🏻‍🦲 Bob tries to remove 👳🏽‍♂️ Charlie
      const remove = () => {
        bob.team.remove(charlie.userId)
      }

      // 👨🏻‍🦲 Bob can't because he is not an admin
      expect(remove).toThrow()
    })

    it('does not allow a non-admin to add a member to a role', () => {
      const { bob, charlie } = setup(
        'alice',
        { user: 'bob', admin: false },
        { user: 'charlie', admin: false }
      )

      // 👨🏻‍🦲 Bob tries to make 👳🏽‍♂️ Charlie an admin
      const add = () => {
        bob.team.addMemberRole(charlie.userId, ADMIN)
      }

      // 👨🏻‍🦲 Bob can't because he is not an admin
      expect(add).toThrow()
    })

    it('does not allow a non-admin to remove a member from a role', () => {
      const { charlie, bob } = setup('alice', 'bob', {
        user: 'charlie',
        admin: false,
      })

      // 👳🏽‍♂️ Charlie tries to remove 👨🏻‍🦲 Bob as admin
      const remove = () => {
        charlie.team.removeMemberRole(bob.userId, ADMIN)
      }

      // 👳🏽‍♂️ Charlie can't because he is not an admin
      expect(remove).toThrow()
    })

    it("can't remove the only admin", () => {
      const { alice } = setup('alice', { user: 'bob', admin: false })

      const remove = () => {
        alice.team.removeMemberRole(alice.userId, ADMIN)
      }

      expect(remove).toThrow()
    })

    it('Alice can remove herself as admin as long as there at least one other admin', () => {
      const { alice } = setup('alice', 'bob')

      const remove = () => {
        alice.team.removeMemberRole(alice.userId, ADMIN)
      }

      expect(remove).not.toThrow()
    })

    it('rotates keys when a member is removed from a role', async () => {
      const COOLKIDS = 'coolkids'

      const { alice, bob, charlie } = setup(
        'alice',
        { user: 'bob', admin: false },
        { user: 'charlie', admin: false }
      )

      alice.team.addRole(COOLKIDS)
      alice.team.addMemberRole(bob.userId, COOLKIDS)
      alice.team.addMemberRole(charlie.userId, COOLKIDS)

      const keys = alice.team.teamKeys()

      const savedTeam = alice.team.save()
      bob.team = teams.load(savedTeam, bob.localContext, keys)
      charlie.team = teams.load(savedTeam, charlie.localContext, keys)

      // 👨🏻‍🦲 Bob is currently in the cool kids
      expect(bob.team.memberHasRole(bob.userId, COOLKIDS)).toBe(true)

      // The cool kids keys have never been rotated
      expect(alice.team.roleKeys(COOLKIDS).generation).toBe(0)

      // 👩🏾 Alice encrypts something for the cool kids
      const message = "exclusive party at Alice's house tonight. cool kids only!!!"
      const encryptedMessage = alice.team.encrypt(message, COOLKIDS)
      // 👨🏻‍🦲 Bob and Charlie can both read the message

      expect(bob.team.decrypt(encryptedMessage)).toEqual(message)
      expect(charlie.team.decrypt(encryptedMessage)).toEqual(message)

      // Now, 👨🏻‍🦲 Bob suspects no one likes him so he makes a copy of his keys
      const copyOfKeysInCaseTheyKickMeOut = bob.team.roleKeys(COOLKIDS)

      // Sure enough, 👩🏾 Alice remembers that she can't stand 👨🏻‍🦲 Bob so she kicks him out
      alice.team.removeMemberRole(bob.userId, COOLKIDS)

      // Everyone gets the latest team state
      const savedTeam2 = alice.team.save()
      bob.team = teams.load(savedTeam2, bob.localContext, alice.team.teamKeys())
      charlie.team = teams.load(savedTeam2, charlie.localContext, alice.team.teamKeys())

      // 👳🏽‍♂️ Charlie can still read the message
      expect(charlie.team.decrypt(encryptedMessage)).toEqual(message)

      // 👨🏻‍🦲 Bob can no longer read the message through normal channels
      expect(() => bob.team.decrypt(encryptedMessage)).toThrow()

      // But with a little effort...
      const decryptUsingSavedKey = (message: teams.EncryptedEnvelope) => () =>
        symmetric.decryptBytes(message.contents, copyOfKeysInCaseTheyKickMeOut.secretKey)

      // 👨🏻‍🦲 Bob can still see the old message using his saved key, because it was encrypted before he
      // was kicked out (can't undisclose what you've disclosed)
      expect(decryptUsingSavedKey(encryptedMessage)).not.toThrow()

      // However! the group's keys have been rotated
      expect(alice.team.roleKeys(COOLKIDS).generation).toBe(1)

      // So 👩🏾 Alice encrypts a new message for the cool kids
      const newMessage = "party moved to Charlie's place, don't tell Bob"
      const newEncryptedMessage = alice.team.encrypt(newMessage, COOLKIDS)

      // 👳🏽‍♂️ Charlie can read the message
      expect(charlie.team.decrypt(newEncryptedMessage)).toEqual(newMessage)

      // 👨🏻‍🦲 Bob tries to read the new message with his old admin key, but he can't because it was
      // encrypted with the new key
      expect(decryptUsingSavedKey(newEncryptedMessage)).toThrow()
    })
  })
})
