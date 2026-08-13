import { ADMIN } from 'role/index.js'
import {
  TestChannel,
  any,
  anyDisconnected,
  anyUpdated,
  connect,
  connectPhoneWithInvitation,
  connectWithInvitation,
  disconnect,
  disconnection,
  expectEveryoneToKnowEveryone,
  joinTestChannel,
  setup,
  updated,
} from 'util/testing/index.js'
import { pause } from '@localfirst/shared'
import { describe, expect, it } from 'vitest'
import { type MemberContext } from '../types.js'

describe('connection', () => {
  describe('sync', () => {
    describe('two peers', () => {
      it('knows when users are up to date', async () => {
        const { alice, bob } = setup('alice', 'bob')

        // 👩🏾 👨🏻‍🦲 Alice and Bob connect
        await connect(alice, bob)
      })

      it('updates remote user after connecting', async () => {
        const { alice, bob } = setup('alice', 'bob')

        // At this point, Alice and Bob have the same signature chain

        // 👩🏾 but now Alice does some stuff
        alice.team.addRole('managers')
        alice.team.addMemberRole(bob.userId, 'managers')

        expect(alice.team.hasRole('managers')).toBe(true)
        expect(alice.team.memberHasRole(bob.userId, 'managers')).toBe(true)

        // 👨🏻‍🦲 Bob hasn't connected, so he doesn't have Alice's changes
        expect(bob.team.hasRole('managers')).toBe(false)
        expect(bob.team.memberHasRole(bob.userId, 'managers')).toBe(false)

        // 👩🏾 👨🏻‍🦲 Alice and Bob connect
        await connect(alice, bob)

        // ✅ 👨🏻‍🦲 Bob is up to date with Alice's changes
        expect(bob.team.hasRole('managers')).toBe(true)
        expect(bob.team.memberHasRole(bob.userId, 'managers')).toBe(true)
      })

      it('updates local user after connecting', async () => {
        const { alice, bob } = setup('alice', 'bob')

        // At this point, Alice and Bob have the same signature chain

        // 👨🏻‍🦲 but now Bob does some stuff. He puts Alice in the new role rather than himself,
        // since 'managers' isn't one of the team's self-assignable roles.
        bob.team.addRole('managers')
        bob.team.addMemberRole(alice.userId, 'managers')

        // 👩🏾 👨🏻‍🦲 Alice and Bob connect
        await connect(alice, bob)

        // ✅ 👩🏾 Alice is up to date with Bob's changes
        expect(alice.team.hasRole('managers')).toBe(true)
        expect(alice.team.memberHasRole(alice.userId, 'managers')).toBe(true)
      })

      it('updates remote user while connected', async () => {
        const { alice, bob } = setup('alice', 'bob')

        // 👩🏾 👨🏻‍🦲 Alice and Bob connect
        await connect(alice, bob)
        // At this point, Alice and Bob have the same signature chain

        // 👨🏻‍🦲 now Alice does some stuff
        alice.team.addRole('managers')

        await anyUpdated(alice, bob)

        // ✅ 👩🏾 Bob is up to date with Alice's changes
        expect(bob.team.hasRole('managers')).toBe(true)
      })

      it('updates local user while connected', async () => {
        const { alice, bob } = setup('alice', 'bob')

        // 👩🏾 👨🏻‍🦲 Alice and Bob connect
        await connect(alice, bob)

        // At this point, Alice and Bob have the same signature chain

        // 👨🏻‍🦲 now Bob does some stuff
        bob.team.addRole('managers')

        await anyUpdated(alice, bob)

        // ✅ 👩🏾 Alice is up to date with Bob's changes
        expect(alice.team.hasRole('managers')).toBe(true)
      })

      it('resolves concurrent non-conflicting changes when updating', async () => {
        const { alice, bob } = setup('alice', 'bob')

        // 👩🏾 Alice creates a new role
        expect(alice.team.hasRole('MANAGERS')).toBe(false)
        alice.team.addRole('MANAGERS')
        expect(alice.team.hasRole('MANAGERS')).toBe(true)

        // 👨🏻‍🦲 concurrently, Bob invites Charlie
        const { id } = bob.team.inviteMember()
        expect(bob.team.hasInvitation(id)).toBe(true)

        // Bob doesn't see the new role
        expect(bob.team.hasRole('MANAGERS')).toBe(false)

        // Alice doesn't see Bob's invitation for Charlie
        expect(alice.team.hasInvitation(id)).toBe(false)

        // 👩🏾<->👨🏻‍🦲 Alice and Bob connect
        await connect(alice, bob)

        // ✅ now Bob does see the new role 👨🏻‍🦲💭
        expect(bob.team.hasRole('MANAGERS')).toBe(true)

        // ✅ and Alice does see the invitation 👩🏾💭
        expect(alice.team.hasInvitation(id)).toBe(true)
      })

      it('resolves concurrent duplicate changes when updating', async () => {
        const { alice, bob } = setup('alice', 'bob')

        // 👩🏾 Alice creates a new role
        alice.team.addRole('MANAGERS')
        expect(alice.team.hasRole('MANAGERS')).toBe(true)

        // 👨🏻‍🦲 concurrently, Bob adds the same role
        bob.team.addRole('MANAGERS')
        expect(bob.team.hasRole('MANAGERS')).toBe(true)

        // 👩🏾<->👨🏻‍🦲 Alice and Bob connect
        await connect(alice, bob)

        // ✅ nothing blew up, and they both have the role
        expect(alice.team.hasRole('MANAGERS')).toBe(true)
        expect(bob.team.hasRole('MANAGERS')).toBe(true)
      })
    })

    describe('three or more peers', () => {
      it('sends updates across multiple hops', async () => {
        const { alice, bob, charlie } = setup('alice', 'bob', 'charlie')

        // 👩🏾 👨🏻‍🦲 Alice and Bob connect
        await connect(alice, bob)
        await connect(bob, charlie)

        // At this point, Alice and Bob have the same signature chain

        // 👨🏻‍🦲 now Alice does some stuff
        alice.team.addRole('managers')
        alice.team.addMemberRole(bob.userId, 'managers')

        await Promise.all([
          anyUpdated(alice, bob), //
          anyUpdated(bob, charlie),
        ])

        await pause(50)

        // ✅ 👩🏾 Bob is up to date with Alice's changes
        expect(bob.team.hasRole('managers')).toBe(true)

        // ✅ Charlie sees the new role, even though he's not connected directly to Alice 👳🏽‍♂️💭
        expect(charlie.team.hasRole('managers')).toBe(true)
      })

      it('syncs up  three ways - changes made after connecting', async () => {
        const { alice, bob, charlie } = setup('alice', 'bob', 'charlie')

        // 👩🏾<->👨🏻‍🦲<->👳🏽‍♂️ Alice, Bob, and Charlie all connect to each other
        await connect(alice, bob)
        await connect(bob, charlie)
        await connect(alice, charlie)

        // <-> while connected...

        // 👩🏾 Alice adds a new role
        alice.team.addRole('ALICES_FRIENDS')

        // 👨🏻‍🦲 Bob adds a new role
        bob.team.addRole('BOBS_FRIENDS')

        // 👳🏽‍♂️ Charlie adds a new role
        charlie.team.addRole('CHARLIES_FRIENDS')

        await Promise.all([
          updated(alice, bob), //
          updated(bob, charlie), //
          updated(alice, charlie),
        ])

        await pause(50)

        // ✅ All three get the three new roles
        expect(bob.team.hasRole('ALICES_FRIENDS')).toBe(true)
        expect(charlie.team.hasRole('ALICES_FRIENDS')).toBe(true)
        expect(alice.team.hasRole('CHARLIES_FRIENDS')).toBe(true)
        expect(bob.team.hasRole('CHARLIES_FRIENDS')).toBe(true)
        expect(alice.team.hasRole('BOBS_FRIENDS')).toBe(true)
        expect(charlie.team.hasRole('BOBS_FRIENDS')).toBe(true)
      })

      it('syncs up three ways - changes made before connecting', async () => {
        const { alice, bob, charlie } = setup('alice', 'bob', 'charlie')

        // 🔌 while disconnected...

        // 👩🏾 Alice adds a new role
        alice.team.addRole('ALICES_FRIENDS')

        // 👨🏻‍🦲 Bob adds a new role
        bob.team.addRole('BOBS_FRIENDS')

        // 👳🏽‍♂️ Charlie adds a new role
        charlie.team.addRole('CHARLIES_FRIENDS')

        // 👩🏾<->👨🏻‍🦲<->👳🏽‍♂️ Alice, Bob, and Charlie all connect to each other
        await connect(alice, bob)
        await connect(bob, charlie)
        await connect(alice, charlie)

        await pause(50)

        // ✅ All three get the three new roles
        expect(bob.team.hasRole('ALICES_FRIENDS')).toBe(true)
        expect(charlie.team.hasRole('ALICES_FRIENDS')).toBe(true)
        expect(alice.team.hasRole('CHARLIES_FRIENDS')).toBe(true)
        expect(bob.team.hasRole('CHARLIES_FRIENDS')).toBe(true)
        expect(alice.team.hasRole('BOBS_FRIENDS')).toBe(true)
        expect(charlie.team.hasRole('BOBS_FRIENDS')).toBe(true)
      })

      it('syncs up three ways - duplicate changes', async () => {
        const { alice, bob, charlie } = setup('alice', 'bob', 'charlie')

        // 🔌 while disconnected...

        // 👩🏾 Alice adds a new role
        alice.team.addRole('MANAGERS')

        // 👨🏻‍🦲 Bob adds the same role
        bob.team.addRole('MANAGERS')

        // 👳🏽‍♂️ Charlie adds the same role!! WHAT??!!
        charlie.team.addRole('MANAGERS')

        // 👩🏾<->👨🏻‍🦲<->👳🏽‍♂️ Alice, Bob, and Charlie all connect to each other
        await Promise.all([
          connect(alice, bob), //
          connect(bob, charlie),
          connect(alice, charlie),
        ])

        // ✅ All three get the three new roles, and nothing bad happened
        expect(alice.team.hasRole('MANAGERS')).toBe(true)
        expect(bob.team.hasRole('MANAGERS')).toBe(true)
        expect(charlie.team.hasRole('MANAGERS')).toBe(true)
      })
    })

    describe('invitations, removals and demotions', () => {
      it('eventually updates disconnected members when someone uses an invitation to join', async () => {
        const { alice, bob, charlie } = setup('alice', 'bob', {
          user: 'charlie',
          member: false,
        })

        // 👩🏾📧👳🏽‍♂️ Alice invites Charlie
        const { seed } = alice.team.inviteMember()

        // 👳🏽‍♂️📧<->👩🏾 Charlie connects to Alice and uses his invitation to join
        await connectWithInvitation(alice, charlie, seed)

        // 👩🏾<->👨🏻‍🦲 Alice and Bob connect
        await connect(alice, bob)

        // ✅
        expectEveryoneToKnowEveryone(alice, charlie, bob)
      })

      it('updates connected members when someone uses an invitation to join', async () => {
        const { alice, bob, charlie } = setup('alice', 'bob', {
          user: 'charlie',
          member: false,
        })

        // 👩🏾<->👨🏻‍🦲 Alice and Bob connect
        await connect(alice, bob)

        // 👩🏾📧👳🏽‍♂️👴 Alice invites Charlie
        const { seed } = alice.team.inviteMember()

        await Promise.all([
          // 👳🏽‍♂️📧<->👩🏾 Charlie connects to Alice and uses his invitation to join
          connectWithInvitation(alice, charlie, seed),
          // 👩🏾<->👨🏻‍🦲 Bob learns about Charlie from Alice
          anyUpdated(alice, bob),
        ])

        // ✅
        expectEveryoneToKnowEveryone(alice, charlie, bob)
      })

      it('resolves concurrent duplicate invitations when updating', async () => {
        const { alice, bob, charlie, dwight } = setup([
          'alice',
          'bob',
          { user: 'charlie', member: false },
          { user: 'dwight', member: false },
        ])

        // 👩🏾📧👳🏽‍♂️👴 Alice invites Charlie and Dwight
        const aliceInvitesCharlie = alice.team.inviteMember()
        const _aliceInvitesDwight = alice.team.inviteMember() // Invitation unused, but that's OK

        // 👨🏻‍🦲📧👳🏽‍♂️👴 concurrently, Bob invites Charlie and Dwight
        const _bobInvitesCharlie = bob.team.inviteMember() // Invitation unused, but that's OK
        const bobInvitesDwight = bob.team.inviteMember()

        // 👳🏽‍♂️📧<->👩🏾 Charlie connects to Alice and uses his invitation to join
        await connectWithInvitation(alice, charlie, aliceInvitesCharlie.seed)

        // 👴📧<->👨🏻‍🦲 Dwight connects to Bob and uses his invitation to join
        await connectWithInvitation(bob, dwight, bobInvitesDwight.seed)

        // 👩🏾<->👨🏻‍🦲 Alice and Bob connect
        await connect(alice, bob)
        await pause(100)

        // ✅ No problemo
        expectEveryoneToKnowEveryone(alice, charlie, bob, dwight)
      })

      it('resolves concurrent duplicate removals', async () => {
        const { alice, bob, charlie } = setup('alice', 'bob', 'charlie')

        // 👳🏽‍♂️ Charlie is a member
        expect(alice.team.has(charlie.userId)).toBe(true)
        expect(bob.team.has(charlie.userId)).toBe(true)

        // 👨🏻‍🦲 Bob removes 👳🏽‍♂️ Charlie
        bob.team.remove(charlie.userId)
        expect(alice.team.has(charlie.userId)).toBe(true)
        expect(bob.team.has(charlie.userId)).toBe(false)

        // 👩🏾 concurrently, Alice also removes 👳🏽‍♂️ Charlie
        alice.team.remove(charlie.userId)
        expect(alice.team.has(charlie.userId)).toBe(false)
        expect(bob.team.has(charlie.userId)).toBe(false)

        // 👩🏾<->👨🏻‍🦲 Alice and Bob connect
        await connect(alice, bob)

        // ✅ nothing blew up, and Charlie has been removed on both sides 🚫👳🏽‍♂️
        expect(alice.team.has(charlie.userId)).toBe(false)
        expect(bob.team.has(charlie.userId)).toBe(false)
      })

      it('lets a member remove the founder', async () => {
        const { alice, bob } = setup('alice', 'bob')

        // 👩🏾<->👨🏻‍🦲 Alice and Bob connect
        await connect(alice, bob)

        // 👨🏻‍🦲 Bob removes Alice
        bob.team.remove(alice.userId)

        // 👩🏾🔌👨🏻‍🦲 Alice is no longer a member, so they're disconnected
        await anyDisconnected(alice, bob)

        // ✅ Alice is no longer on the team 👩🏾👎
        expect(bob.team.has(alice.userId)).toBe(false)
      })

      it('resolves mutual demotions in favor of the senior member', async () => {
        const { alice, bob } = setup('alice', 'bob')
        await connect(alice, bob)

        // Both are admins
        expect(alice.team.memberIsAdmin(alice.userId)).toBe(true)
        expect(bob.team.memberIsAdmin(alice.userId)).toBe(true)
        expect(alice.team.memberIsAdmin(bob.userId)).toBe(true)
        expect(bob.team.memberIsAdmin(bob.userId)).toBe(true)

        // They both go offline
        await disconnect(alice, bob)

        // 👨🏻‍🦲 Bob removes 👩🏾 Alice from admin role
        bob.team.removeMemberRole(alice.userId, ADMIN)

        // 👩🏾 Alice concurrently removes 👨🏻‍🦲 Bob from admin role
        alice.team.removeMemberRole(bob.userId, ADMIN)

        // 👩🏾<->👨🏻‍🦲 Alice and Bob connect. Bob's demotion of Alice is discarded (because they were
        // done concurrently and Alice is senior so she wins)
        await connect(alice, bob)

        // ✅ Alice is still an admin 👩🏾👍
        expect(alice.team.memberIsAdmin(alice.userId)).toBe(true)
        expect(bob.team.memberIsAdmin(alice.userId)).toBe(true)

        // ✅ Bob is no longer an admin 👨🏻‍🦲👎
        expect(alice.team.memberIsAdmin(bob.userId)).toBe(false)
        expect(bob.team.memberIsAdmin(bob.userId)).toBe(false)

        // ✅ They are still connected 👩🏾<->👨🏻‍🦲
        expect(alice.getState(bob.deviceId)).toEqual('connected')
        expect(bob.getState(alice.deviceId)).toEqual('connected')
      })

      it("resolves mutual removals without invalidating the senior member's concurrent actions", async () => {
        const { alice, bob, charlie } = setup('alice', 'bob', 'charlie')

        // 👨🏻‍🦲 Bob removes 👩🏾 Alice
        bob.team.remove(alice.userId)

        // 👩🏾 Alice concurrently removes 👨🏻‍🦲 Bob
        alice.team.remove(bob.userId)

        // 👩🏾 Alice does something else on her phone (also concurrently)
        alice.team.addRole('MANAGERS')
        expect(alice.team.hasRole('MANAGERS')).toBe(true)

        // Charlie connects with both Alice and Bob
        await Promise.all([
          connect(charlie, alice), //
          connect(charlie, bob),
        ])

        // Bob is no longer on the team
        expect(charlie.team.has(bob.userId)).toBe(false)

        // Alice's change was not invalidated
        expect(charlie.team.hasRole('MANAGERS')).toBe(true)
      })

      it('gets both sides of the story in the case of mutual removals', async () => {
        const { alice, bob, charlie } = setup('alice', 'bob', 'charlie')

        // 👨🏻‍🦲 Bob removes 👩🏾 Alice
        bob.team.remove(alice.userId)

        // 👩🏾 Alice concurrently removes 👨🏻‍🦲 Bob
        alice.team.remove(bob.userId)

        // 👳🏽‍♂️<->👨🏻‍🦲 Charlie and Bob connect
        await connect(bob, charlie)

        // 👳🏽‍♂️💭 Charlie now knows that Bob has removed Alice
        expect(charlie.team.has(alice.userId)).toBe(false)

        await disconnect(bob, charlie)

        // 👳🏽‍♂️<->👩🏾 Charlie and Alice connect

        // Even though Charlie now thinks Alice has been removed, he still syncs with her because
        // she might have more information, e.g. that Bob (who removed her) was concurrently removed
        await connect(charlie, alice)

        expect(charlie.team.has(alice.userId)).toBe(true)
        expect(charlie.team.has(bob.userId)).toBe(false)

        // ✅ Charlie is disconnected from Bob because Bob is no longer a member 👳🏽‍♂️🔌👨🏻‍🦲
        await disconnection(bob, charlie)
      })

      it('when a member is demoted and makes concurrent admin-only changes, discards those changes', async () => {
        const { alice, bob, charlie } = setup('alice', 'bob', {
          user: 'charlie',
          admin: false,
        })

        // 👩🏾 Alice removes 👨🏻‍🦲 Bob from admin role
        alice.team.removeMemberRole(bob.userId, ADMIN)

        // 👨🏻‍🦲 concurrently, Bob makes 👳🏽‍♂️ Charlie an admin
        bob.team.addMemberRole(charlie.userId, ADMIN)
        expect(bob.team.memberHasRole(charlie.userId, ADMIN)).toBe(true)

        // 👩🏾<->👨🏻‍🦲 Alice and Bob connect
        await connect(alice, bob)

        // ✅ Bob's promotion of Charlie is discarded, because Bob concurrently lost admin privileges. 🚫👨🏻‍🦲👳🏽‍♂️
        expect(alice.team.memberHasRole(charlie.userId, ADMIN)).toBe(false)
        expect(bob.team.memberHasRole(charlie.userId, ADMIN)).toBe(false)
      })

      it('when a member is demoted and concurrently adds a device, the new device is kept', async () => {
        const { alice, bob } = setup('alice', 'bob')

        // 👩🏾 Alice removes 👨🏻‍🦲 Bob from admin role
        alice.team.removeMemberRole(bob.userId, ADMIN)

        // 👨🏻‍🦲💻📧📱 concurrently, on his laptop, Bob invites his phone
        const { seed } = bob.team.inviteDevice()

        // 💻<->📱 Bob's phone and laptop connect and the phone joins
        await connectPhoneWithInvitation(bob, seed)

        // 👨🏻‍🦲👍📱 Bob's phone is added to his list of devices
        expect(bob.team.members(bob.userId).devices).toHaveLength(2)

        // 👩🏾 Alice doesn't know about the new device
        expect(alice.team.members(alice.userId).devices).toHaveLength(1)

        // 👩🏾<->👨🏻‍🦲 Alice and Bob connect
        await connect(alice, bob)

        // ✅ Bob's phone is still in his devices
        expect(bob.team.members(bob.userId).devices).toHaveLength(2)

        // ✅ Alice knows about the new device
        expect(alice.team.members(bob.userId).devices).toHaveLength(2)
      })

      it('when an invitation is discarded, also discard related admittance actions', async () => {
        const { alice, bob, charlie } = setup('alice', 'bob', {
          user: 'charlie',
          member: false,
        })

        // 👩🏾 Alice removes 👨🏻‍🦲 Bob from admin role
        alice.team.removeMemberRole(bob.userId, ADMIN)

        // 👨🏻‍🦲 concurrently, Bob invites 👳🏽‍♂️ Charlie and admits him to the team
        const { seed } = bob.team.inviteMember()
        await connectWithInvitation(bob, charlie, seed)

        expect(bob.team.has(charlie.userId)).toBe(true)

        // 👩🏾<->👨🏻‍🦲 Alice and Bob connect
        await connect(alice, bob)

        // ✅ Bob's invitation is discarded, because Bob concurrently lost admin privileges
        expect(alice.team.has(charlie.userId)).toBe(false)
        expect(bob.team.has(charlie.userId)).toBe(false)
      })

      it('resolves circular concurrent demotions', async () => {
        const { alice, bob, charlie, dwight } = setup('alice', 'bob', 'charlie', 'dwight')

        // Bob demotes Charlie
        bob.team.removeMemberRole(charlie.userId, ADMIN)

        // Charlie demotes Alice
        charlie.team.removeMemberRole(alice.userId, ADMIN)

        // Alice demotes Bob
        alice.team.removeMemberRole(bob.userId, ADMIN)

        // Dwight connects to all three
        await Promise.all([
          connect(dwight, alice), //
          connect(dwight, bob),
          connect(dwight, charlie),
        ])

        const isAdmin = dwight.team.memberIsAdmin

        // Bob is no longer an admin
        expect(isAdmin(bob.userId)).toBe(false)

        // Alice is still an admin (because seniority)
        expect(isAdmin(alice.userId)).toBe(true)

        // Charlie is still an admin (because Bob demoted him while being demoted)
        expect(isAdmin(charlie.userId)).toBe(true)
      })

      it('Alice promotes Bob then demotes him', async () => {
        const { alice, bob } = setup('alice', { user: 'bob', admin: false })
        await connect(alice, bob)

        // 👨🏻‍🦲 Bob is not an admin
        expect(bob.team.memberIsAdmin(bob.userId)).toBe(false)

        // 👩🏾 Alice promotes Bob
        alice.team.addMemberRole(bob.userId, ADMIN)

        await anyUpdated(alice, bob)

        // 👨🏻‍🦲 Bob sees that he is admin
        expect(bob.team.memberIsAdmin(bob.userId)).toBe(true)

        // 👩🏾 Alice demotes Bob
        alice.team.removeMemberRole(bob.userId, ADMIN)
        await anyUpdated(alice, bob)

        // 👨🏻‍🦲 Bob sees that he is no longer admin
        expect(alice.team.memberIsAdmin(bob.userId)).toBe(false)
        expect(bob.team.memberIsAdmin(bob.userId)).toBe(false)
      })

      it('rotates keys after a member is removed', async () => {
        const { alice, bob } = setup('alice', 'bob')
        await connect(alice, bob)

        // 👨🏻‍🦲 Bob has admin keys
        expect(() => bob.team.adminKeys()).not.toThrow()

        // We have the first-generation keys
        expect(alice.team.adminKeys().generation).toBe(0)
        expect(alice.team.teamKeys().generation).toBe(0)

        // <-> while connected...

        // 👩🏾 Alice removes Bob from the team
        alice.team.remove(bob.userId)
        await anyDisconnected(alice, bob)

        // The admin keys and team keys have been rotated
        expect(alice.team.adminKeys().generation).toBe(1)
        expect(alice.team.teamKeys().generation).toBe(1)
      })

      it('rotates keys after a member is demoted', async () => {
        const { alice, bob } = setup('alice', 'bob')
        await connect(alice, bob)

        // 👨🏻‍🦲 Bob has admin keys
        expect(() => bob.team.adminKeys()).not.toThrow()

        // We have the first-generation keys
        expect(alice.team.adminKeys().generation).toBe(0)

        // <-> while connected...

        // 👩🏾 Alice demotes Bob
        alice.team.removeMemberRole(bob.userId, ADMIN)
        await anyUpdated(alice, bob)

        // 👨🏻‍🦲 Bob no longer has admin keys
        expect(() => bob.team.adminKeys()).toThrow()

        // The admin keys have been rotated
        expect(alice.team.adminKeys().generation).toBe(1)

        // The team keys haven't been rotated because Bob wasn't removed from the team
        expect(alice.team.teamKeys().generation).toBe(0)
      })

      it('decrypts new links received following a key rotation (upon connecting)', async () => {
        const { alice, bob, charlie } = setup('alice', 'bob', 'charlie')

        await connect(alice, bob)

        // 👩🏾 Alice removes 👨🏻‍🦲 Bob from the team
        alice.team.remove(bob.userId)
        await anyDisconnected(alice, bob)

        // The team keys have been rotated
        expect(alice.team.teamKeys().generation).toBe(1)

        // Alice does something else — say she creates a new role
        // This will now be encrypted with the new team keys
        alice.team.addRole('managers')

        await connect(alice, charlie)

        // Charlie can decrypt the last link Alice created
        expect(charlie.team.hasRole('managers')).toBe(true)
      })

      it('allows a new member to join after team keys have been rotated', async () => {
        const { alice, bob, charlie } = setup(['alice', 'bob', { user: 'charlie', member: false }])

        await connect(alice, bob)

        // Alice removes Bob from the team
        alice.team.remove(bob.userId)
        await anyDisconnected(alice, bob)

        // The team keys have been rotated
        expect(alice.team.teamKeys().generation).toBe(1)

        // Alice does something else — say she creates a new role
        // This will now be encrypted with the new team keys
        alice.team.addRole('managers')

        // Alice invites Charlie
        const { seed } = alice.team.inviteMember()
        await connectWithInvitation(alice, charlie, seed)

        // Charlie can decrypt the last link Alice created
        expect(charlie.team.hasRole('managers')).toBe(true)
      })

      it('decrypts new links received following a key rotation (while connected)', async () => {
        const { alice, bob, charlie } = setup('alice', 'bob', 'charlie')

        await connect(alice, bob)
        await connect(alice, charlie)

        // 👩🏾 Alice removes 👨🏻‍🦲 Bob from the team
        alice.team.remove(bob.userId)
        await anyDisconnected(alice, bob)
        await anyUpdated(alice, charlie)

        // The team keys have been rotated
        expect(alice.team.teamKeys().generation).toBe(1)

        // Alice does something else — say she creates a new role
        // This will now be encrypted with the new team keys
        alice.team.addRole('managers')

        // wait for 👳🏽‍♂️ Charlie to get changes
        await anyUpdated(alice, charlie)

        // Charlie can decrypt the last link Alice created
        expect(charlie.team.hasRole('managers')).toBe(true)
      })

      it('unwinds an invalidated admission', async () => {
        const { alice, bob, charlie } = setup('alice', 'bob', {
          user: 'charlie',
          member: false,
        })
        expect(alice.team.adminKeys().generation).toBe(0)

        // While disconnected...
        // Alice demotes Bob
        alice.team.removeMemberRole(bob.userId, ADMIN)
        // The admin keys are rotated
        expect(alice.team.adminKeys().generation).toBe(1)

        // Bob invites Charlie & Charlie joins
        const { seed } = bob.team.inviteMember()
        await connectWithInvitation(bob, charlie, seed)

        // Then...
        // Alice and Bob connect
        await connect(alice, bob)

        // Charlie's admission is invalidated
        expect(alice.team.has(charlie.userId)).toBe(false)
        expect(bob.team.has(charlie.userId)).toBe(false)

        // Alice has rotated the team keys
        expect(alice.team.teamKeys().generation).toBe(1)
        // And all other keys, for good measure
        expect(alice.team.adminKeys().generation).toBe(2)
      })
    })

    describe('post-compromise recovery', () => {
      it("Eve steals Bob's phone; Bob heals the team", async () => {
        const { alice, bob, charlie } = setup('alice', 'bob', 'charlie')
        await connect(alice, bob)
        await connect(bob, charlie)

        // Bob invites his phone and it joins
        const { seed } = bob.team.inviteDevice()
        await Promise.all([connectPhoneWithInvitation(bob, seed), pause(10)])

        // Bob and Alice know about Bob's phone
        expect(bob.team.members(bob.userId).devices).toHaveLength(2)
        expect(alice.team.members(bob.userId).devices).toHaveLength(2)

        // Eve steals Bob's phone.

        // From his laptop, Bob removes his phone from the team
        bob.team.removeDevice(bob.phone!.deviceId)
        expect(bob.team.members(bob.userId).devices).toHaveLength(1)

        await pause(10)

        // Alice and Charlie can see that Bob only has one device
        expect(alice.team.members(bob.userId).devices).toHaveLength(1)
        expect(charlie.team.members(bob.userId).devices).toHaveLength(1)

        // Eve tries to connect to Charlie from Bob's phone, but she can't
        const phoneContext: MemberContext = {
          device: bob.phone!,
          user: bob.user,
          team: bob.team,
        }

        const join = joinTestChannel(new TestChannel())

        const eveOnBobsPhone = join(phoneContext).start()
        const heyCharlie = join(charlie.connectionContext).start()

        // GRRR foiled again
        await any([eveOnBobsPhone, heyCharlie], 'disconnected')
      })
    })
  })
})
