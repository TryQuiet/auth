import { eventPromise, pause } from '@localfirst/shared'
import { cloneDeep } from 'lodash-es'
import { ADMIN } from 'role/index.js'
import * as teams from 'team/index.js'
import {
  TestChannel,
  all,
  anyDisconnected,
  anyUpdated,
  connect,
  connectWithInvitation,
  disconnect,
  expectEveryoneToKnowEveryone,
  joinTestChannel,
  setup,
  tryToConnect,
} from 'util/testing/index.js'
import { describe, expect, it } from 'vitest'
import type { InviteeDeviceContext } from '../types.js'

describe('connection', () => {
  describe('authentication', () => {
    describe('with known members', () => {
      it('connects two members', async () => {
        const { alice, bob } = setup('alice', 'bob')

        // 👩🏾 👨🏻‍🦲 Alice and Bob both join the channel
        await connect(alice, bob)

        // 👩🏾 👨🏻‍🦲 Alice and Bob both leave the channel
        await disconnect(alice, bob)
      })

      // Protocol 4 disables removal/rotation; retained as a historical revocation specification.
      it.skip("doesn't connect with a member who has been removed", async () => {
        const { alice, bob } = setup('alice', 'bob')

        // 👩🏾 Alice removes Bob
        alice.team.remove(bob.userId)

        // ❌ They can't connect because Bob was removed
        void tryToConnect(alice, bob)
        await anyDisconnected(alice, bob)
      })

      it("doesn't connect with someone who doesn't belong to the team", async () => {
        const { alice, charlie } = setup('alice', 'bob', {
          user: 'charlie',
          member: false,
        })

        charlie.connectionContext = {
          team: teams.createTeam('team charlie', {
            device: charlie.device,
            user: charlie.user,
          }),
          userName: 'charlie',
          user: charlie.user,
          device: charlie.device,
        }

        // ❌ Alice and Charlie can't connect because they're on different teams
        void tryToConnect(alice, charlie)
        await anyDisconnected(alice, charlie)
      })

      it('can reconnect after disconnecting', async () => {
        const { alice, bob } = setup('alice', 'bob')
        // 👩🏾<->👨🏻‍🦲 Alice and Bob connect
        await connect(alice, bob)

        // 👩🏾🔌👨🏻‍🦲 Alice disconnects
        await disconnect(alice, bob)

        // 👩🏾<->👨🏻‍🦲 Alice reconnects
        await connect(alice, bob)

        // ✅ all good
      })

      it("doesn't connect if a peer's signature keys are wrong", async () => {
        const { alice, bob, eve } = setup('alice', 'bob', 'eve')

        // 🦹‍♀️ Eve is going to try to impersonate 👨🏻‍🦲 Bob, but fortunately she doesn't know his secret signature key
        const fakeBob = cloneDeep(bob.device)
        fakeBob.keys.signature.secretKey = eve.user.keys.signature.secretKey

        eve.connectionContext.device = fakeBob
        void connect(alice, eve)

        // Without Bob's secret signature key, Eve won't be able to fake the signature challenge
        const error = await eventPromise(eve.connection[alice.deviceId], 'remoteError')
        expect(error.type).toEqual('IDENTITY_PROOF_INVALID') // ❌
      })

      it("doesn't connect if a peer's encryption keys are wrong", async () => {
        const { alice, bob, eve } = setup('alice', 'bob', 'eve')

        // 🦹‍♀️ Eve is going to try to impersonate 👨🏻‍🦲 Bob, but fortunately she doesn't know his secret encryption key
        const fakeBob = cloneDeep(bob.device)
        fakeBob.keys.encryption.secretKey = eve.user.keys.encryption.secretKey

        eve.connectionContext.device = fakeBob
        void connect(alice, eve)

        // Without Bob's secret encryption key, Eve won't be able to converge on a shared secret
        const error = await eventPromise(eve.connection[alice.deviceId], 'remoteError')
        expect(error.type).toEqual('ENCRYPTION_FAILURE') // ❌
      })
    })

    describe('with invitations', () => {
      it('connects an invitee with a member', async () => {
        const { alice, bob } = setup('alice', { user: 'bob', member: false })

        // 👩🏾📧👨🏻‍🦲 Alice invites Bob
        const { seed } = alice.team.inviteMember()

        // 👨🏻‍🦲📧<->👩🏾 Bob connects to Alice and uses his invitation to join
        await connectWithInvitation(alice, bob, seed)

        // ✅
        expectEveryoneToKnowEveryone(alice, bob)
      })

      it('alice invites bob then bob invites charlie', async () => {
        const { alice, bob, charlie } = setup(
          'alice',
          { user: 'bob', member: false },
          { user: 'charlie', member: false }
        )

        // 👩🏾📧👨🏻‍🦲 Alice invites Bob
        const { seed: bobSeed } = alice.team.inviteMember()

        // 👨🏻‍🦲📧<->👩🏾 Bob connects to Alice and uses his invitation to join
        await connectWithInvitation(alice, bob, bobSeed)
        expectEveryoneToKnowEveryone(alice, bob)

        // Alice promotes Bob
        alice.team.addMemberRole(bob.userId, ADMIN)
        await anyUpdated(alice, bob)

        // Bob invites Charlie
        const { seed: charlieSeed } = bob.team.inviteMember()

        // Charlie connects to Alice and uses his invitation to join
        await connectWithInvitation(alice, charlie, charlieSeed)

        // ✅
        expectEveryoneToKnowEveryone(alice, bob, charlie)
      })

      it('after being admitted, invitee has team keys', async () => {
        const { alice, bob } = setup('alice', { user: 'bob', member: false })

        // 👩🏾📧👨🏻‍🦲 Alice invites Bob
        const { seed } = alice.team.inviteMember()

        // 👨🏻‍🦲📧<->👩🏾 Bob connects to Alice and uses his invitation to join
        await connectWithInvitation(alice, bob, seed)

        // Update the team from the connection, which should have the new keys
        const connection = bob.connection[alice.deviceId]
        bob.team = connection.team!

        // 👨🏻‍🦲 Bob has the team keys
        expect(() => bob.team.teamKeys()).not.toThrow()
      })

      it('after an invitee is admitted, the device recorded on the team includes user-agent metadata', async () => {
        const { alice, bob } = setup('alice', { user: 'bob', member: false })

        // 👩🏾📧👨🏻‍🦲 Alice invites Bob
        const { seed } = alice.team.inviteMember()

        // 👨🏻‍🦲📧<->👩🏾 Bob connects to Alice and uses his invitation to join
        await connectWithInvitation(alice, bob, seed)

        // Update the team from the connection
        const connection = bob.connection[alice.deviceId]
        bob.team = connection.team!

        // 👨🏻‍🦲 Bob's device was recorded with user-agent metadata
        const { deviceId } = bob.device
        const device = bob.team.device(deviceId)
        expect(device?.deviceInfo).toEqual(bob.device.deviceInfo)
      })

      it("doesn't allow two invitees to connect", async () => {
        const { alice, charlie, dwight } = setup([
          'alice',
          { user: 'charlie', member: false },
          { user: 'dwight', member: false },
        ])

        // 👩🏾 Alice invites 👳🏽‍♂️ Charlie
        const { seed: charlieSeed } = alice.team.inviteMember()
        charlie.connectionContext = {
          ...charlie.connectionContext,
          invitationSeed: charlieSeed,
        }

        // 👩🏾 Alice invites 👴 Dwight
        const { seed: dwightSeed } = alice.team.inviteMember()
        dwight.connectionContext = {
          ...dwight.connectionContext,
          invitationSeed: dwightSeed,
        }

        expect(await connect(charlie, dwight)).toEqual(false)
      })

      it('lets a member use an invitation to add a device', async () => {
        const { alice, bob } = setup('alice', 'bob')

        await connect(alice, bob)

        expect(bob.team.members(bob.userId).devices).toHaveLength(1)

        // 👨🏻‍🦲💻📧->📱 on his laptop, Bob creates an invitation and gets it to his phone
        const { seed, teamId } = bob.team.inviteDevice()

        // 💻<->📱📧 Bob's phone and laptop connect and the phone joins
        const phoneContext: InviteeDeviceContext = {
          userName: bob.userName,
          device: bob.phone!,
          invitationSeed: seed,
          expectedTeamId: teamId,
        }
        const join = joinTestChannel(new TestChannel())

        const laptopConnection = join(bob.connectionContext).start()
        const phoneConnection = join(phoneContext).start()

        await all([laptopConnection, phoneConnection], 'connected')

        bob.team = laptopConnection.team!

        // 👨🏻‍🦲👍📱 Bob's phone is added to his list of devices
        expect(bob.team.members(bob.userId).devices).toHaveLength(2)

        // ✅ 👩🏾👍📱 Alice knows about Bob's phone
        expect(alice.team.members(bob.userId).devices).toHaveLength(2)
      })

      it('admits a first-use device before continuing authentication', async () => {
        const { bob } = setup('bob')
        bob.team.addRole('member')
        const { userId: _userId, ...phone } = bob.phone!
        const { seed, teamId } = bob.team.inviteDevice()
        const phoneContext: InviteeDeviceContext = {
          userName: bob.userName,
          device: phone,
          invitationSeed: seed,
          expectedTeamId: teamId,
        }
        const join = joinTestChannel(new TestChannel())
        const laptopConnection = join(bob.connectionContext)
        const phoneConnection = join(phoneContext)
        const joined = eventPromise(phoneConnection, 'joined')

        laptopConnection.start()
        phoneConnection.start()

        await expect(joined).resolves.toMatchObject({ user: { userId: bob.userId } })
        expect(phoneConnection.team!.hasDevice(phone.deviceId)).toBe(true)
      })

      // Protocol 4 disables removal/rotation; retained as a historical revocation specification.
      it.skip("won't re-admit a device that was removed, even with a fresh invitation", async () => {
        const { alice, bob } = setup('alice', 'bob')
        await connect(alice, bob)

        // Bob invites and admits his phone

        const phone = bob.phone!

        {
          const { seed, teamId } = bob.team.inviteDevice()
          const phoneContext: InviteeDeviceContext = {
            userName: bob.userName,
            device: phone,
            invitationSeed: seed,
            expectedTeamId: teamId,
          }
          const join = joinTestChannel(new TestChannel())
          const laptopConnection = join(bob.connectionContext).start()
          const phoneConnection = join(phoneContext).start()
          await all([laptopConnection, phoneConnection], 'connected')

          bob.team = laptopConnection.team!

          expect(bob.team.members(bob.userId).devices).toHaveLength(2)
          expect(alice.team.members(bob.userId).devices).toHaveLength(2)

          // Bob removes his phone
          laptopConnection.stop()
          bob.team.removeDevice(phone.deviceId)
          await anyUpdated(alice, bob)
          await pause(50)

          expect(bob.team.members(bob.userId).devices).toHaveLength(1)
          expect(alice.team.members(bob.userId).devices).toHaveLength(1)
        }
        {
          // Bob invites his phone again. A removed device is tombstoned: its id is the fingerprint
          // of keys the team has already retired, and it can never be registered again — otherwise
          // whoever took the device could talk their way back onto the team.

          const { seed, teamId } = bob.team.inviteDevice()
          const phoneContext: InviteeDeviceContext = {
            userName: bob.userName,
            device: phone,
            invitationSeed: seed,
            expectedTeamId: teamId,
          }
          const join = joinTestChannel(new TestChannel())
          const laptopConnection = join(bob.connectionContext).start()
          const phoneConnection = join(phoneContext).start()

          const error = await eventPromise(phoneConnection, 'remoteError')
          expect(error.type).toEqual('DEVICE_REMOVED') // ❌

          bob.team = laptopConnection.team!
          expect(bob.team.members(bob.userId).devices).toHaveLength(1)
        }
      })

      it('lets a different member admit an invited device', async () => {
        const { alice, bob } = setup('alice', 'bob')

        await connect(alice, bob)

        expect(bob.team.members(bob.userId).devices).toHaveLength(1)

        // 👨🏻‍🦲💻📧->📱 on his laptop, Bob creates an invitation and gets it to his phone
        const { seed, teamId } = bob.team.inviteDevice()

        // 💻<->📱📧 Bob's phone and Alice's laptop connect and the phone joins
        const phoneContext: InviteeDeviceContext = {
          userName: bob.userName,
          device: bob.phone!,
          invitationSeed: seed,
          expectedTeamId: teamId,
        }
        const join = joinTestChannel(new TestChannel())
        const aliceConnection = join(alice.connectionContext).start()
        const bobPhoneConnection = join(phoneContext).start()

        await all([aliceConnection, bobPhoneConnection], 'connected')

        alice.team = aliceConnection.team!

        // 👨🏻‍🦲👍📱 Bob's phone is added to his list of devices
        expect(alice.team.members(bob.userId).devices).toHaveLength(2)

        // ✅ 👩🏾👍📱 Alice knows about Bob's phone
        expect(alice.team.members(bob.userId).devices).toHaveLength(2)
      })

      it('fails to connect when the wrong invitation code is entered', async () => {
        const { alice, bob } = setup('alice', { user: 'bob', member: false })

        // 👩🏾📧👨🏻‍🦲 Alice invites Bob
        const seed = 'passw0rd'
        const { teamId } = alice.team.inviteMember({ seed })

        // 👨🏻‍🦲📧<->👩🏾 Bob tries to connect, but mistypes his code
        bob.connectionContext = {
          ...bob.connectionContext,
          invitationSeed: 'password',
          expectedTeamId: teamId,
        }

        void connect(bob, alice)
        const error = await eventPromise(bob.connection[alice.deviceId], 'remoteError')
        expect(error.type).toEqual(`INVITATION_PROOF_INVALID`)
      })

      it('connects an invitee after one failed attempt', async () => {
        const { alice, bob } = setup('alice', { user: 'bob', member: false })

        // 👩🏾📧👨🏻‍🦲 Alice invites Bob
        const seed = 'passw0rd'
        const { teamId } = alice.team.inviteMember({ seed })

        // 👨🏻‍🦲📧<->👩🏾 Bob tries to connect, but mistypes his code
        bob.connectionContext = {
          ...bob.connectionContext,
          invitationSeed: 'password',
          expectedTeamId: teamId,
        }

        {
          // ❌ The connection fails
          const connected = await connect(bob, alice)
          expect(connected).toEqual(false)
        }

        // 👨🏻‍🦲📧<->👩🏾 Bob tries again with the right code this time
        bob.connectionContext = {
          ...bob.connectionContext,
          invitationSeed: 'passw0rd',
          expectedTeamId: teamId,
        }

        {
          // ✅ that works
          const connected = await connect(bob, alice)
          expect(connected).toEqual(true)
          bob.team = bob.connection[alice.deviceId].team!
        }

        expectEveryoneToKnowEveryone(alice, bob)
      })
    })
  })
})
