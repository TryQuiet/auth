import { createKeyset, type UnixTimestamp } from '@localfirst/crdx'
import { signatures } from '@localfirst/crypto'
import { createDevice, redactDevice, type FirstUseDevice } from 'index.js'
import * as teams from 'team/index.js'
import { KeyType } from 'util/index.js'
import {
  deviceInvitationProof,
  memberInvitationProof,
  redactFirstUseDevice,
  setup,
} from 'util/testing/index.js'
import { describe, expect, it } from 'vitest'

const { USER } = KeyType

describe('Team', () => {
  describe('invitations', () => {
    describe('members', () => {
      it('accepts valid proof of invitation', () => {
        const { alice, bob } = setup('alice', { user: 'bob', member: false })

        // 👩🏾 Alice invites 👨🏻‍🦲 Bob by sending him a random secret key
        const { seed } = alice.team.inviteMember()

        // 👨🏻‍🦲 Bob accepts the invitation
        const proofOfInvitation = memberInvitationProof(seed, bob.user, bob.device)

        // 👨🏻‍🦲 Bob shows 👩🏾 Alice his proof of invitation, and she lets him in, associating
        // him with the public keys he's provided
        alice.team.admitMember(
          proofOfInvitation,
          bob.user.keys,
          bob.user.userName,
          redactDevice(bob.device)
        )

        // ✅ 👨🏻‍🦲 Bob is now on the team. Congratulations, Bob!
        expect(alice.team.has(bob.userId)).toBe(true)
      })

      it('lets you use a secret invitation seed of your choosing', () => {
        const { alice, bob } = setup('alice', { user: 'bob', member: false })

        // 👩🏾 Alice invites 👨🏻‍🦲 Bob by sending him a secret key of her choosing
        const seed = 'passw0rd'
        alice.team.inviteMember({ seed })

        const proofOfInvitation = memberInvitationProof(seed, bob.user, bob.device)

        alice.team.admitMember(
          proofOfInvitation,
          bob.user.keys,
          bob.user.userName,
          redactDevice(bob.device)
        )

        // ✅ Still works
        expect(alice.team.has(bob.userId)).toBe(true)
      })

      it('normalizes the a secret invitation seed ', () => {
        const { alice, bob } = setup('alice', { user: 'bob', member: false })

        // 👩🏾 Alice invites 👨🏻‍🦲 Bob
        const seed = 'abc def ghi'
        alice.team.inviteMember({ seed })

        // 👨🏻‍🦲 Bob accepts the invitation using a url-friendlier version of the key
        const proofOfInvitation = memberInvitationProof(
          'abc+def+ghi',
          bob.user,
          bob.device
        )
        alice.team.admitMember(
          proofOfInvitation,
          bob.user.keys,
          bob.user.userName,
          redactDevice(bob.device)
        )

        // ✅ Bob is on the team
        expect(alice.team.has(bob.userId)).toBe(true)
      })

      it('allows non-admins to accept an invitation', () => {
        const { alice, bob, charlie } = setup(
          'alice',
          { user: 'bob', admin: false },
          { user: 'charlie', member: false }
        )

        // 👩🏾 Alice invites 👳🏽‍♂️ Charlie by sending him a secret key
        const { seed } = alice.team.inviteMember()

        // 👳🏽‍♂️ Charlie accepts the invitation
        const proofOfInvitation = memberInvitationProof(seed, charlie.user, charlie.device)

        // Later, 👩🏾 Alice is no longer around, but 👨🏻‍🦲 Bob is online
        let persistedTeam = alice.team.save()
        const bobsTeam = teams.load(persistedTeam, bob.localContext, alice.team.teamKeys())

        // Just to confirm: 👨🏻‍🦲 Bob isn't an admin
        expect(bobsTeam.memberIsAdmin(bob.userId)).toBe(false)

        // 👳🏽‍♂️ Charlie shows 👨🏻‍🦲 Bob his proof of invitation
        bobsTeam.admitMember(
          proofOfInvitation,
          charlie.user.keys,
          charlie.user.userName,
          redactDevice(charlie.device)
        )

        // 👍👳🏽‍♂️ Charlie is now on the team
        expect(bobsTeam.has(charlie.userId)).toBe(true)

        // ✅ 👩🏾 Alice can now see that 👳🏽‍♂️ Charlie is on the team. Congratulations, Charlie!
        persistedTeam = bobsTeam.save()
        alice.team = teams.load(persistedTeam, alice.localContext, alice.team.teamKeys())
        expect(alice.team.has(charlie.userId)).toBe(true)
      })

      it("will use an invitation that hasn't expired yet", () => {
        const { alice, bob } = setup('alice', { user: 'bob', member: false })

        // 👩🏾 Alice invites 👨🏻‍🦲 Bob with a future expiration date
        const expiration = new Date(Date.UTC(2999, 12, 25)).valueOf() as UnixTimestamp // NOTE 👩‍🚀 this test will fail if run in the distant future
        const { seed } = alice.team.inviteMember({ expiration })
        const proofOfInvitation = memberInvitationProof(seed, bob.user, bob.device)
        alice.team.admitMember(
          proofOfInvitation,
          bob.user.keys,
          bob.user.userName,
          redactDevice(bob.device)
        )

        // ✅ 👨🏻‍🦲 Bob's invitation has not expired so he is on the team
        expect(alice.team.has(bob.userId)).toBe(true)
      })

      it("won't use an expired invitation", () => {
        const { alice, bob } = setup('alice', { user: 'bob', member: false })

        // A long time ago 👩🏾 Alice invited 👨🏻‍🦲 Bob
        const expiration = new Date(Date.UTC(2020, 12, 25)).valueOf() as UnixTimestamp
        const { seed } = alice.team.inviteMember({ expiration })
        const proofOfInvitation = memberInvitationProof(seed, bob.user, bob.device)

        const tryToAdmitBob = () => {
          alice.team.admitMember(
            proofOfInvitation,
            bob.user.keys,
            bob.user.userName,
            redactDevice(bob.device)
          )
        }

        // 👎 👨🏻‍🦲 Bob's invitation has expired so he can't get in
        expect(tryToAdmitBob).toThrowError(/expired/)

        // ❌ 👨🏻‍🦲 Bob is not on the team
        expect(alice.team.has(bob.userId)).toBe(false)
      })

      it('can use an invitation multiple times', () => {
        const { alice, bob, charlie } = setup(
          'alice',
          { user: 'bob', member: false },
          { user: 'charlie', member: false }
        )

        const { seed } = alice.team.inviteMember({ maxUses: 2 })

        // 👨🏻‍🦲 Bob and 👳🏽‍♂️ Charlie both generate the same proof of invitation from the seed
        const bobProof = memberInvitationProof(seed, bob.user, bob.device)
        const charlieProof = memberInvitationProof(seed, charlie.user, charlie.device)

        // 👩🏾 Alice admits them both

        alice.team.admitMember(
          bobProof,
          bob.user.keys,
          bob.user.userName,
          redactDevice(bob.device)
        )
        alice.team.admitMember(
          charlieProof,
          charlie.user.keys,
          charlie.user.userName,
          redactDevice(charlie.device)
        )

        // ✅ 👨🏻‍🦲 Bob and 👳🏽‍♂️ Charlie are both on the team
        expect(alice.team.has(bob.userId)).toBe(true)
        expect(alice.team.has(charlie.userId)).toBe(true)
      })

      it('can use an invitation infinite uses when maxUses is zero', () => {
        const { alice } = setup('alice')

        // 👩🏾 Alice makes an invitation that anyone can use
        const { seed } = alice.team.inviteMember({ maxUses: 0 }) // No limit
        // A bunch of people use the same invitation and 👩🏾 Alice admits them all
        const invitees = `
            amanda, bob, charlie, dwight, edwin, frida, gertrude, herbert, 
            ignaszi, joão, krishna, lashawn, mary, ngunda, oprah, phil, quân, 
            rainbow, steve, thad, uriah, vanessa, wade, xerxes, yazmin, zelda`
          .replaceAll(/\s/g, '')
          .split(',')
        for (const userId of invitees) {
          const userKeys = createKeyset({ type: USER, name: userId })
          const device = createDevice({ userId, deviceName: 'laptop' })
          const user = { userName: userId, keys: userKeys }
          const proofOfInvitation = memberInvitationProof(seed, user, device)
          alice.team.admitMember(
            proofOfInvitation,
            userKeys,
            userId,
            redactDevice(device)
          )
        }

        // ✅ they're all on the team
        for (const userId of invitees) {
          expect(alice.team.has(userId)).toBe(true)
        }
      })

      it("won't use an invitation more than the maximum uses defined", () => {
        const { alice, bob, charlie } = setup(
          'alice',
          { user: 'bob', member: false },
          { user: 'charlie', member: false }
        )

        const { seed } = alice.team.inviteMember({ maxUses: 1 })

        // 👨🏻‍🦲 Bob and 👳🏽‍♂️ Charlie both generate the same proof of invitation from the seed
        const bobProof = memberInvitationProof(seed, bob.user, bob.device)
        const charlieProof = memberInvitationProof(seed, charlie.user, charlie.device)

        const tryToAdmitBob = () => {
          alice.team.admitMember(
            bobProof,
            bob.user.keys,
            bob.user.userName,
            redactDevice(bob.device)
          )
        }

        const tryToAdmitCharlie = () => {
          alice.team.admitMember(
            charlieProof,
            charlie.user.keys,
            charlie.user.userName,
            redactDevice(charlie.device)
          )
        }

        // 👍 👨🏻‍🦲 Bob uses the invitation first and he gets in
        expect(tryToAdmitBob).not.toThrow()

        // 👎 👳🏽‍♂️ Charlie also tries to use the invitation, but it can only be used once
        expect(tryToAdmitCharlie).toThrow(/used/)

        // ✅ 👨🏻‍🦲 Bob is on the team
        expect(alice.team.has(bob.userId)).toBe(true)

        // ❌ 👳🏽‍♂️ Charlie is not on the team
        expect(alice.team.has(charlie.userId)).toBe(false)
      })

      it("won't use a revoked invitation", () => {
        const { alice, bob, charlie } = setup(
          'alice',
          { user: 'bob', admin: false },
          { user: 'charlie', member: false }
        )

        // 👩🏾 Alice invites 👳🏽‍♂️ Charlie by sending him a secret key
        const { seed, id } = alice.team.inviteMember()

        // 👳🏽‍♂️ Charlie accepts the invitation
        const proofOfInvitation = memberInvitationProof(seed, charlie.user, charlie.device)

        // 👩🏾 Alice changes her mind and revokes the invitation
        alice.team.revokeInvitation(id)

        // Later, 👩🏾 Alice is no longer around, but 👨🏻‍🦲 Bob is online
        const persistedTeam = alice.team.save()
        bob.team = teams.load(persistedTeam, bob.localContext, alice.team.teamKeys())

        // 👳🏽‍♂️ Charlie shows 👨🏻‍🦲 Bob his proof of invitation
        const tryToAdmitCharlie = () => {
          bob.team.admitMember(
            proofOfInvitation,
            charlie.user.keys,
            charlie.user.userName,
            redactDevice(charlie.device)
          )
        }

        // 👎 But the invitation is rejected because it was revoked
        expect(tryToAdmitCharlie).toThrowError(/revoked/)

        // ❌ 👳🏽‍♂️ Charlie is not on the team
        expect(bob.team.has(charlie.userId)).toBe(false)
      })

      it("won't accept proof of invitation with an invalid signature", () => {
        const { alice, eve } = setup('alice', 'eve')
        const { team } = alice

        // 👩🏾 Alice invites 👨🏻‍🦲 Bob by sending him a random secret key
        const { seed } = alice.team.inviteMember()

        // 🦹‍♀️ Eve is a member of the group and she wants to hijack Bob's invitation for her
        // nefarious purposes. so she tries to create a proof of invitation.

        // She can get the id from the graph
        const proof = memberInvitationProof(seed, eve.user, eve.device)
        const signature = signatures.sign(['invalid'], eve.user.keys.signature.secretKey)
        const badProof = { ...proof, signature }

        // 🦹‍♀️ Eve shows 👩🏾 Alice her proof of invitation
        const submitBadProof = () =>
          team.admitMember(
            badProof,
            eve.user.keys,
            eve.userName,
            redactDevice(eve.device)
          )

        // 🦹‍♀️ GRRR I would've got away with it too, if it weren't for you meddling cryptographic algorithms!
        expect(submitBadProof).toThrow('Signature provided is not valid')
      })

      describe('devices', () => {
        it('creates and accepts an invitation for a device', () => {
          const { alice: aliceLaptop } = setup('alice')
          const alicePhone = aliceLaptop.phone!

          // 👩🏾 Alice only has 💻 one device on the signature chain
          expect(aliceLaptop.team.members(aliceLaptop.userId).devices).toHaveLength(1)

          // 💻 on her laptop, Alice generates an invitation for her phone
          const { seed } = aliceLaptop.team.inviteDevice()

          // 📱 Alice gets the seed to her phone, perhaps by typing it in or by scanning a QR code.

          // Alice's phone uses the seed to generate her starter keys and her proof of invitation
          const proofOfInvitation = deviceInvitationProof(
            seed,
            aliceLaptop.userName,
            alicePhone
          )

          // 📱 Alice's phone connects with 💻 her laptop and presents the proof
          aliceLaptop.team.admitDevice(
            proofOfInvitation,
            redactFirstUseDevice(alicePhone),
            aliceLaptop.userName
          )

          // 👍 The proof was good, so the laptop sends the phone the team's graph and keyring
          const serializedGraph = aliceLaptop.team.save()
          const teamKeyring = aliceLaptop.team.teamKeyring()

          // 📱 Alice's phone needs to get her user keys.

          // To do that, she uses the invitation seed to generate starter keys, which she can use to
          // unlock a lockbox stored on the graph containing her user keys.
          const aliceUser = teams.getDeviceUserFromGraph({
            serializedGraph,
            teamKeyring,
            invitationSeed: seed,
          })

          const phoneTeam = teams.load(
            serializedGraph,
            { user: aliceUser, device: alicePhone },
            teamKeyring
          )

          // ✅ Now Alice has 💻📱 two devices on the signature chain
          expect(phoneTeam.members(aliceLaptop.userId).devices).toHaveLength(2)
          expect(aliceLaptop.team.members(aliceLaptop.userId).devices).toHaveLength(2)
        })

        it("lets someone else admit Alice's device", () => {
          const { alice, bob } = setup('alice', 'bob')

          // 👩🏾 Alice only has 💻 one device on the signature chain
          expect(alice.team.members(alice.userId).devices).toHaveLength(1)

          // 💻 on her laptop, Alice generates an invitation for her phone
          const { seed } = alice.team.inviteDevice()

          // 📱 Alice gets the seed to her phone, perhaps by typing it in or by scanning a QR code.

          // Alice's phone uses the seed to generate her starter keys and her proof of invitation
          const proofOfInvitation = deviceInvitationProof(
            seed,
            alice.userName,
            alice.phone!
          )

          // 👨🏻‍🦲 Bob syncs up with Alice
          const savedTeam = alice.team.save()
          bob.team = teams.load(savedTeam, bob.localContext, alice.team.teamKeys())

          // 📱 Alice's phone connects with 👨🏻‍🦲 Bob and she presents the proof
          bob.team.admitDevice(
            proofOfInvitation,
            redactFirstUseDevice(alice.phone!),
            alice.userName
          )
        })

        it("won't accept proof of invitation with an invalid signature", () => {
          const { alice, eve } = setup('alice', 'eve')

          // 👩🏾 Alice only has 💻 one device on the signature chain
          expect(alice.team.members(alice.userId).devices).toHaveLength(1)

          // 💻 on her laptop, Alice generates an invitation for her phone
          const seed = alice.team.inviteDevice().seed

          // 🦹‍♀️ Eve is a member of the group and she wants to hijack Alice's device invitation
          // for her nefarious purposes. so she tries to create a proof of invitation.

          // She can get the id from the graph
          const proof = deviceInvitationProof(seed, eve.userName, eve.device)
          const signature = signatures.sign(['invalid'], eve.user.keys.signature.secretKey)
          const badProof = { ...proof, signature }

          // 🦹‍♀️ Eve shows 👩🏾 Alice her proof of invitation
          const submitBadProof = () =>
            alice.team.admitDevice(
              badProof,
              redactFirstUseDevice(eve.device) as FirstUseDevice,
              eve.userName
            )

          // 🦹‍♀️ GRRR I would've got away with it too, if it weren't for you meddling cryptographic algorithms!
          expect(submitBadProof).toThrow('Signature provided is not valid')
        })
      })
    })
  })
})
