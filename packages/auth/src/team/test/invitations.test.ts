import { createUser, type UnixTimestamp } from '@localfirst/crdx'
import { createDevice, createFirstUseDevice, redactFirstUseDevice } from 'device/index.js'
import {
  createPossessionProof,
  deriveId,
  generateProof,
  generateStarterKeys,
} from 'invitation/index.js'
import * as teams from 'team/index.js'
import { getTeamState } from 'team/getTeamState.js'
import * as select from 'team/selectors/index.js'
import { KeyType } from 'util/index.js'
import {
  invitationNonces,
  memberClaim,
  memberInvitationProof,
  memberPossessionProof,
  setup,
} from 'util/testing/index.js'
import { describe, expect, it } from 'vitest'
import { deviceAdmission, memberAdmission } from './helpers.js'

describe('Team', () => {
  describe('invitations', () => {
    describe('members', () => {
      it('accepts valid proof of invitation', () => {
        const { alice, bob } = setup('alice', { user: 'bob', member: false })

        // 👩🏾 Alice invites 👨🏻‍🦲 Bob by sending him a random secret key
        const { seed } = alice.team.inviteMember()

        // 👨🏻‍🦲 Bob shows 👩🏾 Alice his proof of invitation, along with the keys he wants
        // registered and proof that he holds his device's secret keys
        alice.team.admitMember(...memberAdmission(seed, bob))

        // ✅ 👨🏻‍🦲 Bob is now on the team. Congratulations, Bob!
        expect(alice.team.has(bob.userId)).toBe(true)

        // ✅ ...and so is the device he'll be signing with
        expect(alice.team.members(bob.userId).devices).toHaveLength(1)
        expect(alice.team.hasDevice(bob.deviceId)).toBe(true)
      })

      it('lets you use a secret invitation seed of your choosing', () => {
        const { alice, bob } = setup('alice', { user: 'bob', member: false })

        // 👩🏾 Alice invites 👨🏻‍🦲 Bob by sending him a secret key of her choosing
        const seed = 'passw0rd'
        alice.team.inviteMember({ seed })

        alice.team.admitMember(...memberAdmission(seed, bob))

        // ✅ Still works
        expect(alice.team.has(bob.userId)).toBe(true)
      })

      it('normalizes the a secret invitation seed ', () => {
        const { alice, bob } = setup('alice', { user: 'bob', member: false })

        // 👩🏾 Alice invites 👨🏻‍🦲 Bob
        const seed = 'abc def ghi'
        alice.team.inviteMember({ seed })

        // 👨🏻‍🦲 Bob accepts the invitation using a url-friendlier version of the key
        alice.team.admitMember(...memberAdmission('abc+def+ghi', bob))

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

        // Later, 👩🏾 Alice is no longer around, but 👨🏻‍🦲 Bob is online
        let persistedTeam = alice.team.save()
        const bobsTeam = teams.load(persistedTeam, bob.localContext, alice.team.teamKeys())

        // Just to confirm: 👨🏻‍🦲 Bob isn't an admin
        expect(bobsTeam.memberIsAdmin(bob.userId)).toBe(false)

        // 👳🏽‍♂️ Charlie shows 👨🏻‍🦲 Bob his proof of invitation
        bobsTeam.admitMember(...memberAdmission(seed, charlie))

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
        alice.team.admitMember(...memberAdmission(seed, bob))

        // ✅ 👨🏻‍🦲 Bob's invitation has not expired so he is on the team
        expect(alice.team.has(bob.userId)).toBe(true)
      })

      it("won't use an expired invitation", () => {
        const { alice, bob } = setup('alice', { user: 'bob', member: false })

        // A long time ago 👩🏾 Alice invited 👨🏻‍🦲 Bob
        const expiration = new Date(Date.UTC(2020, 12, 25)).valueOf() as UnixTimestamp
        const { seed } = alice.team.inviteMember({ expiration })

        const tryToAdmitBob = () => {
          alice.team.admitMember(...memberAdmission(seed, bob))
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

        // Every invitation is multi-use: a use-count can't be enforced under concurrency, so an
        // invitation is bounded by expiration and revocation, not by a number of uses.
        const { seed } = alice.team.inviteMember()

        // 👨🏻‍🦲 Bob and 👳🏽‍♂️ Charlie each prove the same invitation, for their own identities

        // 👩🏾 Alice admits them both
        alice.team.admitMember(...memberAdmission(seed, bob))
        alice.team.admitMember(...memberAdmission(seed, charlie))

        // ✅ 👨🏻‍🦲 Bob and 👳🏽‍♂️ Charlie are both on the team
        expect(alice.team.has(bob.userId)).toBe(true)
        expect(alice.team.has(charlie.userId)).toBe(true)
      })

      it('can use an invitation any number of times', () => {
        const { alice } = setup('alice')

        // 👩🏾 Alice makes an invitation that anyone can use
        const { seed } = alice.team.inviteMember()
        const invitationId = deriveId(seed)

        // A bunch of people use the same invitation and 👩🏾 Alice admits them all
        const invitees = `
            amanda, bob, charlie, dwight, edwin, frida, gertrude, herbert,
            ignaszi, joão, krishna, lashawn, mary, ngunda, oprah, phil, quân,
            rainbow, steve, thad, uriah, vanessa, wade, xerxes, yazmin, zelda`
          .replaceAll(/\s/g, '')
          .split(',')
        const users = invitees.map(userName => {
          const user = createUser(userName, userName, userName)
          const device = createDevice({ userId: user.userId, deviceName: 'laptop', seed: userName })
          return { user, device }
        })

        for (const { user, device } of users) {
          const claim = memberClaim(user, device)
          alice.team.admitMember(
            generateProof({ seed, claim, ...invitationNonces() }),
            claim,
            createPossessionProof({ invitationId, claim, device })
          )
        }

        // ✅ they're all on the team
        for (const { user } of users) {
          expect(alice.team.has(user.userId)).toBe(true)
        }
      })

      it("won't use a revoked invitation", () => {
        const { alice, bob, charlie } = setup(
          'alice',
          { user: 'bob', admin: false },
          { user: 'charlie', member: false }
        )

        // 👩🏾 Alice invites 👳🏽‍♂️ Charlie by sending him a secret key
        const { seed, id } = alice.team.inviteMember()

        // 👩🏾 Alice changes her mind and revokes the invitation
        alice.team.revokeInvitation(id)

        // Later, 👩🏾 Alice is no longer around, but 👨🏻‍🦲 Bob is online
        const persistedTeam = alice.team.save()
        bob.team = teams.load(persistedTeam, bob.localContext, alice.team.teamKeys())

        // 👳🏽‍♂️ Charlie shows 👨🏻‍🦲 Bob his proof of invitation
        const tryToAdmitCharlie = () => {
          bob.team.admitMember(...memberAdmission(seed, charlie))
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
        alice.team.inviteMember()

        // 🦹‍♀️ Eve is a member of the group and she wants to hijack Bob's invitation for her
        // nefarious purposes. She can get the invitation id off the graph, but not the seed, so the
        // best she can do is sign a claim with keys of her own.
        const invitation = Object.values(team.state.invitations)[0]
        const { id } = invitation

        const claim = memberClaim(eve.user, eve.device)
        const badProof = {
          ...memberInvitationProof('not-the-real-seed', eve.user, eve.device),
          id,
        }

        // 🦹‍♀️ Eve shows 👩🏾 Alice her proof of invitation
        const submitBadProof = () =>
          team.admitMember(badProof, claim, memberPossessionProof(id, eve.user, eve.device))

        // 🦹‍♀️ GRRR I would've got away with it too, if it weren't for you meddling cryptographic algorithms!
        expect(submitBadProof).toThrow('Signature provided is not valid')
      })

      it("won't accept an admission that doesn't prove possession of the device's keys", () => {
        const { alice, bob, eve } = setup('alice', { user: 'bob', member: false }, 'eve')

        // 👩🏾 Alice invites 👨🏻‍🦲 Bob, and 🦹‍♀️ Eve intercepts the seed
        const { seed } = alice.team.inviteMember()

        // 🦹‍♀️ Eve knows the seed, so she can mint a proof of invitation naming Bob's keys — but she
        // can't sign for Bob's device, so she signs the possession proof with her own.
        const claim = memberClaim(bob.user, bob.device)
        const proof = generateProof({ seed, claim, ...invitationNonces() })
        const forgedPossessionProof = memberPossessionProof(proof.id, eve.user, eve.device)

        const submit = () => alice.team.admitMember(proof, claim, forgedPossessionProof)

        expect(submit).toThrow(/possession/)
        expect(alice.team.has(bob.userId)).toBe(false)
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

          // 📱 Alice's phone connects with 💻 her laptop and presents its proofs
          aliceLaptop.team.admitDevice(...deviceAdmission(seed, alicePhone))

          // 👍 The proof was good, so the laptop sends the phone the team's graph and keyring
          const serializedGraph = aliceLaptop.team.save()
          const teamKeyring = aliceLaptop.team.teamKeyring()

          // 📱 Alice's phone needs to get her user keys.

          // To do that, she uses the invitation seed to generate starter keys, which she can use to
          // unlock a lockbox stored on the graph containing her user keys. (This is what
          // `getDeviceUserFromGraph` does for the connection layer.)
          const state = getTeamState(serializedGraph, teamKeyring)
          const starterKeys = generateStarterKeys(seed)
          const aliceUser = {
            userId: aliceLaptop.userId,
            userName: aliceLaptop.userName,
            keys: select.keys(state, starterKeys, {
              type: KeyType.USER,
              name: aliceLaptop.userId,
            }),
          }

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

          // 👨🏻‍🦲 Bob syncs up with Alice
          const savedTeam = alice.team.save()
          bob.team = teams.load(savedTeam, bob.localContext, alice.team.teamKeys())

          // 📱 Alice's phone connects with 👨🏻‍🦲 Bob and presents its proofs
          bob.team.admitDevice(...deviceAdmission(seed, alice.phone!))

          // ✅ The device belongs to Alice, because that's who the invitation was issued to — Bob
          // took nobody's word for it
          expect(bob.team.members(alice.userId).devices).toHaveLength(2)
        })

        it("won't accept proof of invitation with an invalid signature", () => {
          const { alice, eve } = setup('alice', 'eve')

          // 💻 on her laptop, Alice generates an invitation for her phone
          alice.team.inviteDevice()

          // 🦹‍♀️ Eve wants to hijack Alice's device invitation. She can read the invitation id off
          // the graph, but she doesn't know the seed.
          const invitation = Object.values(alice.team.state.invitations)[0]
          const { id } = invitation

          const eveDevice = createFirstUseDevice({ deviceName: 'eve-phone', seed: 'eve-phone' })
          const [, claim, possessionProof] = deviceAdmission('not-the-real-seed', eveDevice)
          const badProof = { ...deviceAdmission('not-the-real-seed', eveDevice)[0], id }

          const submitBadProof = () => alice.team.admitDevice(badProof, claim, possessionProof)

          // 🦹‍♀️ GRRR I would've got away with it too, if it weren't for you meddling cryptographic algorithms!
          expect(submitBadProof).toThrow('Signature provided is not valid')
        })

        it("won't let a member invitation be cashed in as a device", () => {
          const { alice } = setup('alice')

          // 👩🏾 Alice creates an invitation for a new *member*
          const { seed } = alice.team.inviteMember()

          // ...and someone tries to use it to attach a device to her account
          const phone = redactFirstUseDevice(alice.phone!)
          const submit = () => alice.team.admitDevice(...deviceAdmission(seed, alice.phone!))

          expect(submit).toThrow()
          expect(alice.team.hasDevice(phone.deviceId)).toBe(false)
        })
      })
    })
  })
})
