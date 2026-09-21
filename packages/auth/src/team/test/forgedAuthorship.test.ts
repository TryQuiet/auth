import { ADMIN } from 'role/index.js'
import type { TeamAction } from 'team/types.js'
import { setup } from 'util/testing/index.js'
import { describe, expect, it } from 'vitest'
import { expectRejectedEverywhere, forge, impersonate } from './forgeHelpers.js'

/**
 * The original private#46 proof of concept, ported to device-signed links.
 *
 * 🦹‍♀️ Eve is a real member, so she holds the team keys and can produce a link that every peer
 * decrypts cleanly. What she wants is 👩🏾 Alice's authority, and the only thing standing between
 * her and it used to be a plaintext field in the link body saying whose link this was. She wrote
 * Alice's userId into it and made herself an admin.
 *
 * Now the body names a *device*, and a device id is the fingerprint of a signing key the graph has
 * on file. Eve can still write Alice's device id there; she just can't sign with Alice's key, so
 * the claim and the signature disagree and the link is refused.
 */
describe('forged link authorship', () => {
  const selfPromotion = (eve: { userId: string }) =>
    ({
      type: 'ADD_MEMBER_ROLE',
      payload: { userId: eve.userId, roleName: ADMIN },
    }) as TeamAction

  it('rejects a non-admin member impersonating an administrator', () => {
    const { alice, bob, eve } = setup('alice', 'bob', { user: 'eve', admin: false })
    expect(eve.team.memberIsAdmin(eve.userId)).toBe(false)

    // 🦹‍♀️ Eve signs with her own device keys but stamps 👩🏾 Alice's device id on the link
    const forged = forge({
      graph: eve.team.graph,
      action: selfPromotion(eve),
      signer: impersonate(alice, eve),
      teamKeys: eve.team.teamKeys(),
    })

    // The link says it's Alice's; the signature says otherwise. Alice herself is one of the peers
    // asked to accept it, and she rejects it for the same reason a stranger does.
    expectRejectedEverywhere({
      forged,
      teamKeys: eve.team.teamKeys(),
      peers: [bob, alice],
      message: /signature does not verify/,
    })

    for (const peer of [alice, bob]) {
      expect(peer.team.memberIsAdmin(eve.userId)).toBe(false)
    }
  })

  it('rejects an impersonation aimed at a device the attacker owns nothing of', () => {
    const { alice, bob, eve } = setup('alice', 'bob', { user: 'eve', admin: false })

    // 🦹‍♀️ Eve claims 👨🏻‍🦲 Bob's device rather than Alice's — Bob isn't an admin either, but the
    // point is that *any* id but her own fails the same way. There is nothing special about
    // impersonating an admin; there is something special about not holding the key.
    const forged = forge({
      graph: eve.team.graph,
      action: { type: 'ADD_ROLE', payload: { roleName: 'managers' } } as TeamAction,
      signer: impersonate(bob, eve),
      teamKeys: eve.team.teamKeys(),
    })

    expectRejectedEverywhere({
      forged,
      teamKeys: eve.team.teamKeys(),
      peers: [alice, bob],
      message: /signature does not verify/,
    })
  })

  it('rejects a member signing as their own second device before it is registered', () => {
    const { alice, bob } = setup('alice', 'bob')

    // 👨🏻‍🦲 Bob's phone has never been admitted, so claiming his laptop's id is the only way it can
    // sign anything. Holding one registered device doesn't let you mint another.
    const forged = forge({
      graph: bob.team.graph,
      action: { type: 'ADD_ROLE', payload: { roleName: 'managers' } } as TeamAction,
      signer: { info: { kind: 'device', id: bob.deviceId }, keys: bob.phone!.keys },
      teamKeys: bob.team.teamKeys(),
    })

    expectRejectedEverywhere({
      forged,
      teamKeys: bob.team.teamKeys(),
      peers: [alice, bob],
      message: /signature does not verify/,
    })
  })

  it('CONTROL: the same promotion by an admin, honestly signed, is accepted', () => {
    const { alice, bob, eve } = setup('alice', 'bob', { user: 'eve', admin: false })

    // 👩🏾 Alice really is an admin and really does hold her device's keys, so the honest version of
    // the forged link above goes through. Without this, the tests above would pass just as well
    // against a validator that rejected everything.
    const honest = forge({
      graph: alice.team.graph,
      action: selfPromotion(eve),
      signer: alice.signer,
      teamKeys: alice.team.teamKeys(),
    })

    bob.team.merge(honest)
    expect(bob.team.memberIsAdmin(eve.userId)).toBe(true)
  })

  it('CONTROL: a non-admin promoting herself through the Team API is rejected too', () => {
    const { eve } = setup('alice', 'bob', { user: 'eve', admin: false })

    // The permission rule the forgery was trying to get around is still there, and still says no
    // when Eve asks honestly.
    expect(() => eve.team.addMemberRole(eve.userId, ADMIN)).toThrow()
  })
})
