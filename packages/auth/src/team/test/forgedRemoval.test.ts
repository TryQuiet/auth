import * as teams from 'team/index.js'
import { serializeTeamGraph } from 'team/serialize.js'
import type { TeamAction } from 'team/types.js'
import { setup } from 'util/testing/index.js'
import { describe, expect, it } from 'vitest'
import { expectRejectedEverywhere, forge, impersonate } from './forgeHelpers.js'

/**
 * Removal, from both ends: forging one, and signing after one.
 *
 * `REMOVE_MEMBER` is admin-only, so under the old scheme a plain member could evict anybody by
 * writing an admin's userId into the link body. The same primitive covers Quiet's private channels —
 * a channel is a role, and evicting someone from one is `REMOVE_MEMBER_ROLE`, equally admin-gated
 * and equally forgeable. Both now need a signature from a device the graph says belongs to an
 * admin.
 *
 * The other direction is the removed member who keeps writing. Their device's registration is
 * still on the graph — that's what makes their old links verifiable — so "removed" has to be an
 * answer the validator gives, not just an absence.
 */
describe('forged removal', () => {
  const removeMember = (userId: string) =>
    ({ type: 'REMOVE_MEMBER', payload: { userId, lockboxes: [] } }) as TeamAction

  it('rejects a REMOVE_MEMBER forged in an administrator’s name', () => {
    const { alice, bob, charlie, eve } = setup('alice', 'bob', 'charlie', {
      user: 'eve',
      admin: false,
    })
    expect(eve.team.memberIsAdmin(eve.userId)).toBe(false)

    // 🦹‍♀️ Eve forges a link as 👩🏾 Alice (admin) removing 👨🏻‍🦲 Bob
    const forged = forge({
      graph: eve.team.graph,
      action: removeMember(bob.userId),
      signer: impersonate(alice, eve),
      teamKeys: eve.team.teamKeys(),
    })

    expectRejectedEverywhere({
      forged,
      teamKeys: eve.team.teamKeys(),
      peers: [charlie, alice, bob],
      message: /signature does not verify/,
    })

    for (const peer of [alice, bob, charlie]) {
      expect(peer.team.has(bob.userId)).toBe(true)
      expect(peer.team.memberWasRemoved(bob.userId)).toBe(false)
    }
  })

  it('cannot evict the founding administrator', () => {
    const { alice, charlie, eve } = setup('alice', 'bob', 'charlie', { user: 'eve', admin: false })

    // "Alice" removes Alice. The founder has no one above her, so if authorship were takeable this
    // would be the end of the team.
    const forged = forge({
      graph: eve.team.graph,
      action: removeMember(alice.userId),
      signer: impersonate(alice, eve),
      teamKeys: eve.team.teamKeys(),
    })

    expectRejectedEverywhere({
      forged,
      teamKeys: eve.team.teamKeys(),
      peers: [charlie, alice],
      message: /signature does not verify/,
    })

    expect(charlie.team.has(alice.userId)).toBe(true)
    expect(charlie.team.memberWasRemoved(alice.userId)).toBe(false)
  })

  it('rejects links signed by a removed member’s device', () => {
    const { alice, bob } = setup('alice', 'bob')

    // 👩🏾 Alice removes 👨🏻‍🦲 Bob...
    alice.team.removeDevice(bob.deviceId)
    alice.team.remove(bob.userId)

    // ...and his laptop keeps posting on the graph it already had, building on the removal itself
    // so there's no question of this being concurrent — it is causally after, and knows it.
    const forged = forge({
      graph: alice.team.graph,
      action: { type: 'ADD_ROLE', payload: { roleName: 'managers' } } as TeamAction,
      signer: bob.signer,
      teamKeys: alice.team.teamKeys(),
    })

    // Bob's own replica doesn't get a vote here — it's the team that refuses him — so Alice is the
    // one asked to accept it.
    expectRejectedEverywhere({
      forged,
      teamKeys: alice.team.teamKeyring(),
      peers: [alice],
      message: /was removed|not on the team/,
    })
  })

  it('rejects links signed by a removed member’s device even when the device itself was left alone', () => {
    const { alice, bob } = setup('alice', 'bob')

    // Only the member is removed this time; his device record is untouched and still carries a
    // perfectly good key. Authority comes from the member, so the device goes silent with him.
    alice.team.remove(bob.userId)

    const forged = forge({
      graph: alice.team.graph,
      action: { type: 'ADD_ROLE', payload: { roleName: 'managers' } } as TeamAction,
      signer: bob.signer,
      teamKeys: alice.team.teamKeys(),
    })

    expectRejectedEverywhere({
      forged,
      teamKeys: alice.team.teamKeyring(),
      peers: [alice],
      message: /not on the team/,
    })
  })

  it('CONTROL: an admin’s own device can remove a member, and the result survives a round trip', () => {
    const { alice, bob, charlie } = setup('alice', 'bob', 'charlie')

    const honest = forge({
      graph: alice.team.graph,
      action: removeMember(bob.userId),
      signer: alice.signer,
      teamKeys: alice.team.teamKeys(),
    })

    charlie.team.merge(honest)
    expect(charlie.team.has(bob.userId)).toBe(false)
    expect(charlie.team.memberWasRemoved(bob.userId)).toBe(true)

    const reloaded = teams.load(
      serializeTeamGraph(honest),
      charlie.localContext,
      alice.team.teamKeyring()
    )
    expect(reloaded.memberWasRemoved(bob.userId)).toBe(true)
  })
})
