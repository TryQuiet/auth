import * as teams from 'team/index.js'
import { setup } from 'util/testing/index.js'
import { describe, expect, it } from 'vitest'
import { memberAdmission } from './helpers.js'

/**
 * The lockbox gate and 185b650 touch the same code from opposite directions, so this pins the
 * invariant where they meet.
 *
 * Removing a member rotates the team keys, which means history — the root link, always — stays
 * sealed to an earlier generation. So `admitMember` lockboxes *every* team-key generation for a
 * joiner, not just the latest, and that is what lets their `teamKeyring()` rebuild itself from the
 * graph on a later cold load.
 *
 * To the gate, that admission looks like a link handing out several generations of a shared key at
 * once. It must not read as a re-key: the highest generation it distributes is one the team already
 * has, so it is distribution, not rotation, and every generation survives.
 */
describe('admission after a team-key rotation (185b650)', () => {
  // Protocol 4 disables removal/rotation; retained as a historical revocation specification.
  it.skip('lockboxes every team-key generation to the joiner', () => {
    const { alice, bob, charlie } = setup('alice', 'bob', { user: 'charlie', member: false })

    // 👩🏾 Alice removes 👨🏻‍🦲 Bob, which rotates the team keys to generation 1.
    alice.team.remove(bob.userId)
    expect(alice.team.teamKeys().generation).toBe(1)

    // 👳🏽‍♂️ Charlie joins *after* the rotation.
    const { seed } = alice.team.inviteMember()
    alice.team.admitMember(...memberAdmission(seed, charlie))
    expect(alice.team.has(charlie.userId)).toBe(true)

    // Charlie loads the graph with the keyring the admission handed him over the wire, and stores
    // his user keys in a lockbox his device can open — the first thing a new member does.
    const keyringOverTheWire = alice.team.teamKeyring()
    const charliesTeam = teams.load(alice.team.save(), charlie.localContext, keyringOverTheWire)
    charliesTeam.join(keyringOverTheWire)
    expect(charliesTeam.teamKeys().generation).toBe(1)

    // The point of lockboxing every generation: Charlie's own keyring, rebuilt from the lockboxes on
    // the graph, holds the older generations too — so his next cold load stands on its own.
    const charliesKeyring = charliesTeam.teamKeyring()
    expect(Object.keys(charliesKeyring).length).toBeGreaterThanOrEqual(2)
    expect(() =>
      teams.load(charliesTeam.save(), charlie.localContext, charliesKeyring)
    ).not.toThrow()
  })
})
