import * as teams from 'team/index.js'
import { setup } from 'util/testing/index.js'
import { describe, expect, it } from 'vitest'
import { memberAdmission } from './helpers.js'

/**
 * A perfectly ordinary race: an invitee connects to two admins at once (or one admin and the
 * syncserver), and both admit them before either has seen the other do it. Because a userId is
 * derived from its device and a deviceId is the fingerprint of its keys, the two admissions register
 * the *same* identity — so this is a convergence problem, not a conflict. The resolver collapses the
 * duplicate to one registration; nothing should throw "id already in use".
 */
describe('Team', () => {
  describe('concurrent duplicate admission', () => {
    it('two admins admitting the same invitee converge to one registration', () => {
      const { alice, bob, charlie } = setup('alice', 'bob', { user: 'charlie', member: false })

      // 👩🏾 Alice invites 👳🏽‍♂️ Charlie, and 👨🏻‍🦲 Bob learns of the invitation before the race.
      const { seed } = alice.team.inviteMember()
      bob.team.merge(alice.team.graph)

      // Concurrently — neither has seen the other's admission — each admin admits Charlie against the
      // same invitation, each running its own handshake (so the two ADMIT_MEMBER links differ).
      alice.team.admitMember(...memberAdmission(seed, charlie))
      bob.team.admitMember(...memberAdmission(seed, charlie))

      // Merging the two branches must not throw, and must converge to a single live registration.
      expect(() => alice.team.merge(bob.team.graph)).not.toThrow()

      expect(alice.team.has(charlie.userId)).toBe(true)
      expect(alice.team.memberWasRemoved(charlie.userId)).toBe(false)
      expect(alice.team.members(charlie.userId).devices).toHaveLength(1)
      expect(alice.team.hasDevice(charlie.deviceId)).toBe(true)
      expect(alice.team.deviceWasRemoved(charlie.deviceId)).toBe(false)

      // It also survives a cold load of the serialized bytes (the path that used to throw outright).
      const reloaded = teams.load(alice.team.save(), alice.localContext, alice.team.teamKeyring())
      expect(reloaded.has(charlie.userId)).toBe(true)
      expect(reloaded.members(charlie.userId).devices).toHaveLength(1)
      expect(reloaded.hasDevice(charlie.deviceId)).toBe(true)
    })
  })
})
