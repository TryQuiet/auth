import { append, merge } from '@localfirst/crdx'
import * as teams from 'team/index.js'
import { deviceSigner } from 'team/signer.js'
import type { TeamAction, TeamGraph } from 'team/types.js'
import { clone, graphSummary } from 'util/index.js'
import { setup } from 'util/testing/index.js'
import { describe, expect, it } from 'vitest'
import { deviceAdmission } from './helpers.js'

/**
 * When two devices act at the same time and one of them is being removed, someone has to lose. The
 * resolver decides that the same way on every replica, from the graph alone — these tests pin down
 * who loses and why.
 */
describe('membershipResolver', () => {
  describe('devices', () => {
    /** 👨🏻‍🦲 Bob adds his phone, so he has two devices that can sign. */
    const setupWithPhone = () => {
      const { alice, bob } = setup('alice', 'bob')

      const { seed } = bob.team.inviteDevice()
      bob.team.admitDevice(...deviceAdmission(seed, bob.phone!))

      // 👩🏾 Alice syncs up, so both of them are working from the same graph
      alice.team.merge(bob.team.graph)

      return { alice, bob, phoneSigner: deviceSigner(bob.phone!) }
    }

    const ADD_MANAGERS = {
      type: 'ADD_ROLE',
      payload: { roleName: 'managers' },
    } as TeamAction

    const removeDevice = (deviceId: string) =>
      ({ type: 'REMOVE_DEVICE', payload: { deviceId } }) as TeamAction

    it('discards what a device does while it is concurrently being removed', () => {
      const { alice, bob, phoneSigner } = setupWithPhone()
      const keys = alice.team.teamKeys()

      // 📱 Bob's phone adds a role...
      const phoneBranch = append({
        graph: clone(alice.team.graph),
        action: ADD_MANAGERS,
        signer: phoneSigner,
        keys,
      }) as TeamGraph

      // ...while 👩🏾 Alice, who can't see that, is removing the phone
      const aliceBranch = append({
        graph: clone(alice.team.graph),
        action: removeDevice(bob.phone!.deviceId),
        signer: alice.signer,
        keys,
      }) as TeamGraph

      // ✅ Removal wins: the phone's role never happened
      const merged = merge(aliceBranch, phoneBranch)
      expect(graphSummary(merged)).not.toContain('ADD_ROLE:managers')
      expect(graphSummary(merged)).toContain('REMOVE_DEVICE')
    })

    it('resolves mutual device removals in favor of the senior device', () => {
      const { alice, bob, phoneSigner } = setupWithPhone()
      const keys = alice.team.teamKeys()

      // 💻 Bob's laptop removes his phone
      const laptopBranch = append({
        graph: clone(bob.team.graph),
        action: removeDevice(bob.phone!.deviceId),
        signer: bob.signer,
        keys,
      }) as TeamGraph

      // 📱 ...while his phone concurrently removes the laptop
      const phoneBranch = append({
        graph: clone(bob.team.graph),
        action: removeDevice(bob.deviceId),
        signer: phoneSigner,
        keys,
      }) as TeamGraph

      // ✅ The laptop was registered first, so it wins and the phone goes
      const merged = merge(laptopBranch, phoneBranch) as TeamGraph
      const mergedTeam = teams.load(merged, bob.localContext, bob.team.teamKeyring())

      expect(mergedTeam.hasDevice(bob.deviceId)).toBe(true)
      expect(mergedTeam.hasDevice(bob.phone!.deviceId)).toBe(false)
      expect(mergedTeam.deviceWasRemoved(bob.phone!.deviceId)).toBe(true)
    })

    it("discards what any of a member's devices do while the member is concurrently removed", () => {
      const { alice, bob, phoneSigner } = setupWithPhone()
      const keys = alice.team.teamKeys()

      // 📱 Bob's *phone* — not the device Alice is thinking about — adds a role
      const phoneBranch = append({
        graph: clone(alice.team.graph),
        action: ADD_MANAGERS,
        signer: phoneSigner,
        keys,
      }) as TeamGraph

      // 👩🏾 ...while Alice removes Bob from the team
      const aliceBranch = append({
        graph: clone(alice.team.graph),
        action: { type: 'REMOVE_MEMBER', payload: { userId: bob.userId } } as TeamAction,
        signer: alice.signer,
        keys,
      }) as TeamGraph

      // ✅ Removing the member reaches every device they sign with, because a link is attributed to
      // the member who registered its signer
      const merged = merge(aliceBranch, phoneBranch)
      expect(graphSummary(merged)).not.toContain('ADD_ROLE:managers')
    })

    it('lets a device retire itself even when it is the only removal in flight', () => {
      const { alice, bob, phoneSigner } = setupWithPhone()
      const keys = alice.team.teamKeys()

      // 📱 Bob's phone removes itself...
      const phoneBranch = append({
        graph: clone(alice.team.graph),
        action: removeDevice(bob.phone!.deviceId),
        signer: phoneSigner,
        keys,
      }) as TeamGraph

      // 👩🏾 ...concurrently with Alice doing something unrelated
      const aliceBranch = append({
        graph: clone(alice.team.graph),
        action: ADD_MANAGERS,
        signer: alice.signer,
        keys,
      }) as TeamGraph

      // ✅ A device retiring itself is the removal, not something overridden by one
      const merged = merge(aliceBranch, phoneBranch) as TeamGraph
      expect(graphSummary(merged)).toContain('REMOVE_DEVICE')

      const mergedTeam = teams.load(merged, bob.localContext, bob.team.teamKeyring())
      expect(mergedTeam.hasDevice(bob.phone!.deviceId)).toBe(false)
    })
  })
})
