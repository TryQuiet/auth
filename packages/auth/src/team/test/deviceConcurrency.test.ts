import { append, merge } from '@localfirst/crdx'
import * as teams from 'team/index.js'
import { deviceSigner } from 'team/signer.js'
import type { TeamAction, TeamGraph } from 'team/types.js'
import { clone, graphSummary } from 'util/index.js'
import { setup } from 'util/testing/index.js'
import { describe, expect, it } from 'vitest'
import { deviceAdmission } from './helpers.js'

/**
 * Protocol 4 keeps disabled removals inert during concurrency resolution. Registered devices
 * retain their authority and their concurrent actions are not censored by a removal request.
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

    it('retains device actions concurrent with a disabled removal', () => {
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

      // The removal is inert and cannot censor the concurrent role addition.
      const merged = merge(aliceBranch, phoneBranch)
      expect(graphSummary(merged)).toContain('ADD_ROLE:managers')
      expect(graphSummary(merged)).toContain('REMOVE_DEVICE')
    })

    it('keeps both devices after mutual removal requests', () => {
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

      // Neither removal applies, regardless of device seniority.
      const merged = merge(laptopBranch, phoneBranch) as TeamGraph
      const mergedTeam = teams.load(merged, bob.localContext, bob.team.teamKeyring())

      expect(mergedTeam.hasDevice(bob.deviceId)).toBe(true)
      expect(mergedTeam.hasDevice(bob.phone!.deviceId)).toBe(true)
      expect(mergedTeam.deviceWasRemoved(bob.phone!.deviceId)).toBe(false)
    })

    it("retains all devices' actions concurrent with a disabled member removal", () => {
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

      // Disabled member removal cannot invalidate any registered device’s actions.
      const merged = merge(aliceBranch, phoneBranch)
      expect(graphSummary(merged)).toContain('ADD_ROLE:managers')
    })

    it('ignores self-removal while retaining unrelated concurrent work', () => {
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

      // Self-removal is also disabled; the unrelated role still exists.
      const merged = merge(aliceBranch, phoneBranch) as TeamGraph
      expect(graphSummary(merged)).toContain('REMOVE_DEVICE')

      const mergedTeam = teams.load(merged, bob.localContext, bob.team.teamKeyring())
      expect(mergedTeam.hasDevice(bob.phone!.deviceId)).toBe(true)
    })
  })
})
