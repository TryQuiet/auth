import { merge } from '@localfirst/crdx'
import * as teams from 'team/index.js'
import { deviceSigner } from 'team/signer.js'
import type { TeamAction, TeamGraph } from 'team/types.js'
import { clone, graphSummary } from 'util/index.js'
import { setup } from 'util/testing/index.js'
import { describe, expect, it } from 'vitest'
import { deviceAdmission } from './helpers.js'
import { forge } from './forgeHelpers.js'

/**
 * The stolen device, racing its own removal.
 *
 * Everything else in this suite is a hard rejection: a link that never had a right to exist. This
 * one isn't. A stolen device's links are signed by a key the graph really did register, so they
 * verify — the question is what happens when the team decides, concurrently, that it no longer
 * trusts that key.
 *
 * That decision belongs to the resolver, not the validator, and it resolves the other way: the
 * links are dropped from the sequence rather than throwing. So the merged graph loads cleanly; it
 * just doesn't contain what the thief did. The two layers have to stay distinct, because a thief
 * who could make honest peers *throw* on a merge would have a denial of service instead of a
 * failed attack.
 */
describe('a removed device racing its removal', () => {
  const ADD_MANAGERS = { type: 'ADD_ROLE', payload: { roleName: 'managers' } } as TeamAction
  const removeDevice = (deviceId: string) =>
    ({ type: 'REMOVE_DEVICE', payload: { deviceId } }) as TeamAction

  /** 👨🏻‍🦲 Bob has admitted his 📱 phone, and 👩🏾 Alice has seen it. Then the phone is stolen. */
  const stolenPhone = () => {
    const { alice, bob } = setup('alice', 'bob')
    const { seed } = bob.team.inviteDevice()
    bob.team.admitDevice(...deviceAdmission(seed, bob.phone!))
    alice.team.merge(bob.team.graph)

    return { alice, bob, thief: deviceSigner(bob.phone!), keys: alice.team.teamKeys() }
  }

  // Protocol 4 disables removal/rotation; retained as a historical revocation specification.
  it.skip('discards what the stolen device does while it is being removed', () => {
    const { alice, bob, thief, keys } = stolenPhone()
    const shared = clone(alice.team.graph)

    // 📱 The thief acts...
    const thiefBranch = forge({
      graph: shared,
      action: ADD_MANAGERS,
      signer: thief,
      teamKeys: keys,
    })

    // ...while 👩🏾 Alice, who can't see that yet, removes the phone.
    const removalBranch = forge({
      graph: clone(shared),
      action: removeDevice(bob.phone!.deviceId),
      signer: alice.signer,
      teamKeys: keys,
    })

    const merged = merge(removalBranch, thiefBranch) as TeamGraph
    expect(graphSummary(merged)).toContain('REMOVE_DEVICE')
    expect(graphSummary(merged)).not.toContain('ADD_ROLE:managers')

    // The merged graph is *valid* — this is a resolver decision, not a rejection — and what it
    // resolves to simply doesn't include the thief's work.
    const loaded = teams.load(merged, alice.localContext, alice.team.teamKeyring())
    expect(loaded.hasRole('managers')).toBe(false)
    expect(loaded.hasDevice(bob.phone!.deviceId)).toBe(false)
    expect(loaded.deviceWasRemoved(bob.phone!.deviceId)).toBe(true)
  })

  // Protocol 4 disables removal/rotation; retained as a historical revocation specification.
  it.skip('does not let the stolen device lock the owner out by removing his other device first', () => {
    const { alice, bob, thief, keys } = stolenPhone()
    const shared = clone(alice.team.graph)

    // 📱 The thief's first move is to remove 💻 Bob's laptop, so that Bob can't remove the phone...
    const thiefBranch = forge({
      graph: shared,
      action: removeDevice(bob.deviceId),
      signer: thief,
      teamKeys: keys,
    })

    // ...and 💻 the laptop concurrently removes the phone. Both are legitimate REMOVE_DEVICE links
    // from a member's own devices; the tie has to be broken the same way on every replica.
    const laptopBranch = forge({
      graph: clone(shared),
      action: removeDevice(bob.phone!.deviceId),
      signer: bob.signer,
      teamKeys: keys,
    })

    // ✅ Seniority decides, and the laptop was registered first. A device that arrived later can
    // never evict the one that let it in.
    const merged = merge(laptopBranch, thiefBranch) as TeamGraph
    const loaded = teams.load(merged, bob.localContext, bob.team.teamKeyring())
    expect(loaded.hasDevice(bob.deviceId)).toBe(true)
    expect(loaded.hasDevice(bob.phone!.deviceId)).toBe(false)
    expect(loaded.deviceWasRemoved(bob.phone!.deviceId)).toBe(true)
  })

  // Protocol 4 disables removal/rotation; retained as a historical revocation specification.
  it.skip('discards what the stolen device does when its owner is concurrently removed', () => {
    const { alice, bob, thief, keys } = stolenPhone()
    const shared = clone(alice.team.graph)

    const thiefBranch = forge({
      graph: shared,
      action: ADD_MANAGERS,
      signer: thief,
      teamKeys: keys,
    })

    // 👩🏾 Alice removes 👨🏻‍🦲 Bob himself — she doesn't know about the phone, and shouldn't have to.
    // Removing a member has to reach every device that member ever registered.
    const removalBranch = forge({
      graph: clone(shared),
      action: { type: 'REMOVE_MEMBER', payload: { userId: bob.userId } } as TeamAction,
      signer: alice.signer,
      teamKeys: keys,
    })

    const merged = merge(removalBranch, thiefBranch) as TeamGraph
    expect(graphSummary(merged)).not.toContain('ADD_ROLE:managers')

    const loaded = teams.load(merged, alice.localContext, alice.team.teamKeyring())
    expect(loaded.hasRole('managers')).toBe(false)
    expect(loaded.has(bob.userId)).toBe(false)
  })

  it('CONTROL: the same actions from the same device, with no removal in flight, are accepted', () => {
    const { alice, bob, thief, keys } = stolenPhone()

    // The phone's links are only dropped because of the concurrent removal. Absent one, this is
    // 📱 Bob's second device doing ordinary work, and it lands — which is what makes the test above
    // a test of the removal rule rather than of the phone being unable to sign at all.
    const phoneBranch = forge({
      graph: clone(alice.team.graph),
      action: ADD_MANAGERS,
      signer: thief,
      teamKeys: keys,
    })

    alice.team.merge(phoneBranch)
    expect(alice.team.hasRole('managers')).toBe(true)
    expect(alice.team.hasDevice(bob.phone!.deviceId)).toBe(true)
  })
})
