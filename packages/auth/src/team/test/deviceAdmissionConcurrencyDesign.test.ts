import { merge } from '@localfirst/crdx'
import * as devices from 'device/index.js'
import * as teams from 'team/index.js'
import type { TeamAction, TeamGraph } from 'team/types.js'
import { clone } from 'util/index.js'
import { setup } from 'util/testing/index.js'
import { describe, expect, it } from 'vitest'
import { forge } from './forgeHelpers.js'
import { deviceAdmission } from './helpers.js'

/**
 * Protocol 4 ignores removals, including their effects on concurrent device admissions. These
 * signed graph branches must preserve both existing registrations and new valid admissions.
 */
describe('device admission concurrency design targets', () => {
  it('keeps the device when two admins concurrently request its removal', () => {
    const { alice, bob } = setup('alice', 'bob')
    const { seed } = bob.team.inviteDevice()
    bob.team.admitDevice(...deviceAdmission(seed, bob.phone!))
    alice.team.merge(bob.team.graph)

    const shared = clone(alice.team.graph)
    const action = {
      type: 'REMOVE_DEVICE',
      payload: { deviceId: bob.phone!.deviceId },
    } as TeamAction

    const aliceBranch = forge({
      graph: clone(shared),
      action,
      signer: alice.signer,
      teamKeys: alice.team.teamKeys(),
    })
    const bobBranch = forge({
      graph: clone(shared),
      action,
      signer: bob.signer,
      teamKeys: bob.team.teamKeys(),
    })

    const loaded = teams.load(
      merge(aliceBranch, bobBranch),
      alice.localContext,
      alice.team.teamKeyring()
    )

    expect(loaded.hasDevice(bob.phone!.deviceId)).toBe(true)
    expect(
      loaded.state.removedDevices.filter(device => device.deviceId === bob.phone!.deviceId)
    ).toHaveLength(0)
  })

  it('retains a device admission concurrent with a disabled member removal', () => {
    const { alice, bob } = setup('alice', 'bob')
    const { seed } = bob.team.inviteDevice()
    alice.team.merge(bob.team.graph)

    const shared = clone(alice.team.graph)
    const [proof, claim, possessionProof] = deviceAdmission(seed, bob.phone!)
    const admissionAction = {
      type: 'ADMIT_DEVICE',
      payload: { id: proof.id, proof, claim, possessionProof },
    } as TeamAction
    const removalAction = {
      type: 'REMOVE_MEMBER',
      payload: { userId: bob.userId },
    } as TeamAction

    let branches: { admission: TeamGraph; removal: TeamGraph } | undefined
    for (let attempt = 0; attempt < 100; attempt += 1) {
      const admission = forge({
        graph: clone(shared),
        action: admissionAction,
        signer: alice.signer,
        teamKeys: alice.team.teamKeys(),
      })
      const removal = forge({
        graph: clone(shared),
        action: removalAction,
        signer: alice.signer,
        teamKeys: alice.team.teamKeys(),
      })

      // Exercise removal before admission in the deterministic link ordering.
      if (removal.head[0] < admission.head[0]) {
        branches = { admission, removal }
        break
      }
    }

    expect(branches).toBeDefined()
    if (branches === undefined) throw new Error('Could not construct the target link ordering')

    const loaded = teams.load(
      merge(branches.removal, branches.admission),
      alice.localContext,
      alice.team.teamKeyring()
    )

    expect(loaded.has(bob.userId)).toBe(true)
    expect(loaded.hasDevice(bob.phone!.deviceId)).toBe(true)
  })

  it('keeps an invitation and its device admission despite a concurrent device removal', () => {
    const { alice, bob } = setup('alice', 'bob')
    const { seed: phoneSeed } = bob.team.inviteDevice()
    bob.team.admitDevice(...deviceAdmission(phoneSeed, bob.phone!))
    alice.team.merge(bob.team.graph)

    const shared = clone(alice.team.graph)
    const tabletSeed = 'bob-tablet'
    const tablet = devices.createFirstUseDevice({ deviceName: 'tablet', seed: tabletSeed })
    bob.team.inviteDevice({ seed: tabletSeed })
    const [proof, claim, possessionProof] = deviceAdmission(tabletSeed, tablet)

    const admissionBranch = forge({
      graph: clone(bob.team.graph),
      action: {
        type: 'ADMIT_DEVICE',
        payload: { id: proof.id, proof, claim, possessionProof },
      } as TeamAction,
      signer: alice.signer,
      teamKeys: alice.team.teamKeys(),
    })
    const removalBranch = forge({
      graph: clone(shared),
      action: {
        type: 'REMOVE_DEVICE',
        payload: { deviceId: bob.deviceId },
      } as TeamAction,
      signer: alice.signer,
      teamKeys: alice.team.teamKeys(),
    })

    const loaded = teams.load(
      merge(removalBranch, admissionBranch),
      alice.localContext,
      alice.team.teamKeyring()
    )
    const tombstone = loaded.state.removedDevices.find(
      device => device.deviceId === tablet.deviceId
    )

    expect(tombstone).toBeUndefined()
    expect(loaded.hasDevice(tablet.deviceId)).toBe(true)
    expect(loaded.hasDevice(bob.deviceId)).toBe(true)
    expect(loaded.state.pendingKeyRotations).toEqual([])
  })
})
