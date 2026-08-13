import { append, createGraph, createKeyring, createUser, merge } from '@localfirst/crdx'
import { createDevice, redactDevice } from 'device/index.js'
import * as teams from 'team/index.js'
import { redactUser } from 'team/redactUser.js'
import { serializeTeamGraph } from 'team/serialize.js'
import { deviceSigner } from 'team/signer.js'
import type { TeamAction, TeamGraph } from 'team/types.js'
import { clone } from 'util/index.js'
import { setup } from 'util/testing/index.js'
import { describe, expect, it } from 'vitest'
import { deviceAdmission } from './helpers.js'
import { expectRejectedEverywhere, forge } from './forgeHelpers.js'

/**
 * Who a signer id is allowed to be.
 *
 * `signer.id` is a claim, and everything downstream of it depends on that claim resolving to a key
 * the graph committed to. Three ways it can fail to: the id was never registered, the id is
 * registered but only somewhere this validator can't see, and the id doesn't actually correspond to
 * the key it's registered with — which would make it an arbitrary label again, and arbitrary labels
 * are the thing the fingerprint scheme exists to abolish.
 */
describe('forged signer identity', () => {
  const ADD_MANAGERS = { type: 'ADD_ROLE', payload: { roleName: 'managers' } } as TeamAction

  it('rejects a link signed by an id the graph has never registered', () => {
    const { alice, bob, eve } = setup('alice', 'bob', { user: 'eve', member: false })

    // 🦹‍♀️ Eve's device is impeccable — real keys, id that is genuinely their fingerprint. She is
    // simply not on this team, and being internally consistent isn't membership.
    const forged = forge({
      graph: alice.team.graph,
      action: ADD_MANAGERS,
      signer: deviceSigner(eve.device),
      teamKeys: alice.team.teamKeys(),
    })

    expectRejectedEverywhere({
      forged,
      teamKeys: alice.team.teamKeys(),
      peers: [alice, bob],
      message: /is not registered on this team/,
    })
  })

  it('rejects a link whose signer is registered only on a branch this validator has not seen', () => {
    const { alice, bob } = setup('alice', 'bob')
    const teamKeys = alice.team.teamKeys()
    const beforeAdmission = clone(alice.team.graph) as TeamGraph

    // 👨🏻‍🦲 Bob admits his 📱 phone on his own branch...
    const { seed } = bob.team.inviteDevice()
    bob.team.admitDevice(...deviceAdmission(seed, bob.phone!))
    const registrationBranch = clone(bob.team.graph) as TeamGraph

    // ...and the phone signs a link rooted before that admission, which it hands to 👩🏾 Alice on
    // its own. She has no way to know this device: nothing in what she was given registers it.
    const phoneBranch = forge({
      graph: beforeAdmission,
      action: ADD_MANAGERS,
      signer: deviceSigner(bob.phone!),
      teamKeys,
    })

    expectRejectedEverywhere({
      forged: phoneBranch,
      teamKeys,
      peers: [alice],
      message: /is not registered on this team/,
    })

    // Once she also has the branch that registers it, the graph loads cleanly and the device is
    // known — but the link the phone signed *before* its own admission is not in that registration's
    // causal future, so it was never causally authorized. The resolver drops it deterministically
    // (rather than accepting it only when the topo-sort tiebreak happens to place the registration
    // first, and throwing when it doesn't). So the device is registered while the role it tried to
    // add is dropped, and every replica agrees regardless of merge order.
    const complete = merge(registrationBranch, phoneBranch) as TeamGraph
    const merged = teams.load(complete, alice.localContext, alice.team.teamKeyring())
    expect(merged.hasDevice(bob.phone!.deviceId)).toBe(true)
    expect(merged.hasRole('managers')).toBe(false)
  })

  it('rejects a device whose id is not the fingerprint of its own key', () => {
    const { alice } = setup('alice')

    // 🦹‍♀️ A device that picks its own id. The keys are real and the keyset is internally
    // consistent — `keys.name` agrees with `deviceId` — but the id is a label of the attacker's
    // choosing rather than a commitment to the key, so anybody could later claim it.
    const genuine = createDevice({
      userId: alice.userId,
      deviceName: 'laptop',
      seed: 'chosen-id-device',
    })
    const chosenId = 'an-id-i-picked-myself'
    const mangled = {
      ...genuine,
      deviceId: chosenId,
      keys: { ...genuine.keys, name: chosenId },
    }

    // It founds a team naming itself, and signs the root with the key it really holds — so the
    // signature verifies. The fingerprint is what catches it.
    const graph = createGraph({
      signer: deviceSigner(mangled),
      rootPayload: {
        name: 'Spies Я Us',
        rootMember: redactUser(alice.user),
        rootDevice: { ...redactDevice(mangled), userId: alice.userId },
        lockboxes: [],
      },
      keys: alice.team.teamKeys(),
    }) as TeamGraph

    expect(() =>
      teams.load(graph, alice.localContext, createKeyring(alice.team.teamKeys()))
    ).toThrow(/not the fingerprint of its signature key/)
  })

  it('rejects a device whose keyset is named for a different id than the device claims', () => {
    const { alice } = setup('alice')

    // The subtler version: the id *is* the fingerprint of the key, but `keys.name` says something
    // else. The two have to commit to each other in both directions, or a keyset could be
    // re-labelled onto another device's registration.
    const genuine = createDevice({ userId: alice.userId, deviceName: 'laptop', seed: 'mismatch' })
    const mangled = { ...genuine, keys: { ...genuine.keys, name: 'some-other-device' } }

    const graph = createGraph({
      signer: deviceSigner(mangled),
      rootPayload: {
        name: 'Spies Я Us',
        rootMember: redactUser(alice.user),
        rootDevice: { ...redactDevice(mangled), userId: alice.userId },
        lockboxes: [],
      },
      keys: alice.team.teamKeys(),
    }) as TeamGraph

    expect(() =>
      teams.load(graph, alice.localContext, createKeyring(alice.team.teamKeys()))
    ).toThrow(/not the fingerprint of its signature key/)
  })

  it('rejects a root link signed by a key other than the founding device’s', () => {
    const { alice, eve } = setup('alice', { user: 'eve', member: false })
    const teamKeys = alice.team.teamKeys()

    // 🦹‍♀️ Eve builds a team whose root names 👩🏾 Alice as founder, and stamps Alice's device id on
    // it so the two agree — then signs with her own key, because it's the only one she has. The
    // root is the trust anchor: nothing precedes it, so its own signature is the entire check.
    const graph = createGraph({
      signer: { info: { kind: 'device', id: alice.deviceId }, keys: eve.device.keys },
      rootPayload: {
        name: 'Spies Я Us',
        rootMember: redactUser(alice.user),
        rootDevice: redactDevice(alice.device),
        lockboxes: [],
      },
      keys: teamKeys,
    }) as TeamGraph

    expect(() => teams.load(graph, alice.localContext, createKeyring(teamKeys))).toThrow(
      /signature does not verify against the founding device/
    )

    // ...and the whole graph goes with it: a link built on that root is not salvageable either.
    const withMore = forge({ graph, action: ADD_MANAGERS, signer: alice.signer, teamKeys })
    expect(() =>
      teams.load(serializeTeamGraph(withMore), alice.localContext, createKeyring(teamKeys))
    ).toThrow(/signature does not verify against the founding device/)
  })

  it('rejects a root whose founding device belongs to a different member than it names', () => {
    const { alice } = setup('alice')
    const teamKeys = alice.team.teamKeys()

    // The device signs honestly and its id checks out; it just says it belongs to somebody other
    // than the member the root is founding. Every later link's author is derived through that
    // link, so a device pointed at the wrong owner is authority handed to the wrong person.
    const otherUser = createUser('mallory', 'mallory-user-id', 'mallory')
    const founderDevice = createDevice({
      userId: otherUser.userId,
      deviceName: 'laptop',
      seed: 'founder-device',
    })

    const graph = createGraph({
      signer: deviceSigner(founderDevice),
      rootPayload: {
        name: 'Spies Я Us',
        rootMember: redactUser(alice.user),
        rootDevice: redactDevice(founderDevice),
        lockboxes: [],
      },
      keys: teamKeys,
    }) as TeamGraph

    expect(() => teams.load(graph, alice.localContext, createKeyring(teamKeys))).toThrow(
      /must belong to the founding member/
    )
  })

  it('CONTROL: a registered device with a well-formed id signs links that are accepted', () => {
    const { alice, bob } = setup('alice', 'bob')

    // 👨🏻‍🦲 Bob's laptop is registered, its id is the fingerprint of its key, and it holds that key.
    const honest = append({
      graph: bob.team.graph,
      action: ADD_MANAGERS,
      signer: deviceSigner(bob.device),
      keys: bob.team.teamKeys(),
    }) as TeamGraph

    alice.team.merge(honest)
    expect(alice.team.hasRole('managers')).toBe(true)

    const reloaded = teams.load(
      serializeTeamGraph(honest),
      alice.localContext,
      alice.team.teamKeyring()
    )
    expect(reloaded.hasRole('managers')).toBe(true)
  })
})
