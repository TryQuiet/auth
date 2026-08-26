import { append, createGraph } from '@localfirst/crdx'
import { createFirstUseDevice, redactDevice } from 'device/index.js'
import * as teams from 'team/index.js'
import { deviceSigner } from 'team/signer.js'
import { redactUser } from 'team/redactUser.js'
import type { TeamAction, TeamGraph } from 'team/types.js'
import { setup } from 'util/testing/index.js'
import { describe, expect, it } from 'vitest'
import { deviceAdmission } from './helpers.js'

/**
 * A device is only allowed to author links because the graph says it exists, says whose it is, and
 * commits to the key its signatures are checked against. These tests are about the edges of that:
 * ids that are already spoken for, ids that were retired, and signers the graph has never heard of.
 */
describe('Team', () => {
  describe('device registration', () => {
    it('registers the founding device in the root link', () => {
      const { alice } = setup('alice')

      expect(alice.team.hasDevice(alice.deviceId)).toBe(true)
      expect(alice.team.memberByDeviceId(alice.deviceId).userId).toBe(alice.userId)

      // The team is exactly one link old: the root carries the member, the device, and the metadata
      expect(Object.keys(alice.team.graph.links)).toHaveLength(1)
    })

    it('records when a device was admitted and when it was removed', () => {
      const { alice, bob } = setup('alice', 'bob')

      const [bobsLaptop] = alice.team.members(bob.userId).devices!
      expect(bobsLaptop.admittedAt).toBeGreaterThan(0)
      expect(bobsLaptop.removedAt).toBeUndefined()

      alice.team.removeDevice(bob.deviceId)

      const tombstone = alice.team.device(bob.deviceId, { includeRemoved: true })
      expect(tombstone.removedAt).toBeGreaterThan(0)
    })

    it("won't register a device id that's already in use", () => {
      const { alice } = setup('alice')

      // 👩🏾 Alice invites a device...
      const { seed } = alice.team.inviteDevice()

      // ...and then tries to admit a device that's already registered — her own laptop. Two
      // registrations for one id would make it ambiguous whose signature a link's is.
      const admitTwice = () => alice.team.admitDevice(...deviceAdmission(seed, alice.device))

      expect(admitTwice).toThrow(/already in use/)
    })

    it("won't register a device id that was removed", () => {
      const { bob } = setup('alice', 'bob')

      // 👨🏻‍🦲 Bob admits his phone, then it's stolen and 👩🏾 Alice removes it
      const firstInvitation = bob.team.inviteDevice()
      bob.team.admitDevice(...deviceAdmission(firstInvitation.seed, bob.phone!))
      bob.team.removeDevice(bob.phone!.deviceId)

      // 👨🏻‍🦲 Bob can't put the same device back: a removed id is retired for good, or else
      // whoever took the phone could simply be let back in
      const { seed } = bob.team.inviteDevice()
      const readmit = () => bob.team.admitDevice(...deviceAdmission(seed, bob.phone!))

      expect(readmit).toThrow(/already in use/)
      expect(bob.team.hasDevice(bob.phone!.deviceId)).toBe(false)
      expect(bob.team.deviceWasRemoved(bob.phone!.deviceId)).toBe(true)
    })

    it("won't register a device whose id isn't the fingerprint of its keys", () => {
      const { alice } = setup('alice')
      const { seed } = alice.team.inviteDevice()

      const device = createFirstUseDevice({ deviceName: 'phone', seed: 'phone' })
      const [proof, claim, possessionProof] = deviceAdmission(seed, device)

      // The id is what a validator recomputes from the registered key, so relabelling the device
      // doesn't get it a different identity — it just stops hanging together
      const relabelled = { ...claim, device: { ...claim.device, deviceId: 'a-nicer-id' } }
      const submit = () => alice.team.admitDevice(proof, relabelled, possessionProof)

      expect(submit).toThrow()
    })

    it('rejects a link signed by a device the graph has never registered', () => {
      const { alice, eve } = setup('alice', { user: 'eve', member: false })

      // 🦹‍♀️ Eve has the team keys (say she was handed the graph), so she can produce a
      // well-formed, correctly encrypted link. What she can't do is be someone the graph knows.
      const graph = append({
        graph: alice.team.graph,
        action: { type: 'ADD_ROLE', payload: { roleName: 'managers' } } as TeamAction,
        signer: deviceSigner(eve.device),
        keys: alice.team.teamKeys(),
      }) as TeamGraph

      const load = () => teams.load(graph, alice.localContext, alice.team.teamKeyring())
      expect(load).toThrow(/not registered/)
    })

    it('rejects a link signed by a device that was removed', () => {
      const { alice, bob } = setup('alice', 'bob')

      // 👩🏾 Alice removes 👨🏻‍🦲 Bob's laptop
      alice.team.removeDevice(bob.deviceId)

      // ...and it keeps posting anyway. Its registration is still on the graph, so this isn't an
      // unknown signer — it's a retired one, which is a different answer and a different message.
      const graph = append({
        graph: alice.team.graph,
        action: { type: 'ADD_ROLE', payload: { roleName: 'managers' } } as TeamAction,
        signer: deviceSigner(bob.device),
        keys: alice.team.teamKeys(),
      }) as TeamGraph

      const load = () => teams.load(graph, alice.localContext, alice.team.teamKeyring())
      expect(load).toThrow(/was removed/)
    })

    it('rejects a root link signed by anyone but the founding device', () => {
      const { alice, eve } = setup('alice', { user: 'eve', member: false })
      const teamKeys = alice.team.teamKeys()

      // 🦹‍♀️ Eve builds a team whose root names 👩🏾 Alice as founder but is signed by Eve's device.
      // The root is the trust anchor — nothing precedes it to check it against — so it has to be
      // signed by the device it names.
      const graph = createGraph({
        signer: deviceSigner(eve.device),
        rootPayload: {
          name: 'Spies Я Us',
          rootMember: redactUser(alice.user),
          rootDevice: redactDevice(alice.device),
          lockboxes: [],
        },
        keys: teamKeys,
      }) as TeamGraph

      const load = () => teams.load(graph, alice.localContext, teamKeys)
      expect(load).toThrow(/founding device/)
    })
  })
})
