import { createUser } from '@localfirst/crdx'
import { createFirstUseDevice, redactFirstUseDevice } from 'device/index.js'
import { deriveId } from 'invitation/index.js'
import { createServer, redactServer } from 'server/index.js'
import type { Host } from 'server/index.js'
import { redactUser } from 'team/redactUser.js'
import type { TeamAction } from 'team/types.js'
import { devicePossessionProof, setup } from 'util/testing/index.js'
import { describe, expect, it } from 'vitest'
import { deviceAdmission, memberAdmission } from './helpers.js'
import { expectRejectedEverywhere, forge } from './forgeHelpers.js'

/**
 * Registration is where new signers get their authority, so it is where an attacker with a foot in
 * the door reaches next. Every link in the suite above is checked against the key registered for an
 * id — which is only worth anything if registering an id is itself hard.
 *
 * The forgeries here all come from a *legitimate signer*: 👩🏾 Alice, an admin, signing honestly with
 * her own device. Nothing about authorship is faked. What's wrong is the payload, which is exactly
 * the case the Team API's own argument checking would never see — these links are built directly,
 * as a modified client would build them.
 */
describe('forged registration', () => {
  /** A new member record, ready to be dropped into an ADD_MEMBER payload. */
  const newcomer = (userName: string, deviceSeed: string) => {
    const user = createUser(userName, `${userName}-user-id`, userName)
    const device = createFirstUseDevice({ deviceName: 'laptop', seed: deviceSeed })
    return { user, device, member: redactUser(user) }
  }

  const addMember = (member: any, devices: any[]) =>
    ({ type: 'ADD_MEMBER', payload: { member: { ...member, devices }, roles: [] } }) as TeamAction

  describe('duplicate ids', () => {
    it('rejects registering a device id that already belongs to another member', () => {
      const { alice, bob } = setup('alice', 'bob')
      const { member } = newcomer('mallory', 'mallory-laptop')

      // 🦹‍♀️ The new member's device record is a byte-for-byte copy of 👨🏻‍🦲 Bob's — the id really is
      // the fingerprint of that key, so nothing about it is malformed. Two registrations for one id
      // would make "which key signed this" a question with two answers, and the second answer is
      // whoever registered last.
      const bobsDevice = { ...alice.team.device(bob.deviceId), userId: member.userId }

      const forged = forge({
        graph: alice.team.graph,
        action: addMember(member, [bobsDevice]),
        signer: alice.signer,
        teamKeys: alice.team.teamKeys(),
      })

      expectRejectedEverywhere({
        forged,
        teamKeys: alice.team.teamKeys(),
        peers: [alice, bob],
        message: /already in use/,
      })
    })

    // Protocol 4 disables removal/rotation; retained as a historical revocation specification.
    it.skip('rejects registering a device id that was removed', () => {
      const { alice, bob } = setup('alice', 'bob')
      const removed = { ...alice.team.device(bob.deviceId) }
      alice.team.removeDevice(bob.deviceId)

      // A tombstone is not a vacancy. If a removed id could come back, whoever took the device
      // could simply be re-admitted under the same identity, and every link it ever signed would
      // start verifying again.
      const { member } = newcomer('mallory', 'mallory-laptop')
      const forged = forge({
        graph: alice.team.graph,
        action: addMember(member, [{ ...removed, userId: member.userId }]),
        signer: alice.signer,
        teamKeys: alice.team.teamKeys(),
      })

      expectRejectedEverywhere({
        forged,
        teamKeys: alice.team.teamKeyring(),
        peers: [alice],
        message: /already in use/,
      })
    })

    it('rejects a registration that repeats an id within its own payload', () => {
      const { alice, bob } = setup('alice', 'bob')
      const { member, device } = newcomer('mallory', 'mallory-laptop')
      const owned = { ...redactFirstUseDevice(device), userId: member.userId }

      const forged = forge({
        graph: alice.team.graph,
        action: addMember(member, [owned, owned]),
        signer: alice.signer,
        teamKeys: alice.team.teamKeys(),
      })

      expectRejectedEverywhere({
        forged,
        teamKeys: alice.team.teamKeys(),
        peers: [alice, bob],
        message: /duplicate ids/,
      })
    })

    it('rejects a member id that collides with a device id', () => {
      const { alice, bob } = setup('alice', 'bob')

      // Ids live in one namespace, because `signer.id` is one field. A member whose userId is
      // 👨🏻‍🦲 Bob's device id would make his device's registration ambiguous with a member record.
      const user = createUser('mallory', bob.deviceId, 'mallory')
      const forged = forge({
        graph: alice.team.graph,
        action: addMember(redactUser(user), []),
        signer: alice.signer,
        teamKeys: alice.team.teamKeys(),
      })

      expectRejectedEverywhere({
        forged,
        teamKeys: alice.team.teamKeys(),
        peers: [alice, bob],
        message: /already in use/,
      })
    })

    it('rejects a server id that collides with an existing device id', () => {
      const { alice, bob } = setup('alice', 'bob')

      // Servers sign links too, through the same `signer.id` field, so their ids share the same
      // namespace as devices and members.
      const server = redactServer(createServer({ host: 'qss.example' as Host, seed: 'qss' }))
      const forged = forge({
        graph: alice.team.graph,
        action: {
          type: 'ADD_SERVER',
          payload: { server: { ...server, serverId: bob.deviceId } },
        } as TeamAction,
        signer: alice.signer,
        teamKeys: alice.team.teamKeys(),
      })

      expectRejectedEverywhere({
        forged,
        teamKeys: alice.team.teamKeys(),
        peers: [alice, bob],
        message: /already in use/,
      })
    })

    it('CONTROL: a fresh id registers without complaint', () => {
      const { alice, bob } = setup('alice', 'bob')
      const { member, device } = newcomer('mallory', 'mallory-laptop')

      const honest = forge({
        graph: alice.team.graph,
        action: addMember(member, [{ ...redactFirstUseDevice(device), userId: member.userId }]),
        signer: alice.signer,
        teamKeys: alice.team.teamKeys(),
      })

      bob.team.merge(honest)
      expect(bob.team.has(member.userId)).toBe(true)
      expect(bob.team.hasDevice(device.deviceId)).toBe(true)
    })
  })

  describe('admissions', () => {
    it('rejects an admission whose claim was swapped for a different device', () => {
      const { alice, bob, eve } = setup('alice', 'bob', { user: 'eve', member: false })

      // 👨🏻‍🦲 Bob invites his 📱 phone and sends his proof over the wire.
      const { seed } = bob.team.inviteDevice()
      alice.team.merge(bob.team.graph)
      const [proof] = deviceAdmission(seed, bob.phone!)

      // 🦹‍♀️ Eve intercepts it and keeps the proof — which is valid, and which she cannot make
      // herself — but substitutes her own device in the claim. Under a design where the device's
      // owner rode in the payload this is exactly how you attach your device to someone else's
      // account; here the invitation names the owner, so the substitution has to survive the proof.
      const [, eveClaim, evePossession] = deviceAdmission(seed, eve.device)

      const forged = forge({
        graph: alice.team.graph,
        action: {
          type: 'ADMIT_DEVICE',
          payload: { id: proof.id, proof, claim: eveClaim, possessionProof: evePossession },
        } as TeamAction,
        signer: alice.signer,
        teamKeys: alice.team.teamKeys(),
      })

      // The proof's signature covers the claim it was made over, so a claim it wasn't made over
      // can't borrow it.
      expectRejectedEverywhere({
        forged,
        teamKeys: alice.team.teamKeys(),
        peers: [alice, bob],
        message: /does not contain a valid invitation proof/,
      })
      expect(alice.team.hasDevice(eve.deviceId)).toBe(false)
    })

    // Protocol 4 disables removal/rotation; retained as a historical revocation specification.
    it.skip('rejects a device admitted against an invitation whose owner has left the team', () => {
      const { alice, bob } = setup('alice', 'bob')

      // 👨🏻‍🦲 Bob invites his phone and is then removed from the team. A device invitation is the
      // only thing that says whose a new device is, so an invitation with no live owner has nobody
      // to give the device to.
      const { seed } = bob.team.inviteDevice()
      alice.team.merge(bob.team.graph)
      alice.team.remove(bob.userId)

      const [proof, claim, possessionProof] = deviceAdmission(seed, bob.phone!)
      const forged = forge({
        graph: alice.team.graph,
        action: {
          type: 'ADMIT_DEVICE',
          payload: { id: proof.id, proof, claim, possessionProof },
        } as TeamAction,
        signer: alice.signer,
        teamKeys: alice.team.teamKeys(),
      })

      expectRejectedEverywhere({
        forged,
        teamKeys: alice.team.teamKeyring(),
        peers: [alice],
        message: /is not on the team/,
      })
    })

    it('rejects a member invitation cashed in as a device admission', () => {
      const { alice, bob } = setup('alice', 'bob')

      // A member invitation admits a member; a device invitation admits a device. The kind is
      // recorded by the reducer from the INVITE_* link, so an admission can't talk it into being
      // the other one — which would attach a device to whoever the admitter felt like.
      const { seed } = alice.team.inviteMember()
      const [proof, claim, possessionProof] = deviceAdmission(seed, alice.phone!)

      const forged = forge({
        graph: alice.team.graph,
        action: {
          type: 'ADMIT_DEVICE',
          payload: { id: proof.id, proof, claim, possessionProof },
        } as TeamAction,
        signer: alice.signer,
        teamKeys: alice.team.teamKeys(),
      })

      expectRejectedEverywhere({
        forged,
        teamKeys: alice.team.teamKeys(),
        peers: [alice, bob],
        message: /member invitation cannot be used by ADMIT_DEVICE/,
      })
      expect(alice.team.hasDevice(alice.phone!.deviceId)).toBe(false)
    })

    it('rejects an admission with no possession proof at all', () => {
      const { alice, bob, charlie } = setup('alice', 'bob', { user: 'charlie', member: false })

      const { seed } = alice.team.inviteMember()
      const [proof, claim] = memberAdmission(seed, charlie)

      const forged = forge({
        graph: alice.team.graph,
        action: {
          type: 'ADMIT_MEMBER',
          payload: { id: proof.id, proof, claim },
        } as TeamAction,
        signer: alice.signer,
        teamKeys: alice.team.teamKeys(),
      })

      expectRejectedEverywhere({
        forged,
        teamKeys: alice.team.teamKeys(),
        peers: [alice, bob],
        message: /missing its proofs/,
      })
      expect(alice.team.has(charlie.userId)).toBe(false)
    })

    it('rejects an admission whose possession proof was made by a different device', () => {
      const { alice, bob, charlie } = setup('alice', 'bob', { user: 'charlie', member: false })

      // 👩🏾 Alice knows the seed, so she can mint an invitation proof for any keys she likes — that
      // is what possession proofs are for. This is her (or anyone holding the seed) registering
      // 👳🏽‍♂️ Charlie's identity with a device *she* controls: the invitation proof is genuine,
      // and only the possession proof gives it away.
      const { seed } = alice.team.inviteMember()
      const [proof, claim] = memberAdmission(seed, charlie)
      const impostorProof = devicePossessionProof(deriveId(seed), alice.device)

      const forged = forge({
        graph: alice.team.graph,
        action: {
          type: 'ADMIT_MEMBER',
          payload: { id: proof.id, proof, claim, possessionProof: impostorProof },
        } as TeamAction,
        signer: alice.signer,
        teamKeys: alice.team.teamKeys(),
      })

      expectRejectedEverywhere({
        forged,
        teamKeys: alice.team.teamKeys(),
        peers: [alice, bob],
        message: /does not prove possession/,
      })
      expect(alice.team.has(charlie.userId)).toBe(false)
    })

    it('rejects a possession proof lifted from another invitation', () => {
      const { alice, bob, charlie } = setup('alice', 'bob', { user: 'charlie', member: false })

      // 👳🏽‍♂️ Charlie proved possession once, for one invitation. The proof is bound to the
      // invitation id, so it can't be replayed into a second admission — otherwise one captured
      // handshake would be reusable forever.
      const first = alice.team.inviteMember()
      const second = alice.team.inviteMember()
      const [, claim] = memberAdmission(first.seed, charlie)
      const staleProof = devicePossessionProof(deriveId(first.seed), charlie.device)
      const [proof] = memberAdmission(second.seed, charlie)

      const forged = forge({
        graph: alice.team.graph,
        action: {
          type: 'ADMIT_MEMBER',
          payload: { id: proof.id, proof, claim, possessionProof: staleProof },
        } as TeamAction,
        signer: alice.signer,
        teamKeys: alice.team.teamKeys(),
      })

      expectRejectedEverywhere({
        forged,
        teamKeys: alice.team.teamKeys(),
        peers: [alice, bob],
        message: /does not prove possession/,
      })
    })

    it('CONTROL: a complete, self-consistent admission is accepted', () => {
      const { alice, bob, charlie } = setup('alice', 'bob', { user: 'charlie', member: false })

      const { seed } = alice.team.inviteMember()
      const [proof, claim, possessionProof] = memberAdmission(seed, charlie)

      const honest = forge({
        graph: alice.team.graph,
        action: {
          type: 'ADMIT_MEMBER',
          payload: { id: proof.id, proof, claim, possessionProof },
        } as TeamAction,
        signer: alice.signer,
        teamKeys: alice.team.teamKeys(),
      })

      bob.team.merge(honest)
      expect(bob.team.has(charlie.userId)).toBe(true)
      expect(bob.team.hasDevice(charlie.deviceId)).toBe(true)
    })
  })
})
