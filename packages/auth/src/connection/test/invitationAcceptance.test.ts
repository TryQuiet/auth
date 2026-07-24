import { randomKey } from '@localfirst/crypto'
import { redactKeys } from '@localfirst/crdx'
import { redactDevice } from 'device/index.js'
import { generateProof, type InvitationClaim, type InvitationV2 } from 'invitation/index.js'
import { setup } from 'util/testing/index.js'
import { describe, expect, it } from 'vitest'
import {
  createInvitationAcceptance,
  invitationAcceptanceSenderIsActive,
  openInvitationAcceptance,
} from '../invitationAcceptance.js'
import type { AcceptInvitationPayload } from '../message.js'

describe('encrypted invitation acceptance', () => {
  it('keeps the graph and team keyring out of the outer wire payload', () => {
    const fixture = memberAcceptanceFixture()

    expect(Object.keys(fixture.payload).sort()).toEqual([
      'encryptedAcceptance',
      'senderDeviceId',
      'senderPublicKey',
      'version',
    ])
    expect(fixture.payload).not.toHaveProperty('serializedGraph')
    expect(fixture.payload).not.toHaveProperty('teamKeyring')
    expect(fixture.payload.encryptedAcceptance).toBeInstanceOf(Uint8Array)
  })

  it('opens only with the invitation seed and the exact proof transcript', () => {
    const fixture = memberAcceptanceFixture()

    const acceptance = openInvitationAcceptance(fixture)
    expect(acceptance.serializedGraph).toEqual(fixture.serializedGraph)
    expect(acceptance.teamKeyring).toEqual(fixture.teamKeyring)

    expect(() =>
      openInvitationAcceptance({ ...fixture, invitationSeed: 'not the invitation seed' })
    ).toThrow()
    expect(() =>
      openInvitationAcceptance({
        ...fixture,
        proof: { ...fixture.proof, acceptorNonce: randomKey() },
      })
    ).toThrow()
    expect(() =>
      openInvitationAcceptance({
        ...fixture,
        proof: { ...fixture.proof, inviteeNonce: randomKey() },
      })
    ).toThrow()
    expect(() =>
      openInvitationAcceptance({
        ...fixture,
        claim: { ...fixture.claim, userName: 'mallory' },
      })
    ).toThrow()
  })

  it('rejects ciphertext tampering and non-exact outer schemas', () => {
    const fixture = memberAcceptanceFixture()
    const encryptedAcceptance = fixture.payload.encryptedAcceptance.slice()
    encryptedAcceptance[Math.floor(encryptedAcceptance.length / 2)] ^= 1

    expect(() =>
      openInvitationAcceptance({
        ...fixture,
        payload: { ...fixture.payload, encryptedAcceptance },
      })
    ).toThrow()
    expect(() =>
      openInvitationAcceptance({
        ...fixture,
        payload: { ...fixture.payload, extra: true } as AcceptInvitationPayload,
      })
    ).toThrow()
    expect(() =>
      openInvitationAcceptance({
        ...fixture,
        payload: { ...fixture.payload, version: 3 } as unknown as AcceptInvitationPayload,
      })
    ).toThrow()
    const { senderPublicKey: _, ...missingSenderKey } = fixture.payload
    expect(() =>
      openInvitationAcceptance({
        ...fixture,
        payload: missingSenderKey as AcceptInvitationPayload,
      })
    ).toThrow()
  })

  it('rejects replay against a fresh proof transcript', () => {
    const fixture = memberAcceptanceFixture()
    const freshProof = generateProof({
      seed: fixture.invitationSeed,
      claim: fixture.claim,
      acceptorNonce: randomKey(),
      inviteeNonce: randomKey(),
    })

    expect(() =>
      openInvitationAcceptance({
        ...fixture,
        proof: freshProof,
      })
    ).toThrow()
  })

  it('requires the authenticated graph to register the acceptance sender and key', () => {
    const fixture = memberAcceptanceFixture()
    const acceptance = openInvitationAcceptance(fixture)

    expect(
      invitationAcceptanceSenderIsActive(fixture.alice.team.state, fixture.payload, acceptance)
    ).toBe(true)

    const unregisteredPayload = createInvitationAcceptance({
      invitation: fixture.invitation,
      proof: fixture.proof,
      claim: fixture.claim,
      senderDevice: fixture.eve.device,
      serializedGraph: fixture.serializedGraph,
      teamKeyring: fixture.teamKeyring,
    })
    const unregisteredAcceptance = openInvitationAcceptance({
      ...fixture,
      payload: unregisteredPayload,
    })
    expect(
      invitationAcceptanceSenderIsActive(
        fixture.alice.team.state,
        unregisteredPayload,
        unregisteredAcceptance
      )
    ).toBe(false)
  })
})

const memberAcceptanceFixture = () => {
  const { alice, bob, eve } = setup(
    'alice',
    { user: 'bob', member: false },
    { user: 'eve', member: false }
  )
  const { seed: invitationSeed } = alice.team.inviteMember()
  const claim: InvitationClaim = {
    invitationKind: 'member',
    userName: bob.userName,
    userKeys: redactKeys(bob.user.keys),
    device: redactDevice(bob.device),
  }
  const proof = generateProof({
    seed: invitationSeed,
    claim,
    acceptorNonce: randomKey(),
    inviteeNonce: randomKey(),
  })
  const invitation = alice.team.getInvitation(proof.id)
  if (invitation.version !== 2) {
    throw new Error('Expected a version 2 invitation')
  }
  const serializedGraph = alice.team.save()
  const teamKeyring = alice.team.teamKeyring()
  const payload = createInvitationAcceptance({
    invitation,
    proof,
    claim,
    senderDevice: alice.device,
    serializedGraph,
    teamKeyring,
  })

  return {
    alice,
    eve,
    invitation: invitation as InvitationV2,
    invitationSeed,
    proof,
    claim,
    serializedGraph,
    teamKeyring,
    payload,
  }
}
