import type { Keyring } from '@localfirst/crdx'
import { asymmetric, hash, randomKey, type Base58 } from '@localfirst/crypto'
import { assert, eventPromise } from '@localfirst/shared'
import type { ConnectionMessage } from 'connection/message.js'
import type { InviteeIdentityClaim, InviteeMemberContext } from 'connection/types.js'
import {
  generateProof,
  generateStarterKeys,
  invitationProofPayload,
  type InvitationClaim,
  type ProofOfInvitation,
} from 'invitation/index.js'
import { unpack } from 'msgpackr'
import { getTeamState } from 'team/getTeamState.js'
import * as select from 'team/selectors/index.js'
import { joinTestChannel, setup, TestChannel } from 'util/testing/index.js'
import { describe, expect, it } from 'vitest'
import type { NumberedMessage } from '../MessageQueue.js'

const ACCEPTANCE_DOMAIN = 'localfirst-auth/invitation-acceptance'
const ACCEPTANCE_VERSION = 2

// The source branch exposes production envelope helpers directly. Path A does not, so this adapter
// captures its real wire message and validates it with an independent oracle for the same envelope,
// transcript-binding, tamper-resistance, and sender-authentication contract.
describe('encrypted invitation acceptance', () => {
  it('keeps the graph and team keyring out of the outer wire payload', async () => {
    const fixture = await captureAcceptance()

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

  it('opens only with the invitation seed and the exact proof transcript', async () => {
    const fixture = await captureAcceptance()
    const acceptance = openExpectedAcceptance(fixture)

    expect(acceptance.invitationId).toBe(fixture.proof.id)
    expect(acceptance.acceptorNonce).toBe(fixture.proof.acceptorNonce)
    expect(acceptance.inviteeNonce).toBe(fixture.proof.inviteeNonce)
    expect(acceptance.claimDigest).toBe(claimDigest(fixture.proof, fixture.claim))
    expect(() =>
      openExpectedAcceptance({ ...fixture, invitationSeed: 'not the invitation seed' })
    ).toThrow()
    expect(() =>
      openExpectedAcceptance({
        ...fixture,
        proof: { ...fixture.proof, acceptorNonce: randomKey() as Base58 },
      })
    ).toThrow()
    expect(() =>
      openExpectedAcceptance({
        ...fixture,
        proof: { ...fixture.proof, inviteeNonce: randomKey() as Base58 },
      })
    ).toThrow()
  })

  it('rejects ciphertext tampering and non-exact outer schemas', async () => {
    const fixture = await captureAcceptance()
    expect(fixture.payload.encryptedAcceptance).toBeInstanceOf(Uint8Array)
    const encryptedAcceptance = fixture.payload.encryptedAcceptance.slice()
    encryptedAcceptance[Math.floor(encryptedAcceptance.length / 2)] ^= 1

    expect(() =>
      openExpectedAcceptance({ ...fixture, payload: { ...fixture.payload, encryptedAcceptance } })
    ).toThrow()
    expect(() =>
      openExpectedAcceptance({ ...fixture, payload: { ...fixture.payload, extra: true } })
    ).toThrow()
    expect(() =>
      openExpectedAcceptance({ ...fixture, payload: { ...fixture.payload, version: 3 } })
    ).toThrow()
    const { senderPublicKey: _, ...missingSenderKey } = fixture.payload
    expect(() =>
      openExpectedAcceptance({ ...fixture, payload: missingSenderKey as ExpectedPayload })
    ).toThrow()
  })

  it('rejects replay against a fresh proof transcript', async () => {
    const fixture = await captureAcceptance()
    expect(() => openExpectedAcceptance(fixture)).not.toThrow()
    const freshProof = generateProof({
      seed: fixture.invitationSeed,
      claim: fixture.claim,
      acceptorNonce: randomKey() as Base58,
      inviteeNonce: randomKey() as Base58,
    })

    expect(() => openExpectedAcceptance({ ...fixture, proof: freshProof })).toThrow()
  })

  it('requires the authenticated graph to register the acceptance sender and key', async () => {
    const fixture = await captureAcceptance()
    const acceptance = openExpectedAcceptance(fixture)
    const state = getTeamState(acceptance.serializedGraph, acceptance.teamKeyring)

    expect(senderIsActive(state, fixture.payload, acceptance)).toBe(true)
    expect(
      senderIsActive(
        state,
        { ...fixture.payload, senderDeviceId: fixture.eve.deviceId },
        acceptance
      )
    ).toBe(false)
    expect(
      senderIsActive(
        state,
        {
          ...fixture.payload,
          senderPublicKey: fixture.eve.device.keys.encryption.publicKey,
        },
        acceptance
      )
    ).toBe(false)
  })
})

type ExpectedPayload = {
  version: number
  senderDeviceId: string
  senderPublicKey: string
  encryptedAcceptance: Uint8Array
  [key: string]: unknown
}

type ExpectedAcceptance = {
  domain: string
  version: number
  invitationId: string
  invitationKind: InvitationClaim['invitationKind']
  claimDigest: string
  acceptorNonce: string
  inviteeNonce: string
  acceptorDeviceId: string
  serializedGraph: Uint8Array
  teamKeyring: Keyring
}

type AcceptanceFixture = {
  invitationSeed: string
  proof: ProofOfInvitation
  claim: InvitationClaim
  payload: ExpectedPayload
  eve: ReturnType<typeof setup>['eve']
}

class CaptureAcceptanceChannel extends TestChannel {
  acceptance?: unknown
  inviteeClaim?: InviteeIdentityClaim

  override write(senderId: string, message: Uint8Array) {
    const numbered = unpack(message) as NumberedMessage<ConnectionMessage>
    if (numbered.type === 'CLAIM_IDENTITY' && 'proofOfInvitation' in numbered.payload) {
      this.inviteeClaim = numbered.payload
    }
    if (numbered.type === 'ACCEPT_INVITATION') this.acceptance = numbered.payload
    super.write(senderId, message)
  }
}

const captureAcceptance = async (): Promise<AcceptanceFixture> => {
  const { alice, bob, eve } = setup(
    'alice',
    { user: 'bob', member: false },
    { user: 'eve', member: false }
  )
  const { seed: invitationSeed } = alice.team.inviteMember()
  const inviteeContext: InviteeMemberContext = {
    user: bob.user,
    device: bob.device,
    invitationSeed,
    expectedTeamId: alice.team.id,
  }
  const channel = new CaptureAcceptanceChannel()
  const join = joinTestChannel(channel)
  const acceptor = join(alice.connectionContext)
  const invitee = join(inviteeContext)
  const connected = Promise.all([
    eventPromise(acceptor, 'connected'),
    eventPromise(invitee, 'connected'),
  ])

  acceptor.start()
  invitee.start()
  await connected
  acceptor.stop(false)
  invitee.stop(false)

  assert(channel.acceptance !== undefined, 'Expected an ACCEPT_INVITATION payload')
  assert(channel.inviteeClaim !== undefined, 'Expected an invitee identity claim')
  return {
    invitationSeed,
    proof: channel.inviteeClaim.proofOfInvitation,
    claim: channel.inviteeClaim.claim,
    payload: channel.acceptance as ExpectedPayload,
    eve,
  }
}

const openExpectedAcceptance = ({
  payload,
  invitationSeed,
  proof,
  claim,
}: Omit<AcceptanceFixture, 'eve'>): ExpectedAcceptance => {
  assertExactKeys(payload, ['encryptedAcceptance', 'senderDeviceId', 'senderPublicKey', 'version'])
  assert(payload.version === ACCEPTANCE_VERSION, 'Unsupported invitation acceptance')
  assert(payload.encryptedAcceptance instanceof Uint8Array, 'Acceptance is not encrypted')

  const starterKeys = generateStarterKeys(invitationSeed)
  const decrypted = asymmetric.decryptBytes({
    cipher: payload.encryptedAcceptance,
    recipientSecretKey: starterKeys.encryption.secretKey as Base58,
    senderPublicKey: payload.senderPublicKey as Base58,
  })
  assertExpectedAcceptance(decrypted)

  assert(decrypted.invitationId === proof.id, 'Acceptance invitation does not match proof')
  assert(decrypted.invitationKind === claim.invitationKind, 'Acceptance kind does not match claim')
  assert(
    decrypted.claimDigest === claimDigest(proof, claim),
    'Acceptance claim does not match proof'
  )
  assert(
    decrypted.acceptorNonce === proof.acceptorNonce,
    'Acceptance acceptor nonce does not match'
  )
  assert(decrypted.inviteeNonce === proof.inviteeNonce, 'Acceptance invitee nonce does not match')
  assert(
    decrypted.acceptorDeviceId === payload.senderDeviceId,
    'Acceptance sender metadata does not match'
  )
  return decrypted
}

const claimDigest = (proof: ProofOfInvitation, claim: InvitationClaim) =>
  hash('localfirst-auth/invitation-claim-digest', invitationProofPayload(proof, claim))

const senderIsActive = (
  state: ReturnType<typeof getTeamState>,
  payload: ExpectedPayload,
  acceptance: ExpectedAcceptance
) => {
  if (acceptance.acceptorDeviceId !== payload.senderDeviceId) return false
  try {
    return select.device(state, payload.senderDeviceId).keys.encryption === payload.senderPublicKey
  } catch {
    return false
  }
}

const assertExpectedAcceptance: (value: unknown) => asserts value is ExpectedAcceptance = value => {
  assertExactKeys(value, [
    'acceptorDeviceId',
    'acceptorNonce',
    'claimDigest',
    'domain',
    'invitationId',
    'invitationKind',
    'inviteeNonce',
    'serializedGraph',
    'teamKeyring',
    'version',
  ])
  assert(value.domain === ACCEPTANCE_DOMAIN, 'Invalid invitation acceptance domain')
  assert(value.version === ACCEPTANCE_VERSION, 'Unsupported invitation acceptance')
  assert(value.serializedGraph instanceof Uint8Array, 'Invalid invitation acceptance graph')
}

const assertExactKeys: (
  value: unknown,
  expected: readonly string[]
) => asserts value is Record<string, unknown> = (value, expected) => {
  assert(typeof value === 'object' && value !== null && !Array.isArray(value))
  const actual = Object.keys(value).sort()
  const sortedExpected = [...expected].sort()
  assert(
    actual.length === sortedExpected.length &&
      actual.every((key, index) => key === sortedExpected[index]),
    'Invitation acceptance has unexpected fields'
  )
}
