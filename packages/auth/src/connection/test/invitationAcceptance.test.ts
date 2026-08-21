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
import { pack, unpack } from 'msgpackr'
import { getTeamState } from 'team/getTeamState.js'
import * as select from 'team/selectors/index.js'
import { joinTestChannel, setup, TestChannel } from 'util/testing/index.js'
import { describe, expect, it } from 'vitest'
import type { NumberedMessage } from '../MessageQueue.js'

/**
 * Wire-contract tests for the ACCEPT_INVITATION message ("the welcome"): the envelope an acceptor
 * sends an invitee, carrying the team graph and keyring encrypted to keys derived from the secret
 * invitation seed.
 *
 * Each test runs a real, fully honest handshake, captures the actual ACCEPT_INVITATION bytes off
 * the test channel, and checks them against `openExpectedAcceptance` — a self-contained
 * restatement of the opening rules that deliberately imports nothing from
 * `connection/invitationAcceptance.ts`. That independence is the point: these tests pin the wire
 * format itself, so a production change that (say) dropped a binding field or re-added plaintext
 * would fail here even if production's own `openInvitationAcceptance` were changed to match.
 *
 * Scope and limits:
 * - This oracle mirrors the *intended* rules, so a rule that is wrong in the same way in both
 *   places would pass. What can't slip through is a silent change to what actually crosses the
 *   wire.
 * - Nothing here exercises the production validator; end-to-end tests where a malicious acceptor
 *   attacks the production code path live in validateInvitationAcceptance.test.ts.
 */
describe('invitation acceptance wire format', () => {
  // The outer (plaintext) payload is the only part of the welcome an eavesdropper sees. It must
  // carry exactly four fields — nothing else, and in particular neither the team graph nor the
  // team keyring, which ride only inside the ciphertext. Beyond checking the schema, we scan the
  // packed wire bytes for the graph bytes and for every secret key in the keyring, so this holds
  // for the bytes actually sent, not just for the object shape.
  it('sends only {version, senderDeviceId, senderPublicKey, encryptedAcceptance} in the clear', async () => {
    const fixture = await captureAcceptance()

    expect(Object.keys(fixture.payload).sort()).toEqual([
      'encryptedAcceptance',
      'senderDeviceId',
      'senderPublicKey',
      'version',
    ])
    expect(fixture.payload.encryptedAcceptance).toBeInstanceOf(Uint8Array)

    const acceptance = openExpectedAcceptance(fixture)
    const wireBytes = new Uint8Array(pack(fixture.payload))
    expect(bytesInclude(wireBytes, acceptance.serializedGraph)).toBe(false)
    const secrets = collectSecretKeys(acceptance.teamKeyring)
    expect(secrets.length).toBeGreaterThan(0)
    for (const secret of secrets) {
      expect(bytesInclude(wireBytes, new TextEncoder().encode(secret))).toBe(false)
    }
  })

  // Confidentiality and session binding: decrypting requires the key derived from the invitation
  // seed, and the decrypted envelope must repeat this connection's exact transcript — the
  // invitation id, both handshake nonces, and a digest of the identity claim. A welcome opened
  // with the right seed but produced for any other session must not open.
  it('opens only with the invitation seed, and only for this handshake transcript', async () => {
    const fixture = await captureAcceptance()
    const acceptance = openExpectedAcceptance(fixture)

    expect(acceptance.invitationId).toBe(fixture.proof.id)
    expect(acceptance.acceptorNonce).toBe(fixture.proof.acceptorNonce)
    expect(acceptance.inviteeNonce).toBe(fixture.proof.inviteeNonce)
    expect(acceptance.claimDigest).toBe(claimDigest(fixture.proof, fixture.claim))

    // Wrong seed: the derived decryption key is wrong, so authenticated decryption fails.
    expect(() =>
      openExpectedAcceptance({ ...fixture, invitationSeed: 'not the invitation seed' })
    ).toThrow()
    // Right seed, wrong transcript: decryption succeeds but the nonce bindings don't match.
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

  // `encryptedAcceptance` is a msgpack wrapper {nonce, message, senderPublicKey} in which only
  // `message` (the sealed box, XSalsa20-Poly1305) is MAC-protected; the wrapper bytes themselves
  // are not. So "every flipped bit is rejected" is not the actual guarantee — a flip in wrapper
  // metadata the opener ignores can decrypt successfully. The guarantee that matters is that no
  // corruption can change what the invitee ends up accepting. This test flips one bit at every
  // byte position (sampled by a stride when the blob is large, endpoints always included) and
  // asserts each result either fails to open or opens to the byte-identical honest envelope; it
  // also checks truncated and empty blobs, and that only a small minority of positions are inert.
  it('no corruption of the ciphertext can change the opened envelope', async () => {
    const fixture = await captureAcceptance()
    const original = fixture.payload.encryptedAcceptance
    const honest = openExpectedAcceptance(fixture)

    const stride = Math.max(1, Math.floor(original.length / 512))
    const positions = new Set([0, original.length - 1])
    for (let index = 0; index < original.length; index += stride) positions.add(index)

    let inert = 0
    for (const index of positions) {
      const encryptedAcceptance = original.slice()
      encryptedAcceptance[index] ^= 1
      let opened: ExpectedAcceptance
      try {
        opened = openExpectedAcceptance({
          ...fixture,
          payload: { ...fixture.payload, encryptedAcceptance },
        })
      } catch {
        continue
      }
      expect(opened).toEqual(honest)
      inert += 1
    }
    // Most of the blob is the sealed box, so most corruptions must be outright rejected — this
    // would catch the authentication tag no longer being checked at all.
    expect(inert).toBeLessThan(positions.size / 10)

    for (const encryptedAcceptance of [original.slice(0, -1), new Uint8Array()]) {
      expect(() =>
        openExpectedAcceptance({ ...fixture, payload: { ...fixture.payload, encryptedAcceptance } })
      ).toThrow()
    }
  })

  // The outer payload must be *exactly* the v2 schema: no unknown extra fields (which could smuggle
  // data past the envelope), no missing fields, no other version. This pins the strictness of the
  // schema check, not every possible malformed payload.
  it('rejects outer payloads that are not exactly the v2 schema', async () => {
    const fixture = await captureAcceptance()

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

  // Replay: an eavesdropper records a valid welcome, then plays it back when the same invitation
  // seed is redeemed again (same seed ⇒ same decryption key, so without transcript binding the
  // recording would open). The new session has fresh nonces, so the recorded envelope — bound to
  // the old ones — must not open. Replaying into the *same* transcript just yields the identical
  // message and is not a distinct attack.
  it('cannot be replayed into a later handshake for the same invitation', async () => {
    const fixture = await captureAcceptance()
    expect(() => openExpectedAcceptance(fixture)).not.toThrow()

    const laterHandshakeProof = generateProof({
      seed: fixture.invitationSeed,
      claim: fixture.claim,
      acceptorNonce: randomKey() as Base58,
      inviteeNonce: randomKey() as Base58,
    })
    expect(() => openExpectedAcceptance({ ...fixture, proof: laterHandshakeProof })).toThrow()
  })

  // The invitation seed is a bearer secret — anyone who learns it can encrypt a well-formed
  // welcome. So the envelope's sender fields must be checkable against the graph the envelope
  // itself delivered: the inner (encrypted, tamper-proof) acceptorDeviceId must match the outer
  // senderDeviceId, and that device's registered encryption key must be the key the ciphertext
  // authenticates. Here we check the rule against the honest capture using the oracle's own copy
  // of it; the production check (`invitationAcceptanceSenderIsActive`) is exercised end to end in
  // validateInvitationAcceptance.test.ts.
  it('binds the sender to a device registered in the delivered graph', async () => {
    const fixture = await captureAcceptance()
    const acceptance = openExpectedAcceptance(fixture)
    const state = getTeamState(acceptance.serializedGraph, acceptance.teamKeyring)

    expect(senderIsActive(state, fixture.payload, acceptance)).toBe(true)
    // Same key, different claimed device: Eve can't take credit for Alice's welcome.
    expect(
      senderIsActive(
        state,
        { ...fixture.payload, senderDeviceId: fixture.eve.deviceId },
        acceptance
      )
    ).toBe(false)
    // Same device id, different key: the key that authenticated the ciphertext must be the one the
    // team graph registers for that device.
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

const ACCEPTANCE_DOMAIN = 'localfirst-auth/invitation-acceptance'
const ACCEPTANCE_VERSION = 2

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

/** Records the invitee's identity claim and the acceptor's welcome as they cross the channel. */
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

/** Runs one honest member-invitation handshake to completion and returns what crossed the wire. */
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

/**
 * The oracle: opens a captured welcome by re-deriving the starter keys from the seed and checking
 * every field and binding the production opener is supposed to check. Kept import-free of
 * `connection/invitationAcceptance.ts` on purpose — see the describe comment.
 */
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

/** True if `needle` occurs as a contiguous byte subsequence of `haystack`. */
const bytesInclude = (haystack: Uint8Array, needle: Uint8Array): boolean => {
  if (needle.length === 0) return true
  for (let offset = 0; offset + needle.length <= haystack.length; offset++) {
    if (needle.every((byte, index) => haystack[offset + index] === byte)) return true
  }
  return false
}

/** Every value stored under a `secretKey` property anywhere in the keyring. */
const collectSecretKeys = (value: unknown): string[] => {
  if (typeof value !== 'object' || value === null) return []
  return Object.entries(value).flatMap(([key, child]) =>
    key === 'secretKey' && typeof child === 'string' ? [child] : collectSecretKeys(child)
  )
}
