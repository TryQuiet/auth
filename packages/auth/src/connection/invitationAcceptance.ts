import type { Keyring } from '@localfirst/crdx'
import { asymmetric, type Base58 } from '@localfirst/crypto'
import { assert } from '@localfirst/shared'
import type { DeviceWithSecrets, FirstUseDeviceWithSecrets } from 'device/index.js'
import {
  generateStarterKeys,
  invitationClaimDigest,
  type Invitation,
  type InvitationClaim,
  type ProofOfInvitation,
} from 'invitation/index.js'
import type { ServerWithSecrets } from 'server/index.js'
import * as select from 'team/selectors/index.js'
import type { TeamState } from 'team/types.js'
import type { AcceptInvitationPayload, InvitationAcceptanceEnvelope } from './message.js'

/**
 * The invitation acceptance is the ACCEPT_INVITATION message an acceptor sends an invitee after
 * verifying their proof of invitation. It delivers the two things the invitee cannot have yet —
 * the serialized team graph and the team keyring — and it is the moment the invitee decides
 * whether to trust a team.
 *
 * No other protocol protection covers this message, and its payload is the team's whole security
 * perimeter. The connection's session encryption only begins after both peers authenticate, which
 * an invitee cannot yet do, so the invitation seed is the only secret the two sides share. The
 * keyring decrypts the graph's link payloads and everything else encrypted at team scope — the
 * team's past, and its future until a rotation — and the graph itself is the complete roster of
 * members, devices, and roles. Before v2 both crossed the wire in plaintext, so wherever transport
 * security ends (the untrusted relay a standard local-first-auth deployment syncs through, or a
 * logged transcript), one observed join yielded permanent read access to the team. And transport
 * encryption, where the application adds it, authenticates a pipe — not who minted the welcome, or
 * for which handshake. The seed itself is a bearer secret (the inviter knows it, and it can leak),
 * so this message is built to prove more than "someone knows the seed":
 *
 * - Confidentiality: the graph and keyring travel only inside a ciphertext encrypted to an
 *   ephemeral key derived from the seed; an eavesdropper on the transport learns nothing but the
 *   sender's device id and public key.
 * - Session binding: the encrypted envelope repeats the invitation id, both peers' handshake
 *   nonces, and a digest of the invitee's exact identity claim, so a recorded acceptance cannot
 *   be replayed into another session and cannot stand in for accepting a different identity.
 * - Sender authentication: decryption authenticates the sender's encryption key, the envelope
 *   names the sending device, and the invitee requires that device to be active in the very graph
 *   being delivered (`invitationAcceptanceSenderIsActive`).
 * - Strictness: the outer payload and the decrypted envelope must match their schemas exactly —
 *   unknown fields, missing fields, or other versions are rejected outright.
 *
 * `openInvitationAcceptance` checks all of the above. What it deliberately does NOT check is the
 * graph inside the envelope: that is `validateInvitationAcceptance.ts`'s job, and it runs only on
 * envelopes that opened cleanly here.
 */
export const INVITATION_ACCEPTANCE_DOMAIN = 'localfirst-auth/invitation-acceptance' as const
export const INVITATION_ACCEPTANCE_VERSION = 2 as const

type AcceptanceSender = DeviceWithSecrets | FirstUseDeviceWithSecrets | ServerWithSecrets

type CreateInvitationAcceptanceOptions = {
  invitation: Invitation
  proof: ProofOfInvitation
  claim: InvitationClaim
  sender: AcceptanceSender
  serializedGraph: Uint8Array
  teamKeyring: Keyring
}

/** Encrypts the graph and team keyring to the ephemeral key derived from the invitation seed. */
export const createInvitationAcceptance = ({
  invitation,
  proof,
  claim,
  sender,
  serializedGraph,
  teamKeyring,
}: CreateInvitationAcceptanceOptions): AcceptInvitationPayload => {
  assert(invitation.id === proof.id, 'Invitation and proof IDs do not match')
  assert(
    typeof invitation.encryptionPublicKey === 'string',
    'Invitation does not contain an encryption key'
  )

  const { id: senderDeviceId, encryptionKeys } = acceptanceSender(sender)
  const acceptance: InvitationAcceptanceEnvelope = {
    domain: INVITATION_ACCEPTANCE_DOMAIN,
    version: INVITATION_ACCEPTANCE_VERSION,
    invitationId: proof.id,
    invitationKind: claim.invitationKind,
    claimDigest: invitationClaimDigest(proof, claim),
    acceptorNonce: proof.acceptorNonce,
    inviteeNonce: proof.inviteeNonce,
    acceptorDeviceId: senderDeviceId,
    serializedGraph,
    teamKeyring,
  }

  return {
    version: INVITATION_ACCEPTANCE_VERSION,
    senderDeviceId,
    senderPublicKey: encryptionKeys.publicKey,
    encryptedAcceptance: asymmetric.encryptBytes({
      secret: acceptance,
      recipientPublicKey: invitation.encryptionPublicKey,
      senderSecretKey: encryptionKeys.secretKey,
    }),
  }
}

type OpenInvitationAcceptanceOptions = {
  payload: AcceptInvitationPayload
  invitationSeed: string
  proof: ProofOfInvitation
  claim: InvitationClaim
}

/** Authenticates an acceptance and binds it to the invitee's seed and exact live transcript. */
export const openInvitationAcceptance = ({
  payload,
  invitationSeed,
  proof,
  claim,
}: OpenInvitationAcceptanceOptions): InvitationAcceptanceEnvelope => {
  assertAcceptInvitationPayload(payload)

  const starterKeys = generateStarterKeys(invitationSeed)
  const decrypted = asymmetric.decryptBytes({
    cipher: payload.encryptedAcceptance,
    recipientSecretKey: starterKeys.encryption.secretKey,
    senderPublicKey: payload.senderPublicKey,
  })
  assertInvitationAcceptance(decrypted)

  assert(decrypted.invitationId === proof.id, 'Invitation acceptance ID does not match proof')
  assert(
    decrypted.invitationKind === claim.invitationKind,
    'Invitation acceptance kind does not match claim'
  )
  assert(
    decrypted.claimDigest === invitationClaimDigest(proof, claim),
    'Invitation acceptance claim digest does not match'
  )
  assert(
    decrypted.acceptorNonce === proof.acceptorNonce,
    'Invitation acceptance acceptor nonce does not match'
  )
  assert(
    decrypted.inviteeNonce === proof.inviteeNonce,
    'Invitation acceptance invitee nonce does not match'
  )
  assert(
    decrypted.acceptorDeviceId === payload.senderDeviceId,
    'Invitation acceptance sender ID does not match'
  )

  return decrypted
}

/**
 * Verifies the acceptance's sender against the delivered graph: the device id named inside the
 * tamper-proof envelope must match the outer payload's sender fields, and the resolved team state
 * must register exactly that encryption key under that device or server id.
 *
 * The "one active device" this resolves to is deterministic, not assumed. Ids cannot be chosen to
 * collide (a device or server id is the fingerprint of its own keys), re-registering an existing
 * or tombstoned id is rejected by the `registeredIdsAreUnique` validator, and concurrent
 * registrations of one id — necessarily the same identity — are collapsed deterministically by
 * the membership resolver. If a hostile graph nevertheless presents an ambiguous id,
 * `select.device` throws and this returns false: ambiguity fails closed.
 */
export const invitationAcceptanceSenderIsActive = (
  state: TeamState,
  payload: AcceptInvitationPayload,
  acceptance: InvitationAcceptanceEnvelope
): boolean => {
  if (acceptance.acceptorDeviceId !== payload.senderDeviceId) return false

  try {
    return select.device(state, payload.senderDeviceId).keys.encryption === payload.senderPublicKey
  } catch {
    try {
      return (
        select.server(state, payload.senderDeviceId).identityKeys.encryption ===
        payload.senderPublicKey
      )
    } catch {
      return false
    }
  }
}

const acceptanceSender = (
  sender: AcceptanceSender
): { id: string; encryptionKeys: { publicKey: Base58; secretKey: Base58 } } =>
  'serverId' in sender
    ? { id: sender.serverId, encryptionKeys: sender.identityKeys.encryption }
    : { id: sender.deviceId, encryptionKeys: sender.keys.encryption }

const ACCEPT_INVITATION_PAYLOAD_KEYS = [
  'encryptedAcceptance',
  'senderDeviceId',
  'senderPublicKey',
  'version',
] as const

const INVITATION_ACCEPTANCE_KEYS = [
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
] as const

function assertAcceptInvitationPayload(value: unknown): asserts value is AcceptInvitationPayload {
  assertExactKeys(value, ACCEPT_INVITATION_PAYLOAD_KEYS)
  assert(value.version === INVITATION_ACCEPTANCE_VERSION, 'Unsupported invitation acceptance')
  assert(typeof value.senderDeviceId === 'string', 'Invalid invitation acceptance sender ID')
  assert(typeof value.senderPublicKey === 'string', 'Invalid invitation acceptance sender key')
  assert(value.encryptedAcceptance instanceof Uint8Array, 'Invalid encrypted invitation acceptance')
}

function assertInvitationAcceptance(value: unknown): asserts value is InvitationAcceptanceEnvelope {
  assertExactKeys(value, INVITATION_ACCEPTANCE_KEYS)
  assert(value.domain === INVITATION_ACCEPTANCE_DOMAIN, 'Invalid invitation acceptance domain')
  assert(value.version === INVITATION_ACCEPTANCE_VERSION, 'Unsupported invitation acceptance')
  assert(typeof value.invitationId === 'string', 'Invalid invitation acceptance ID')
  assert(
    value.invitationKind === 'member' || value.invitationKind === 'device',
    'Invalid invitation acceptance kind'
  )
  assert(typeof value.claimDigest === 'string', 'Invalid invitation acceptance claim digest')
  assert(typeof value.acceptorNonce === 'string', 'Invalid invitation acceptance acceptor nonce')
  assert(typeof value.inviteeNonce === 'string', 'Invalid invitation acceptance invitee nonce')
  assert(
    typeof value.acceptorDeviceId === 'string',
    'Invalid invitation acceptance acceptor device ID'
  )
  assert(value.serializedGraph instanceof Uint8Array, 'Invalid invitation acceptance graph')
  assert(isRecord(value.teamKeyring), 'Invalid invitation acceptance keyring')
}

function assertExactKeys<Keys extends readonly string[]>(
  value: unknown,
  expectedKeys: Keys
): asserts value is Record<Keys[number], unknown> {
  assert(isRecord(value), 'Invitation acceptance must be an object')
  const actualKeys = Object.keys(value).sort((a, b) => a.localeCompare(b))
  const expected = [...expectedKeys].sort((a, b) => a.localeCompare(b))
  assert(
    actualKeys.length === expected.length &&
      actualKeys.every((key, index) => key === expected[index]),
    'Invitation acceptance has unexpected fields'
  )
}

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value)
