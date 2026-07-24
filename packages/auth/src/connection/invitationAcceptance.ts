import type { Keyring } from '@localfirst/crdx'
import { asymmetric } from '@localfirst/crypto'
import { assert } from '@localfirst/shared'
import type { DeviceWithSecrets, FirstUseDeviceWithSecrets } from 'device/index.js'
import {
  generateStarterKeys,
  invitationClaimDigest,
  type InvitationClaim,
  type InvitationV2,
  type ProofOfInvitationV2,
} from 'invitation/index.js'
import type { TeamState } from 'team/index.js'
import * as select from 'team/selectors/index.js'
import type { AcceptInvitationPayload, InvitationAcceptance } from './message.js'

export const INVITATION_ACCEPTANCE_DOMAIN = 'localfirst-auth/invitation-acceptance' as const
export const INVITATION_ACCEPTANCE_VERSION = 2 as const

type CreateInvitationAcceptanceOptions = {
  invitation: InvitationV2
  proof: ProofOfInvitationV2
  claim: InvitationClaim
  senderDevice: DeviceWithSecrets | FirstUseDeviceWithSecrets
  serializedGraph: Uint8Array
  teamKeyring: Keyring
}

export const createInvitationAcceptance = ({
  invitation,
  proof,
  claim,
  senderDevice,
  serializedGraph,
  teamKeyring,
}: CreateInvitationAcceptanceOptions): AcceptInvitationPayload => {
  assert(invitation.id === proof.id, 'Invitation and proof IDs do not match')

  const acceptance: InvitationAcceptance = {
    domain: INVITATION_ACCEPTANCE_DOMAIN,
    version: INVITATION_ACCEPTANCE_VERSION,
    invitationId: proof.id,
    invitationKind: claim.invitationKind,
    claimDigest: invitationClaimDigest(proof, claim),
    acceptorNonce: proof.acceptorNonce,
    inviteeNonce: proof.inviteeNonce,
    acceptorDeviceId: senderDevice.deviceId,
    serializedGraph,
    teamKeyring,
  }

  return {
    version: INVITATION_ACCEPTANCE_VERSION,
    senderDeviceId: senderDevice.deviceId,
    senderPublicKey: senderDevice.keys.encryption.publicKey,
    encryptedAcceptance: asymmetric.encryptBytes({
      secret: acceptance,
      recipientPublicKey: invitation.encryptionPublicKey,
      senderSecretKey: senderDevice.keys.encryption.secretKey,
    }),
  }
}

type OpenInvitationAcceptanceOptions = {
  payload: AcceptInvitationPayload
  invitationSeed: string
  proof: ProofOfInvitationV2
  claim: InvitationClaim
}

export const openInvitationAcceptance = ({
  payload,
  invitationSeed,
  proof,
  claim,
}: OpenInvitationAcceptanceOptions): InvitationAcceptance => {
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

export const invitationAcceptanceSenderIsActive = (
  state: TeamState,
  payload: AcceptInvitationPayload,
  acceptance: InvitationAcceptance
): boolean => {
  if (acceptance.acceptorDeviceId !== payload.senderDeviceId) {
    return false
  }

  try {
    const sender = select.device(state, payload.senderDeviceId)
    return sender.keys.encryption === payload.senderPublicKey
  } catch {
    return false
  }
}

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

function assertInvitationAcceptance(value: unknown): asserts value is InvitationAcceptance {
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
  const actualKeys = Object.keys(value).sort()
  const expected = [...expectedKeys].sort()
  assert(
    actualKeys.length === expected.length &&
      actualKeys.every((key, index) => key === expected[index]),
    'Invitation acceptance has unexpected fields'
  )
}

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value)
