import type { Keyset } from '@localfirst/crdx'
import type { Payload } from '@localfirst/crypto'
import type { Device, FirstUseDevice } from 'device/index.js'
import type { InvitationClaim, ProofOfInvitation } from './types.js'

export const INVITATION_CLAIM_DOMAIN = 'localfirst-auth/invitation-claim' as const

/**
 * Returns the canonical, domain-separated payload signed by a proof of invitation.
 *
 * It binds the invitation id, the handshake nonces, and every public key being registered. Because
 * the keys are in the signed payload, an intercepted proof can't be used to register a different
 * identity, and because the nonces are, it can't be replayed on a different connection.
 */
export const invitationProofPayload = (
  proof: Pick<ProofOfInvitation, 'id' | 'acceptorNonce' | 'inviteeNonce'>,
  claim: InvitationClaim
): Payload =>
  [
    INVITATION_CLAIM_DOMAIN,
    proof.id,
    proof.acceptorNonce,
    proof.inviteeNonce,
    identityClaimPayload(claim),
  ] as Payload

/**
 * Returns the canonical encoding of the identity an invitation admits. Kept separate from the
 * proof fields above so that the possession proof can bind the exact same identity under its own
 * domain tag — the two proofs then cover the same claim and can't be recombined across identities.
 */
export const identityClaimPayload = (claim: InvitationClaim): Payload =>
  [
    claim.invitationKind,
    claim.invitationKind === 'member' ? claim.userName : null,
    claim.invitationKind === 'member' ? keysetPayload(claim.memberKeys) : null,
    devicePayload(claim.device),
  ] as Payload

const keysetPayload = (keys: Keyset): Payload =>
  [keys.type, keys.name, keys.generation, keys.encryption, keys.signature] as Payload

const devicePayload = (device: Device | FirstUseDevice): Payload =>
  [
    device.deviceId,
    device.deviceName,
    device.created ?? null,
    device.deviceInfo ?? null,
    keysetPayload(device.keys),
    'userId' in device ? device.userId : null,
  ] as Payload
