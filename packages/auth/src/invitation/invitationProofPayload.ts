import type { Keyset } from '@localfirst/crdx'
import { hash, type Base58, type Payload } from '@localfirst/crypto'
import type { Device, FirstUseDevice } from 'device/index.js'
import type { InvitationClaim, InvitationKind, ProofOfInvitationV2 } from './types.js'

export const INVITATION_CLAIM_DOMAIN = 'localfirst-auth/invitation-claim' as const
export const INVITATION_CLAIM_VERSION = 2 as const

/** Returns the canonical, domain-separated payload signed by a version-2 invitation proof. */
export const invitationProofPayload = (
  proof: Pick<ProofOfInvitationV2, 'id' | 'acceptorNonce' | 'inviteeNonce'>,
  claim: InvitationClaim
): Payload =>
  [
    INVITATION_CLAIM_DOMAIN,
    INVITATION_CLAIM_VERSION,
    proof.id,
    claim.invitationKind,
    proof.acceptorNonce,
    proof.inviteeNonce,
    claim.userName,
    claim.invitationKind === 'member' ? keysetPayload(claim.userKeys) : null,
    devicePayload(claim.device, claim.invitationKind),
  ] as Payload

/** Returns a stable digest of the exact proof transcript and identity claim. */
export const invitationClaimDigest = (
  proof: Pick<ProofOfInvitationV2, 'id' | 'acceptorNonce' | 'inviteeNonce'>,
  claim: InvitationClaim
): Base58 =>
  hash('localfirst-auth/invitation-claim-digest', invitationProofPayload(proof, claim)) as Base58

const keysetPayload = (keys: Keyset): Payload =>
  [keys.type, keys.name, keys.generation, keys.encryption, keys.signature] as Payload

const devicePayload = (device: Device | FirstUseDevice, kind: InvitationKind): Payload =>
  [
    device.deviceId,
    device.deviceName,
    device.created ?? null,
    device.deviceInfo ?? null,
    keysetPayload(device.keys),
    kind === 'member' ? (device as Device).userId : null,
  ] as Payload
