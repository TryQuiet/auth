import { redactKeys } from '@localfirst/crdx'
import { signatures, type Base58, type Payload } from '@localfirst/crypto'
import { assert } from '@localfirst/shared'
import type { DeviceWithSecrets, FirstUseDeviceWithSecrets } from 'device/index.js'
import { VALID, type ValidationResult } from 'util/index.js'
import { identityClaimPayload } from './invitationProofPayload.js'
import type { InvitationClaim } from './types.js'
import { fail, validateClaim } from './validate.js'

export const POSSESSION_PROOF_DOMAIN = 'localfirst-auth/possession-proof' as const

/**
 * Returns the canonical, domain-separated payload signed by a possession proof: the invitation the
 * device is being admitted under, plus the exact identity being registered.
 */
export const possessionProofPayload = (invitationId: Base58, claim: InvitationClaim): Payload =>
  [POSSESSION_PROOF_DOMAIN, invitationId, identityClaimPayload(claim)] as Payload

/**
 * Proves that whoever is being admitted actually holds the secret keys of the device being
 * registered.
 *
 * This is the binding a proof of invitation can't provide: the inviter knows the invitation seed,
 * so they can mint invitation proofs for keys of their choosing. A possession proof is signed with
 * the new device's own signing key, which only the device holds — so an inviter (or anyone who
 * intercepts an invitation) can't register a device they control in the invitee's place.
 */
export const createPossessionProof = ({
  invitationId,
  claim,
  device,
}: {
  invitationId: Base58
  claim: InvitationClaim
  /** The device being registered, with its secret keys. */
  device: DeviceWithSecrets | FirstUseDeviceWithSecrets
}): Base58 => {
  assert(
    device.deviceId === claim.device.deviceId &&
      redactKeys(device.keys).signature === claim.device.keys.signature,
    'A possession proof must be signed by the device named in the claim'
  )
  return signatures.sign(
    possessionProofPayload(invitationId, claim),
    device.keys.signature.secretKey
  ) as Base58
}

/**
 * Verifies a possession proof against the identity it claims.
 *
 * The proof is checked against the signature key inside the claim, so it only means anything if
 * that key really is the device's identity — hence the claim validation first, which recomputes
 * `deviceId` from the key. Substituting a different device key changes the id, and substituting a
 * different id fails the fingerprint check.
 */
export const validatePossessionProof = ({
  invitationId,
  claim,
  proof,
}: {
  invitationId: Base58
  claim: InvitationClaim
  proof: Base58
}): ValidationResult => {
  const claimValidation = validateClaim(claim)
  if (!claimValidation.isValid) return claimValidation

  const signatureIsValid = signatures.verify({
    payload: possessionProofPayload(invitationId, claim),
    signature: proof,
    publicKey: claim.device.keys.signature,
  })
  if (!signatureIsValid) {
    return fail('The device did not prove possession of its own keys', { invitationId, claim })
  }

  return VALID
}
