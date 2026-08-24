import { signatures, INVITATION_PROOF, type Base58 } from '@localfirst/crypto'
import { deviceIdentityIsValid } from 'device/index.js'
import {
  type Invitation,
  type InvitationClaim,
  type InvitationState,
  type ProofOfInvitation,
} from 'invitation/types.js'
import { KeyType, VALID, type ValidationResult } from 'util/index.js'
import { invitationProofPayload } from './invitationProofPayload.js'

/** The exact fields a public keyset consists of. */
const KEYSET_FIELDS = ['type', 'name', 'generation', 'encryption', 'signature']

export const invitationCanBeUsed = (invitation: InvitationState, timeOfUse: number) => {
  const { revoked, expiration } = invitation
  // No use-count check: a use-counter is a consensus value that concurrency can't enforce (two
  // branches each see it below the limit and both admit), so invitations are multi-use, bounded
  // only by revocation and expiration — both of which are per-link, consensus-free facts.
  if (revoked) {
    return fail('The invitation has been revoked')
  }

  if (expiration > 0 && expiration < timeOfUse) {
    return fail('The invitation has expired')
  }

  return VALID
}

/**
 * Validates a proof of invitation against the invitation record on the team graph and the exact
 * identity being claimed.
 *
 * When `expectedIdentityNonce` is supplied, the proof must have been created for that connection
 * handshake.
 */
export const validate = (
  proof: ProofOfInvitation,
  invitation: Invitation,
  claim: InvitationClaim,
  expectedIdentityNonce?: Base58
): ValidationResult => {
  if (!hasExactKeys(proof, ['id', 'identityNonce', 'inviteeNonce', 'signature'])) {
    return fail('Invitation proof has extra or missing fields')
  }

  // Check that id from proof matches invitation
  if (proof.id !== invitation.id) {
    return fail("IDs don't match", { proof, invitation })
  }

  if (expectedIdentityNonce && proof.identityNonce !== expectedIdentityNonce) {
    return fail('Invitation proof was created for a different handshake', { proof, invitation })
  }

  const claimValidation = validateClaim(claim)
  if (!claimValidation.isValid) return claimValidation

  // Check signature on proof against public key from invitation
  const signatureIsValid = signatures.verify({
    payload: invitationProofPayload(proof, claim),
    signature: proof.signature,
    publicKey: invitation.publicKey,
    context: INVITATION_PROOF,
  })
  if (!signatureIsValid) {
    return fail('Signature provided is not valid', { proof, invitation })
  }

  return VALID
}

/**
 * Checks that a claimed identity is internally consistent before anything is signed over it or
 * registered from it.
 *
 * The central check is that the device's id is the fingerprint of its own signature key: that is
 * what makes a `deviceId` a commitment to a keyset rather than a label a peer can choose. The
 * strict field checks matter for the same reason — every field that isn't accounted for here would
 * be a field the proofs bind but validators ignore, or vice versa.
 */
export const validateClaim = (claim: InvitationClaim): ValidationResult => {
  const isMemberClaim = claim.invitationKind === 'member'

  const claimFields = isMemberClaim
    ? ['invitationKind', 'userName', 'memberKeys', 'device']
    : ['invitationKind', 'device']
  if (!hasExactKeys(claim, claimFields)) {
    return fail('Invitation claim has extra or missing fields')
  }

  const { device } = claim

  if (!isMemberClaim && 'userId' in device) {
    return fail('A device invitation claim must not supply its owner')
  }

  const deviceFields = ['keys', 'deviceId', 'deviceName']
  if ('created' in device) deviceFields.push('created')
  if ('deviceInfo' in device) deviceFields.push('deviceInfo')
  if (isMemberClaim) deviceFields.push('userId')
  if (!hasExactKeys(device, deviceFields)) {
    return fail('Invitation device has extra or missing fields')
  }

  if (!hasExactKeys(device.keys, KEYSET_FIELDS)) {
    return fail('Device keys have extra or missing fields')
  }

  if (!deviceIdentityIsValid(device)) {
    return fail('The claimed device id is not the fingerprint of its signature key', { device })
  }

  if (claim.invitationKind === 'member') {
    const { memberKeys, device } = claim
    if (
      !hasExactKeys(memberKeys, KEYSET_FIELDS) ||
      memberKeys.type !== KeyType.USER ||
      memberKeys.generation !== 0 ||
      device.userId !== memberKeys.name
    ) {
      return fail('Member identity claim is internally inconsistent', { claim })
    }
  }

  return VALID
}

/** True if `value` has exactly the listed keys — no extras, none missing. */
export const hasExactKeys = (value: object, expected: string[]) => {
  const actual = Object.keys(value).sort()
  const wanted = [...expected].sort()
  return actual.length === wanted.length && actual.every((key, index) => key === wanted[index])
}

export const fail = (message: string, details?: any) =>
  ({
    isValid: false,
    error: new InvitationValidationError(message, details),
  }) as ValidationResult

export class InvitationValidationError extends Error {
  constructor(message: string, details?: any) {
    super(message)
    this.name = 'Invitation validation failed'
    this.details = details
  }

  public index?: number
  public details?: any
}
