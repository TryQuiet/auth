import { signatures, type Base58 } from '@localfirst/crypto'
import type {
  Invitation,
  InvitationClaim,
  InvitationState,
  ProofOfInvitation,
  ProofOfInvitationV2,
} from 'invitation/types.js'
import { KeyType, VALID, type ValidationResult } from 'util/index.js'
import { invitationProofPayload } from './invitationProofPayload.js'

export const invitationCanBeUsed = (invitation: InvitationState, timeOfUse: number) => {
  const { revoked, maxUses, uses, expiration } = invitation
  if (revoked) return fail('The invitation has been revoked')
  if (maxUses > 0 && uses >= maxUses) return fail('The invitation cannot be used again')
  if (expiration > 0 && expiration < timeOfUse) return fail('The invitation has expired')
  return VALID
}

export const validate = (
  proof: ProofOfInvitation,
  invitation: Invitation,
  claim: InvitationClaim,
  expectedAcceptorNonce?: Base58
): ValidationResult => {
  if (invitation.version !== 2) {
    return fail('Legacy invitations are disabled and must be reissued')
  }
  if (!isV2Proof(proof)) {
    return fail('Invitation proof must use protocol version 2')
  }
  if (!hasExactKeys(proof, ['version', 'id', 'acceptorNonce', 'inviteeNonce', 'signature'])) {
    return fail('Invitation proof has extra or missing fields')
  }
  if (proof.id !== invitation.id) {
    return fail("IDs don't match", { proof, invitation })
  }
  if (expectedAcceptorNonce && proof.acceptorNonce !== expectedAcceptorNonce) {
    return fail('Invitation proof was created for a different handshake')
  }

  const claimValidation = validateClaim(claim)
  if (!claimValidation.isValid) return claimValidation

  const signatureIsValid = signatures.verify({
    payload: invitationProofPayload(proof, claim),
    signature: proof.signature,
    publicKey: invitation.signaturePublicKey,
  })
  if (!signatureIsValid) {
    return fail('Signature provided is not valid', { proof, invitation })
  }

  return VALID
}

const isV2Proof = (proof: ProofOfInvitation): proof is ProofOfInvitationV2 =>
  proof.version === 2

const validateClaim = (claim: InvitationClaim): ValidationResult => {
  const memberClaim = claim.invitationKind === 'member'
  const claimKeys = memberClaim
    ? ['invitationKind', 'userName', 'userKeys', 'device']
    : ['invitationKind', 'userName', 'device']
  if (!hasExactKeys(claim, claimKeys)) {
    return fail('Invitation claim has extra or missing fields')
  }

  const deviceKeys = claim.device.keys
  if (
    !hasExactKeys(deviceKeys, ['type', 'name', 'generation', 'encryption', 'signature']) ||
    deviceKeys.type !== KeyType.DEVICE ||
    deviceKeys.name !== claim.device.deviceId
  ) {
    return fail('Device key metadata does not match the claimed device')
  }

  const deviceFields = ['keys', 'deviceId', 'deviceName']
  if ('created' in claim.device) deviceFields.push('created')
  if ('deviceInfo' in claim.device) deviceFields.push('deviceInfo')
  if (memberClaim) deviceFields.push('userId')
  if (!hasExactKeys(claim.device, deviceFields)) {
    return fail('Invitation device has extra or missing fields')
  }

  if (memberClaim) {
    const { userKeys, device } = claim
    if (
      !hasExactKeys(userKeys, ['type', 'name', 'generation', 'encryption', 'signature']) ||
      userKeys.type !== KeyType.USER ||
      userKeys.generation !== 0 ||
      device.userId !== userKeys.name
    ) {
      return fail('Member identity claim is internally inconsistent')
    }
  } else if ('userId' in claim.device) {
    return fail('A device invitation claim must not supply its owner')
  }

  return VALID
}

const hasExactKeys = (value: object, expected: string[]) => {
  const actual = Object.keys(value).sort()
  return actual.length === expected.length && actual.every((key, index) => key === [...expected].sort()[index])
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
