import { signatures, INVITATION_PROOF, type Base58 } from '@localfirst/crypto'
import { deriveId } from 'invitation/deriveId.js'
import type { InvitationClaim, ProofOfInvitation } from 'invitation/types.js'
import { generateStarterKeys } from './generateStarterKeys.js'
import { invitationProofPayload } from './invitationProofPayload.js'
import { normalize } from './normalize.js'

/**
 * Generates a proof that the invitee knows the secret invitation seed.
 *
 * The signature is domain-separated and binds the seed to the exact member or device claim plus
 * both peers' handshake nonces, so a proof can't be replayed for a different identity or a
 * different connection.
 */
export const generateProof = ({
  seed,
  claim,
  identityNonce,
  inviteeNonce,
}: {
  seed: string
  claim: InvitationClaim
  identityNonce: Base58
  inviteeNonce: Base58
}): ProofOfInvitation => {
  seed = normalize(seed)

  // Bob independently derives the invitation id and the ephemeral keys
  const id = deriveId(seed)
  const starterKeys = generateStarterKeys(seed)

  const proofFields = { id, identityNonce, inviteeNonce }
  const signature = signatures.sign(
    invitationProofPayload(proofFields, claim),
    starterKeys.signature.secretKey,
    INVITATION_PROOF
  )

  return { ...proofFields, signature }
}
