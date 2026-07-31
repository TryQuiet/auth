import { signatures, type Base58 } from '@localfirst/crypto'
import { deriveId } from 'invitation/deriveId.js'
import type { InvitationClaim, ProofOfInvitationV2 } from 'invitation/types.js'
import { generateStarterKeys } from './generateStarterKeys.js'
import { invitationProofPayload } from './invitationProofPayload.js'
import { normalize } from './normalize.js'

/**
 * Generates a version-2 proof of invitation possession.
 *
 * The signature is domain-separated and binds the normalized invitation seed to the exact member
 * or device claim plus both peers' handshake nonces. A proof therefore cannot be replayed for a
 * different identity or connection transcript.
 */
export const generateProof = ({
  seed,
  claim,
  acceptorNonce,
  inviteeNonce,
}: {
  seed: string
  claim: InvitationClaim
  acceptorNonce: Base58
  inviteeNonce: Base58
}): ProofOfInvitationV2 => {
  seed = normalize(seed)

  const id = deriveId(seed)
  const starterKeys = generateStarterKeys(seed)
  const proofFields = { id, acceptorNonce, inviteeNonce }
  const signature = signatures.sign(
    invitationProofPayload(proofFields, claim),
    starterKeys.signature.secretKey
  )

  return { version: 2, ...proofFields, signature }
}
