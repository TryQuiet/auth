import { signatures, type Base58 } from '@localfirst/crypto'
import { deriveId } from 'invitation/deriveId.js'
import type { InvitationClaim, ProofOfInvitationV2 } from 'invitation/types.js'
import { generateStarterKeys } from './generateStarterKeys.js'
import { invitationProofPayload } from './invitationProofPayload.js'
import { normalize } from './normalize.js'

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
