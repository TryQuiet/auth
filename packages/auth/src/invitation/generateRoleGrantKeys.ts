import { createKeyset } from '@localfirst/crdx'
import { memoize } from '@localfirst/shared'
import { deriveId } from './deriveId.js'
import { normalize } from './normalize.js'

/** Key type used only for invitation-bound role-key deliveries. */
export const INVITATION_ROLE_GRANT_KEY_TYPE = 'INVITATION_ROLE_GRANT'

/**
 * Derives the keyset that opens role grants attached to a member invitation.
 *
 * These keys are deliberately domain-separated from the invitation starter keys used to encrypt
 * the acceptance handshake. A relay can see the public key recorded on the invitation, but only a
 * holder of the invitation seed can reproduce the corresponding decryption key.
 */
export const generateRoleGrantKeys = memoize((seed: string) => {
  seed = normalize(seed)
  return createKeyset(
    { type: INVITATION_ROLE_GRANT_KEY_TYPE, name: deriveId(seed) },
    `localfirst-auth/invitation-role-grant:${seed}`
  )
})
