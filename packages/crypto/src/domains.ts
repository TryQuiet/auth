/**
 * Domain-separation tags for identity-key signatures.
 *
 * A single identity signing key is reused across multiple contexts (identity challenges, invitation
 * proofs, team messages, and link authorship). Every signature MUST be bound to the context it was
 * produced for, so that a signature harvested from one context cannot be replayed as a valid
 * signature in another (cross-context forgery).
 *
 * These constants are passed as the `context` argument to `signatures.sign` / `signatures.verify`.
 * The value is bound OUTSIDE the signed payload, so an attacker who can get a victim to sign
 * arbitrary bytes in one context still cannot produce a signature valid in another. The values are
 * stable wire constants: a signature is only valid when verified under the exact same string it was
 * signed with, so changing a value invalidates every signature previously made under it. Treat this
 * list as append-only, and keep the strings globally distinct.
 */

/** Signing an identity challenge during connection (`connection/identity.ts`). */
export const IDENTITY_CHALLENGE = 'lf/auth/identity-challenge'

/** Signing proof that the holder knows a secret invitation key (`invitation/*`). */
export const INVITATION_PROOF = 'lf/auth/invitation-proof'

/** Signing a team message with the current user's keys (`Team.sign` / `Team.verify`). */
export const TEAM_MESSAGE = 'lf/auth/team-message'

/**
 * Signing proof that a device holds its own signing key, when it is admitted under an invitation
 * (`invitation/possession.ts`). Signed with the same device key as the identity challenge and link
 * authorship, so it needs its own tag.
 */
export const DEVICE_POSSESSION = 'lf/auth/device-possession'

/** Signing authorship of a crdx graph link (`graph/append.ts` / `graph/linkSignature.ts`). */
export const LINK_AUTHORSHIP = 'lf/crdx/link-authorship'
