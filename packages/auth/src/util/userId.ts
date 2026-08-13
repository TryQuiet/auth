import { hash, type Base58 } from '@localfirst/crypto'

/**
 * Hash purpose seed for deriving a user's id from their founding device. Domain-separated from
 * `SIGNER_FINGERPRINT` (which produces device and server ids), so a `userId` can never collide with
 * any `deviceId` — the two are hashes of different things under different seeds.
 */
export const USER_ID_DOMAIN = 'USER_ID'

/**
 * The self-certifying id of a user: the hash of the id of the device that founded the identity.
 *
 * A user's id isn't chosen; it's derived from the one device that first spoke for it — the founder's
 * root device, or a member's admitted device. Because a `deviceId` is already the fingerprint of an
 * immutable signature key, and a `userId` is a domain-tagged hash of that `deviceId`, two different
 * users can never share an id (their founding devices differ) and a `userId` can never equal a
 * `deviceId` (different domain tag). This is what lets a validator recompute a member's id from the
 * device it registered, rather than trusting a claimed id or scanning the graph for uniqueness.
 *
 * Uniform for founders and members: there is no invitation component and no founder special case.
 */
export const deriveUserId = (foundingDeviceId: string): Base58 =>
  hash(USER_ID_DOMAIN, foundingDeviceId) as Base58
