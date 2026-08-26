import { hash } from './hash.js'
import { type Base58 } from './types.js'

/**
 * Hash purpose seed for signer identity fingerprints. Domain-separated from all other
 * hash uses in this codebase.
 */
export const SIGNER_FINGERPRINT = 'SIGNER_FINGERPRINT'

/**
 * Computes the self-certifying identifier for a signing identity: the fingerprint of its
 * public signature key. A device's `deviceId` and a server's `serverId` are fingerprints,
 * so any validator can recompute `fingerprint(record.keys.signature)` and compare it to
 * the claimed id — the id is a commitment to the key, not a label.
 *
 * Signature keys used as signer identities are permanent: devices can never rotate their
 * keys, and servers can only rotate their encryption keys, never their identity keys.
 */
export const fingerprint = (publicSigningKey: Base58): Base58 =>
  hash(SIGNER_FINGERPRINT, publicSigningKey)
