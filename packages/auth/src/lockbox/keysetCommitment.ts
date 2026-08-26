import { redactKeys, type KeysetWithSecrets } from '@localfirst/crdx'
import { hash, type Base58, type Payload } from '@localfirst/crypto'
import { KEY_MANIFEST_VERSION } from 'lockbox/types.js'
import { assertValidKeyset } from 'lockbox/validateKeyset.js'

export const KEYSET_COMMITMENT_DOMAIN = 'localfirst-auth/keyset-commitment' as const
export const SYMMETRIC_KEY_COMMITMENT_DOMAIN = 'localfirst-auth/symmetric-key-commitment' as const

/**
 * Canonically commits to all metadata and key material in a complete keyset without exposing its
 * symmetric secret. The nested, domain-separated hash makes the symmetric component safe to place
 * alongside the public fields in the outer commitment.
 */
export const keysetCommitment = (keys: KeysetWithSecrets): Base58 => {
  assertValidKeyset(keys)
  const publicKeys = redactKeys(keys)
  const symmetricCommitment = hash(SYMMETRIC_KEY_COMMITMENT_DOMAIN, keys.secretKey)
  const payload = [
    KEY_MANIFEST_VERSION,
    keys.type,
    keys.name,
    keys.generation,
    publicKeys.encryption,
    publicKeys.signature,
    symmetricCommitment,
  ] as Payload

  return hash(KEYSET_COMMITMENT_DOMAIN, payload)
}
