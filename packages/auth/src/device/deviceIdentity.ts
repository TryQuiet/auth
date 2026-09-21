import type { Keyset, KeysetWithSecrets } from '@localfirst/crdx'
import { KeyType, signerIdFromKeys } from 'util/index.js'

/** The minimum a device record has to expose for its identity to be checked. */
type DeviceIdentity = {
  deviceId: string
  keys: Keyset | KeysetWithSecrets
}

/**
 * Confirms that a device record's id really is the fingerprint of its own signature key, and that
 * its keyset carries the metadata a device keyset must have.
 *
 * Anything that registers or authenticates a device (invitation claims, admission payloads, link
 * signer resolution) runs this first: without it, `deviceId` would be an unverified label and a
 * device could claim another device's id.
 */
export const deviceIdentityIsValid = ({ deviceId, keys }: DeviceIdentity): boolean =>
  keys.type === KeyType.DEVICE &&
  keys.generation === 0 && // device keys are immutable, so they never advance past generation 0
  keys.name === deviceId &&
  signerIdFromKeys(keys) === deviceId
