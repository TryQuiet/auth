import { redactKeys, type Keyset, type KeysetWithSecrets } from '@localfirst/crdx'
import { fingerprint, type Base58 } from '@localfirst/crypto'

/**
 * The self-certifying id of a signing identity: the fingerprint of its public signature key.
 *
 * A device's `deviceId` and a server's `serverId` are computed this way, so any validator can
 * recompute the id from the registered keyset and confirm that the id is a commitment to the key
 * rather than an arbitrary label. Ids are only self-certifying for keysets that never rotate:
 * device keys are immutable, and a server's `identityKeys` are immutable (only its `keys` rotate).
 */
export const signerIdFromKeys = (keys: Keyset | KeysetWithSecrets): Base58 =>
  fingerprint(redactKeys(keys).signature)
