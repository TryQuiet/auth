import type { Keyset, KeysetWithSecrets } from '@localfirst/crdx'
import { KeyType, signerIdFromKeys } from 'util/index.js'

/** The minimum a server record has to expose for its identity to be checked. */
type ServerIdentity = {
  serverId: string
  identityKeys: Keyset | KeysetWithSecrets
  keys: Keyset | KeysetWithSecrets
}

/**
 * Confirms that a server record's id really is the fingerprint of its own identity signature key,
 * and that both of its keysets carry the metadata their roles require.
 *
 * The rotatable `keys` are checked too: they must name the identity they belong to, so that a
 * rotation can't quietly re-point a server's lockboxes at some other server's name. Their
 * generation is deliberately unconstrained — rotating is exactly what they're for.
 */
export const serverIdentityIsValid = ({ serverId, identityKeys, keys }: ServerIdentity): boolean =>
  identityKeys.type === KeyType.SERVER_IDENTITY &&
  identityKeys.generation === 0 && // identity keys are immutable, so they never rotate
  identityKeys.name === serverId &&
  signerIdFromKeys(identityKeys) === serverId &&
  keys.type === KeyType.SERVER &&
  keys.name === serverId
