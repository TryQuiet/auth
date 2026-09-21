import { createKeyset } from '@localfirst/crdx'
import { randomKey } from '@localfirst/crypto'
import type { Host, ServerWithSecrets } from './types.js'
import { KeyType, signerIdFromKeys } from 'util/index.js'

/**
 * Fixed derivation label for a server's identity keyset — the same trick `createDevice` uses: the
 * `serverId` is derived from these keys, so the derivation can't depend on the id.
 */
const SERVER_IDENTITY_KEY_SCOPE = {
  type: KeyType.SERVER_IDENTITY,
  name: KeyType.SERVER_IDENTITY,
} as const

/**
 * Creates a server with an immutable signing identity (`identityKeys`, fingerprinted as
 * `serverId`) and a separate rotatable keyset (`keys`) for lockboxes.
 */
export const createServer = ({ host, seed = randomKey() }: Params): ServerWithSecrets => {
  const derivedIdentityKeys = createKeyset(SERVER_IDENTITY_KEY_SCOPE, seed)
  const serverId = signerIdFromKeys(derivedIdentityKeys)
  const identityKeys = { ...derivedIdentityKeys, name: serverId }

  // The rotatable keys are named for the identity they belong to; unlike the identity keys, their
  // name is a label rather than a commitment, since a new generation has different key material.
  const keys = createKeyset({ type: KeyType.SERVER, name: serverId }, seed)

  return { host, serverId, identityKeys, keys }
}

type Params = {
  host: Host

  /** A strong secret from which both keysets are derived. If not provided, one is generated. */
  seed?: string
}
