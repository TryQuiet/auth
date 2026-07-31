import {
  type Hash,
  createKeyring,
  decryptLink,
  type Keyring,
  type KeysetWithSecrets,
  type MaybePartlyDecryptedGraph,
} from '@localfirst/crdx'
import { Logger } from '@localfirst/shared'
import { initialState, TEAM_SCOPE } from './constants.js'
import { reducer } from './reducer.js'
import { keys } from './selectors/index.js'
import type { TeamAction, TeamContext, TeamGraph, TeamLink, TeamState } from './types.js'

export type DecryptTeamGraphCoreOptions = {
  encryptedGraph: MaybePartlyDecryptedGraph<TeamAction, TeamContext>
  teamKeys: KeysetWithSecrets | KeysetWithSecrets[] | Keyring
  deviceKeys: KeysetWithSecrets
  trustedGraph?: TeamGraph
  extendableLogger?: Logger
}

export const decryptTeamGraphCore = ({
  encryptedGraph,
  teamKeys,
  deviceKeys,
  trustedGraph,
  extendableLogger,
}: DecryptTeamGraphCoreOptions): TeamGraph => {
  const logger =
    extendableLogger !== undefined
      ? extendableLogger.extend('decryptTeamGraph')
      : new Logger({ moduleName: 'auth:decryptTeamGraph' })
  const keyring = createKeyring(teamKeys)

  const { encryptedLinks, childMap, root } = encryptedGraph
  const decryptedByHash: Record<Hash, TeamLink> = {}

  /** Recursively decrypts a link and its children. */
  const decrypt = (
    hash: Hash,
    previousKeys: KeysetWithSecrets,
    previousState: TeamState = initialState
  ): void => {
    const encryptedLink = encryptedLinks[hash]
    const decryptionKeys = keyring[encryptedLink.recipientPublicKey] ?? previousKeys
    const trustedLink =
      trustedGraph?.encryptedLinks[hash] === encryptedLink ? trustedGraph.links[hash] : undefined
    const decryptedLink =
      trustedLink ??
      decryptedByHash[hash] ??
      decryptLink<TeamAction, TeamContext>(encryptedLink, decryptionKeys)
    decryptedByHash[hash] = decryptedLink

    // Reduce along every traversal path to preserve key-discovery behavior at graph joins.
    const newState = reducer(previousState, decryptedLink, logger)
    let newKeys: KeysetWithSecrets | undefined
    try {
      newKeys = keys(newState, deviceKeys, TEAM_SCOPE)
      keyring[newKeys.encryption.publicKey] = newKeys
    } catch {
      newKeys = previousKeys
    }

    const children = childMap![hash]
    if (children) {
      for (const childHash of children) {
        if (encryptedLinks[childHash] === undefined) continue
        decrypt(childHash, newKeys, newState)
      }
    }
  }

  const rootPublicKey = encryptedLinks[root].recipientPublicKey
  const rootKeys = keyring[rootPublicKey]
  decrypt(root, rootKeys)

  return {
    ...encryptedGraph,
    links: decryptedByHash,
  }
}
