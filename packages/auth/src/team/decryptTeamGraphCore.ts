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
  /** Encrypted graph and child topology to traverse. */
  encryptedGraph: MaybePartlyDecryptedGraph<TeamAction, TeamContext>

  /** First-generation or retained team keys used to begin decryption. */
  teamKeys: KeysetWithSecrets | KeysetWithSecrets[] | Keyring

  /** Device keys used to open rotated team keys discovered in graph lockboxes. */
  deviceKeys: KeysetWithSecrets

  /**
   * Locally accepted graph whose plaintext may be reused only when the encrypted-link object is
   * identical. Public callers must not supply this capability.
   */
  trustedGraph?: TeamGraph
  extendableLogger?: Logger

  /** Maximum number of enter steps before aborting. Defaults to 50,000. */
  maxTraversalSteps?: number
}

/**
 * Decrypts a team graph with iterative, per-path state reduction so newly discovered rotation keys
 * are available to descendants. Rejects cycles, missing links, and traversal-limit exhaustion.
 */
export const decryptTeamGraphCore = ({
  encryptedGraph,
  teamKeys,
  deviceKeys,
  trustedGraph,
  extendableLogger,
  maxTraversalSteps = 50_000,
}: DecryptTeamGraphCoreOptions): TeamGraph => {
  const logger =
    extendableLogger !== undefined
      ? extendableLogger.extend('decryptTeamGraph')
      : new Logger({ moduleName: 'auth:decryptTeamGraph' })
  const keyring = createKeyring(teamKeys)

  const { encryptedLinks, childMap, root } = encryptedGraph
  const decryptedByHash: Record<Hash, TeamLink> = {}

  type TraversalFrame =
    | { phase: 'enter'; hash: Hash; previousKeys: KeysetWithSecrets; previousState: TeamState }
    | { phase: 'exit'; hash: Hash }

  const rootPublicKey = encryptedLinks[root].recipientPublicKey
  const rootKeys = keyring[rootPublicKey]
  const activePath = new Set<Hash>()
  const stack: TraversalFrame[] = [
    { phase: 'enter', hash: root, previousKeys: rootKeys, previousState: initialState },
  ]
  let traversalSteps = 0

  while (stack.length > 0) {
    const frame = stack.pop()!
    if (frame.phase === 'exit') {
      activePath.delete(frame.hash)
      continue
    }
    if (++traversalSteps > maxTraversalSteps) {
      throw new Error('Team graph decryption exceeded its traversal limit')
    }

    const { hash, previousKeys, previousState } = frame
    if (activePath.has(hash)) {
      throw new Error(`Team graph decryption encountered a cycle at '${hash}'`)
    }
    activePath.add(hash)
    stack.push({ phase: 'exit', hash })

    const encryptedLink = encryptedLinks[hash]
    if (encryptedLink === undefined) {
      throw new Error(`Team graph decryption is missing link '${hash}'`)
    }
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
      for (const childHash of [...children].reverse()) {
        if (encryptedLinks[childHash] === undefined) continue
        stack.push({
          phase: 'enter',
          hash: childHash,
          previousKeys: newKeys,
          previousState: newState,
        })
      }
    }
  }

  return {
    ...encryptedGraph,
    links: decryptedByHash,
  }
}
