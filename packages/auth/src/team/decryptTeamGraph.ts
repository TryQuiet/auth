import {
  type Hash,
  createKeyring,
  decryptLink,
  type Keyring,
  type KeysetWithSecrets,
  type MaybePartlyDecryptedGraph,
} from '@localfirst/crdx'
import { initialState, TEAM_SCOPE } from './constants.js'
import { reducer } from './reducer.js'
import { keys } from './selectors/index.js'
import {
  type TeamAction,
  type TeamContext,
  type TeamGraph,
  type TeamLink,
  type TeamState,
} from './types.js'
import { Logger } from '@localfirst/shared'

/**
 * Decrypts a graph.
 *
 * This is a team-specific version of `decryptGraph` from crdx. When we're communicating with a
 * peer, we can't just use a single set of team keys to decrypt everything, because there might be
 * key rotations in links that we receive that we will need to decrypt subsequent links. When that
 * happens, each team member gets the new keys in a lockbox that's stored on the chain. So we need
 * to recurse through the chain, updating the keys if necessary before continuing to decrypt
 * further.
 */
export const decryptTeamGraph = ({
  encryptedGraph,
  teamKeys,
  deviceKeys,
  extendableLogger,
}: {
  encryptedGraph: MaybePartlyDecryptedGraph<TeamAction, TeamContext>

  /**
   * We need the first-generation team keys to get started. If the team keys have been rotated, we
   * will find them in lockboxes that we can get to with our device keys.
   */
  teamKeys: KeysetWithSecrets | KeysetWithSecrets[] | Keyring

  /**
   * We need our device keys so that we can get the latest team keys from the graph if they've been
   * rotated.
   */
  deviceKeys: KeysetWithSecrets

  extendableLogger?: Logger
}): TeamGraph => {
  const logger = extendableLogger != null ? extendableLogger.extend('decryptTeamGraph') : new Logger({ moduleName: 'auth:decryptTeamGraph' })
  const keyring = createKeyring(teamKeys)

  const { encryptedLinks, childMap, root } = encryptedGraph

  /** Recursively decrypts a link and its children. */
  const decrypt = (
    hash: Hash,
    previousKeys: KeysetWithSecrets,
    previousDecryptedLinks: Record<Hash, TeamLink> = {},
    previousState: TeamState = initialState
  ): Record<Hash, TeamLink> => {
    // Decrypt this link. A graph from a peer can carry attacker-chosen plaintext alongside its
    // ciphertext, so we always reconstruct the body from the bytes the hash commits to.
    const encryptedLink = encryptedLinks[hash]
    const decryptedLink = decryptLink<TeamAction, TeamContext>(encryptedLink, previousKeys)
    let decryptedLinks = {
      [hash]: decryptedLink,
    }

    // Reduce & see if there are new team keys.
    //
    // This walk follows one root-to-link path at a time, so the state we accumulate is only what
    // that path establishes — a link whose author was registered on a *concurrent* branch will
    // fail to validate here even though the merged graph is perfectly good. Decryption isn't the
    // acceptance boundary; the resolved, causally ordered sequence in `makeMachine` is, and it
    // revalidates everything. So a rejection here only means "can't learn key rotations down this
    // path", and we carry on with the keys we have.
    let newState = previousState
    try {
      newState = reducer(previousState, decryptedLink, logger)
    } catch (error) {
      logger.debug(`Could not reduce link ${hash} along this path while decrypting`, error)
    }

    let newKeys: KeysetWithSecrets | undefined
    try {
      newKeys = keys(newState, deviceKeys, TEAM_SCOPE)
      keyring[newKeys.encryption.publicKey] = newKeys
    } catch {
      newKeys = previousKeys
    }

    // Decrypt its children
    const children = childMap![hash]

    if (children) {
      for (const hash of children) {
        decryptedLinks = {
          ...decryptedLinks,
          ...decrypt(hash, newKeys, decryptedLinks, newState),
        }
      }
    }

    return { ...previousDecryptedLinks, ...decryptedLinks }
  }

  const rootPublicKey = encryptedLinks[root].recipientPublicKey
  const rootKeys = keyring[rootPublicKey]
  const decryptedLinks = decrypt(root, rootKeys)

  return {
    ...encryptedGraph,
    links: decryptedLinks,
  }
}
