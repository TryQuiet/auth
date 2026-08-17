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
import { assert, Logger } from '@localfirst/shared'

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
  maxTraversalSteps = 50_000,
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

  /**
   * Ceiling on how many links the walk will visit. The child map comes from a peer, and a link
   * reachable by many paths is visited once per path, so a crafted graph can blow this up. Well
   * past anything a real team produces.
   */
  maxTraversalSteps?: number
}): TeamGraph => {
  const logger = extendableLogger != null ? extendableLogger.extend('decryptTeamGraph') : new Logger({ moduleName: 'auth:decryptTeamGraph' })
  const keyring = createKeyring(teamKeys)

  const { encryptedLinks, childMap, root } = encryptedGraph
  const decryptedLinks: Record<Hash, TeamLink> = {}

  /**
   * A frame of the traversal. `exit` frames are how we know we've finished with a link's whole
   * subtree, so it can leave the active path again.
   */
  type TraversalFrame =
    | { phase: 'enter'; hash: Hash; previousKeys: KeysetWithSecrets; previousState: TeamState }
    | { phase: 'exit'; hash: Hash }

  const rootLink = encryptedLinks[root]
  assert(rootLink, `Can't decrypt team graph: the root link is missing`)
  const rootKeys = keyring[rootLink.recipientPublicKey]

  // This walk is iterative rather than recursive. The graph and its child map come from a peer, so
  // its depth is the peer's choice; recursion made a deep chain a stack overflow rather than an
  // error we could handle.
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

    // A child map that leads back to a link already on our path is a cycle, and would keep us
    // walking forever. A real graph is acyclic; every link commits to its parents by hash.
    if (activePath.has(hash)) {
      throw new Error(`Team graph decryption encountered a cycle at '${hash}'`)
    }

    activePath.add(hash)
    stack.push({ phase: 'exit', hash })

    // Decrypt this link. A graph from a peer can carry attacker-chosen plaintext alongside its
    // ciphertext, so we always reconstruct the body from the bytes the hash commits to.
    //
    // We decrypt against the whole keyring rather than just this path's `previousKeys`. Each link
    // names the exact generation it was sealed to (`recipientPublicKey`), so the keyring picks the
    // right one — but this walk visits links in graph order, not causal order, and a link authored
    // on a concurrent branch can be reached before this path has reduced the rotation that produced
    // its generation. Threading a single generation would then fail to open a link we hold the key
    // for; the keyring (seeded with every generation we can access, and grown as we discover more)
    // does not.
    const encryptedLink = encryptedLinks[hash]
    if (encryptedLink === undefined) {
      throw new Error(`Team graph decryption is missing link '${hash}'`)
    }

    const decryptedLink = decryptLink<TeamAction, TeamContext>(encryptedLink, keyring)
    decryptedLinks[hash] = decryptedLink

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
      // Reversed so that popping off the stack visits them in their original order
      for (const childHash of [...children].reverse()) {
        // A child map may name links we haven't been sent; that's a gap, not a fault
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
    links: decryptedLinks,
  }
}
