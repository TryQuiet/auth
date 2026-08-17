import { Logger } from '@localfirst/shared'
import { decryptGraph, type DecryptFn } from 'graph/decrypt.js'
import {
  getChildMap,
  invertLinkMap,
  merge,
  type Action,
  type EncryptedLink,
  type Graph,
  type LinkMap,
} from 'graph/index.js'
import { createKeyring, type Keyring, type KeysetWithSecrets } from 'keyset/index.js'
import { type Hash } from 'util/index.js'
import { validate, ValidationError } from 'validator/index.js'
import { DEFAULT_SYNC_LIMITS, type SyncLimits, type SyncMessage, type SyncState } from './types.js'

/**
 * Receives a sync message from a peer and updates our sync state accordingly so that
 * `generateMessage` can determine what information they need. Also possibly updates our graph with
 * information from them.
 *
 * Everything in the message is peer-supplied and arrives before the peer has proved anything, so
 * nothing here may assert, throw, or wander: a malformed or hostile message has to come back as a
 * recorded sync failure, not as an exception out of the caller's state machine.
 *
 * @returns A tuple `[graph, state]` containing our updated graph and our updated sync state with
 * this peer.
 * */
export const receiveMessage = <A extends Action, C>(
  /** Our current graph */
  graph: Graph<A, C>,

  /** Our sync state with this peer */
  prevState: SyncState,

  /** The sync message they've just sent */
  message: SyncMessage,

  keys: KeysetWithSecrets | Keyring,

  decrypt: DecryptFn = decryptGraph,
  extendableLogger?: Logger,
  limits: SyncLimits = DEFAULT_SYNC_LIMITS
): [Graph<A, C>, SyncState] => {
  const logger = extendableLogger != null ? extendableLogger.extend('receiveMessage') : new Logger({ moduleName: 'auth:receiveMessage' })
  // if a keyset was provided, wrap it in a keyring
  const keyring = createKeyring(keys)

  try {
    validateSyncMessage(message, limits)
    // This should never happen between honest peers, but it's their claim, not a fact
    if (graph.root !== message.root) {
      throw new ValidationError(`Can't sync graphs with different roots`)
    }
  } catch (error) {
    return [graph, recordSyncFailure(prevState, toValidationError(error))]
  }

  const their = message

  const state: SyncState = {
    ...prevState,
    their: {
      head: their.head,
      need: their.need ?? [],
      encryptedLinks: { ...prevState.their.encryptedLinks, ...(their.links ?? {}) },
      parentMap: { ...prevState.their.parentMap, ...(their.parentMap ?? {}) },
    },
  }

  // if we've received links from them, try to reconstruct their graph and merge
  if (Object.keys(state.their.encryptedLinks).length > 0) {
    try {
      // The pending set accumulates across messages, so re-check it as a whole: a peer can't get
      // past the per-message limits by dribbling a huge topology in over many messages.
      validatePendingTopology(graph, state.their.encryptedLinks, state.their.parentMap, limits)

      // reconstruct their graph
      const ourChildMap = getChildMap(graph)
      const theirChildMap = invertLinkMap(state.their.parentMap)
      const childMap = mergeLinkMaps(ourChildMap, theirChildMap)

      const encryptedLinks = {
        ...graph.encryptedLinks,
        ...state.their.encryptedLinks,
      }
      const encryptedGraph = {
        ...graph,
        head: their.head,
        encryptedLinks,
        childMap,
      }

      const theirGraph = decrypt({
        encryptedGraph,
        keys: keyring,
        maxTraversalSteps: limits.maxTraversalSteps,
      })

      // The parent map is unauthenticated; each link's own `prev` is not. Now that we've opened
      // the links, make the peer's claimed topology match the one their links actually attest to,
      // so a lie about the shape of the graph can't survive into the merge.
      validateAuthenticatedTopology(theirGraph, state.their.encryptedLinks, state.their.parentMap)

      // merge with our graph
      const mergedGraph = merge(graph, theirGraph)

      // check the integrity of the merged graph
      const validation = validate(mergedGraph, undefined, logger)
      if (!validation.isValid) throw validation.error

      graph = mergedGraph
    } catch (error) {
      // We only get here if we've received bad links from them — maliciously, or not. The
      // application should monitor `failedSyncCount` and decide not to trust them if it's too high.
      const failed = recordSyncFailure(prevState, toValidationError(error))
      state.failedSyncCount = failed.failedSyncCount
      state.our = failed.our
      state.their = failed.their
    }

    // either way, we can discard all pending links
    state.their.encryptedLinks = {}
    state.their.parentMap = {}
  }

  return [graph, state]
}

/** Rejects a message whose shape or size is not something we're willing to work on. */
const validateSyncMessage = (message: SyncMessage, limits: SyncLimits) => {
  if (!isRecord(message) || typeof message.root !== 'string') {
    throw new ValidationError('Sync message has an invalid root')
  }

  assertHashArray(message.head, 'head')
  if (message.need !== undefined) assertHashArray(message.need, 'need')
  if (
    message.head.length > limits.maxParentEntries ||
    (message.need?.length ?? 0) > limits.maxParentEntries
  ) {
    throw new ValidationError('Sync message exceeds the hash-list limit')
  }

  if (message.links !== undefined) {
    if (!isRecord(message.links)) throw new ValidationError('Sync links must be an object')
    for (const [hash, link] of Object.entries(message.links)) {
      if (
        typeof hash !== 'string' ||
        !isRecord(link) ||
        typeof link.senderPublicKey !== 'string' ||
        typeof link.recipientPublicKey !== 'string' ||
        !(link.encryptedBody instanceof Uint8Array)
      ) {
        throw new ValidationError('Sync message contains an invalid encrypted link')
      }
    }

    const entries = Object.entries(message.links)
    const ciphertextBytes = entries.reduce(
      (count, [, link]) => count + link.encryptedBody.byteLength,
      0
    )
    if (
      entries.length > limits.maxPendingLinks ||
      ciphertextBytes > limits.maxPendingCiphertextBytes
    ) {
      throw new ValidationError('Sync message exceeds the pending-link limit')
    }
  }

  if (message.parentMap !== undefined) {
    validateLinkMapShape(message.parentMap)
    const entries = Object.entries(message.parentMap) as Array<[Hash, Hash[]]>
    const edgeCount = entries.reduce((count, [, parents]) => count + parents.length, 0)
    if (entries.length > limits.maxParentEntries || edgeCount > limits.maxParentEdges) {
      throw new ValidationError('Sync message exceeds the topology-size limit')
    }
  }
}

/** Checks the accumulated pending set: within limits, self-consistent, and acyclic. */
const validatePendingTopology = <A extends Action, C>(
  graph: Graph<A, C>,
  encryptedLinks: Record<Hash, EncryptedLink>,
  parentMap: LinkMap,
  limits: SyncLimits
) => {
  const linkEntries = Object.entries(encryptedLinks) as Array<[Hash, EncryptedLink]>
  const parentEntries = Object.entries(parentMap) as Array<[Hash, Hash[]]>
  const parentEdgeCount = parentEntries.reduce((count, [, parents]) => count + parents.length, 0)
  const ciphertextBytes = linkEntries.reduce(
    (count, [, link]) => count + link.encryptedBody.byteLength,
    0
  )

  if (linkEntries.length > limits.maxPendingLinks) {
    throw new ValidationError('Sync message exceeds the pending-link limit')
  }

  if (ciphertextBytes > limits.maxPendingCiphertextBytes) {
    throw new ValidationError('Sync message exceeds the ciphertext-size limit')
  }

  if (parentEntries.length > limits.maxParentEntries || parentEdgeCount > limits.maxParentEdges) {
    throw new ValidationError('Sync message exceeds the topology-size limit')
  }

  validateLinkMapShape(parentMap)

  for (const [hash] of linkEntries) {
    if (parentMap[hash] === undefined) {
      throw new ValidationError(`Sync topology is missing parents for '${hash}'`)
    }
  }

  for (const [hash, parents] of parentEntries) {
    if (parents.includes(hash) || new Set(parents).size !== parents.length) {
      throw new ValidationError(`Sync topology has an invalid parent list for '${hash}'`)
    }

    // A link we already hold is authenticated; the peer doesn't get to restate its parents.
    const localLink = graph.links[hash]
    if (localLink !== undefined && !sameHashSet(localLink.body.prev, parents)) {
      throw new ValidationError(`Sync topology contradicts local link '${hash}'`)
    }
  }

  assertAcyclic(parentMap)
}

/** Makes the peer's claimed parents match what the decrypted links themselves say. */
const validateAuthenticatedTopology = <A extends Action, C>(
  graph: Graph<A, C>,
  receivedLinks: Record<Hash, EncryptedLink>,
  parentMap: LinkMap
) => {
  for (const hash of Object.keys(receivedLinks) as Hash[]) {
    const link = graph.links[hash]
    if (link === undefined || !sameHashSet(link.body.prev, parentMap[hash])) {
      throw new ValidationError(`Authenticated parents do not match sync topology for '${hash}'`)
    }
  }
}

/** Kahn's algorithm; a graph with a cycle leaves nodes unvisited. */
const assertAcyclic = (parentMap: LinkMap) => {
  const nodes = new Set<Hash>(Object.keys(parentMap) as Hash[])
  const remainingParents = new Map<Hash, number>()
  const childMap = invertLinkMap(parentMap)

  for (const node of nodes) {
    remainingParents.set(node, (parentMap[node] ?? []).filter(parent => nodes.has(parent)).length)
  }

  const queue = [...nodes].filter(node => remainingParents.get(node) === 0)
  let visited = 0
  while (queue.length > 0) {
    const node = queue.pop()!
    visited++
    for (const child of childMap[node] ?? []) {
      if (!nodes.has(child)) continue
      const remaining = (remainingParents.get(child) ?? 0) - 1
      remainingParents.set(child, remaining)
      if (remaining === 0) queue.push(child)
    }
  }

  if (visited !== nodes.size) throw new ValidationError('Sync topology contains a cycle')
}

const mergeLinkMaps = (ours: LinkMap, theirs: LinkMap): LinkMap => {
  const merged: LinkMap = { ...ours }
  for (const [hash, links] of Object.entries(theirs) as Array<[Hash, Hash[]]>) {
    merged[hash] = [...new Set([...(merged[hash] ?? []), ...links])]
  }

  return merged
}

const validateLinkMapShape = (map: LinkMap) => {
  if (!isRecord(map)) throw new ValidationError('Sync topology must be an object')
  for (const [hash, parents] of Object.entries(map) as Array<[Hash, unknown]>) {
    if (typeof hash !== 'string') throw new ValidationError('Sync topology has an invalid hash')
    assertHashArray(parents, `parents for '${hash}'`)
  }
}

function assertHashArray(value: unknown, label: string): asserts value is Hash[] {
  if (!Array.isArray(value) || value.some(hash => typeof hash !== 'string')) {
    throw new ValidationError(`Sync message has an invalid ${label}`)
  }
}

const sameHashSet = (left: readonly Hash[], right: readonly Hash[] | undefined) =>
  right !== undefined && left.length === right.length && left.every(hash => right.includes(hash))

const recordSyncFailure = (state: SyncState, error: ValidationError): SyncState => ({
  ...state,
  their: { ...state.their, encryptedLinks: {}, parentMap: {} },
  our: { ...state.our, reportedError: error },
  failedSyncCount: state.failedSyncCount + 1,
})

const toValidationError = (error: unknown) =>
  error instanceof ValidationError
    ? error
    : new ValidationError((error as Error)?.message ?? 'Invalid sync message', error)

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value)
