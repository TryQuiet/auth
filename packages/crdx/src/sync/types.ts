import { type EncryptedLink, type LinkMap } from 'graph/index.js'
import { type Hash } from 'util/index.js'
import { type ValidationError } from 'validator/index.js'

export type SyncState = {
  their: {
    /** Their head as of the last time they sent a sync message. */
    head: Hash[]

    /** Received links accumulated for the current validation/merge attempt. */
    encryptedLinks: Record<Hash, EncryptedLink>

    /** Advertised parents accumulated for the current validation/merge attempt. */
    parentMap: LinkMap

    /** Hashes of links they asked for in the last message. */
    need: Hash[]
  }

  our: {
    /** Our head as of the last message */
    head: Hash[]

    /** The last error we sent them */
    reportedError?: ValidationError

    /** Our head when we sent the last linkMap, so we don't keep sending it */
    parentMapAtHead?: Hash[]

    /** List of links we've sent them, so we don't send them multiple times */
    links: Hash[]
  }

  /** The head we had in common with this peer the last time we synced. If empty, we haven't synced before. */
  lastCommonHead: Hash[]

  /**
   * Count of rejected syncs, including malformed messages, root mismatches, resource-limit or
   * topology failures, decryption failures, and invalid merged graphs.
   */
  failedSyncCount: number
}

export type SyncMessage = {
  /** Our graph root. A peer with a different root is rejected. */
  root: Hash

  /** Our head at the time of sending. */
  head: Hash[]

  /** Encrypted links supplied to the peer. */
  links?: Record<Hash, EncryptedLink>

  /** Our most recent hashes and their dependencies. */
  parentMap?: LinkMap

  /** Any hashes we know we need. */
  need?: Hash[]

  /** Any errors caused by their last sync message. */
  error?: ValidationError
}

/** Defensive per-peer bounds applied before and during sync graph reconstruction. */
export type SyncLimits = {
  /** Maximum number of received links accumulated for one merge attempt. */
  maxPendingLinks: number

  /** Maximum aggregate encrypted-body bytes across pending links. */
  maxPendingCiphertextBytes: number

  /** Maximum parent-map entries; also caps `head` and `need` hash arrays. */
  maxParentEntries: number

  /** Maximum aggregate parent edges. */
  maxParentEdges: number

  /** Maximum work steps forwarded to graph decryption. */
  maxTraversalSteps: number
}

/** Frozen default defensive bounds for sync messages and graph traversal. */
export const DEFAULT_SYNC_LIMITS: SyncLimits = Object.freeze({
  maxPendingLinks: 10_000,
  maxPendingCiphertextBytes: 64 * 1024 * 1024,
  maxParentEntries: 20_000,
  maxParentEdges: 50_000,
  maxTraversalSteps: 100_000,
})
