import { append, createGraph, decryptGraph } from 'graph/index.js'
import {
  DEFAULT_SYNC_LIMITS,
  initSyncState,
  receiveMessage,
  type SyncMessage,
} from 'sync/index.js'
import { createUser } from 'user/index.js'
import { TEST_GRAPH_KEYS as keys } from 'util/testing/setup.js'
import { describe, expect, it, vi } from 'vitest'

describe('sync message hardening', () => {
  it('rejects cyclic topology before decryption', () => {
    const alice = createUser('alice')
    const graph = createGraph<any>({ user: alice, name: 'test graph', keys })
    const first = append({ graph, action: { type: 'FIRST' }, user: alice, keys })
    const second = append({ graph: first, action: { type: 'SECOND' }, user: alice, keys })
    const [firstHash] = first.head
    const [secondHash] = second.head
    const decrypt = vi.fn(decryptGraph)
    const message: SyncMessage = {
      root: graph.root,
      head: second.head,
      links: {
        [firstHash]: first.encryptedLinks[firstHash],
        [secondHash]: second.encryptedLinks[secondHash],
      },
      parentMap: {
        [firstHash]: [secondHash],
        [secondHash]: [firstHash],
      },
    }

    const [nextGraph, state] = receiveMessage(
      graph,
      initSyncState(),
      message,
      keys,
      decrypt
    )

    expect(nextGraph).toBe(graph)
    expect(state.failedSyncCount).toBe(1)
    expect(state.our.reportedError?.message).toMatch(/cycle/)
    expect(state.their.head).toEqual([])
    expect(decrypt).not.toHaveBeenCalled()
  })

  it('rejects advertised parents that do not match authenticated link bodies', () => {
    const alice = createUser('alice')
    const graph = createGraph<any>({ user: alice, name: 'test graph', keys })
    const localGraph = append({ graph, action: { type: 'FIRST' }, user: alice, keys })
    const remoteGraph = append({
      graph: localGraph,
      action: { type: 'SECOND' },
      user: alice,
      keys,
    })
    const [remoteHash] = remoteGraph.head
    const message: SyncMessage = {
      root: graph.root,
      head: remoteGraph.head,
      links: { [remoteHash]: remoteGraph.encryptedLinks[remoteHash] },
      parentMap: { [remoteHash]: [graph.root] },
    }

    const [nextGraph, state] = receiveMessage(localGraph, initSyncState(), message, keys)

    expect(nextGraph).toBe(localGraph)
    expect(state.failedSyncCount).toBe(1)
    expect(state.our.reportedError?.message).toMatch(/Authenticated parents/)
    expect(state.their.head).toEqual([])
  })

  it('enforces configurable pending-link limits before decryption', () => {
    const alice = createUser('alice')
    const graph = createGraph<any>({ user: alice, name: 'test graph', keys })
    const remoteGraph = append({ graph, action: { type: 'FIRST' }, user: alice, keys })
    const [remoteHash] = remoteGraph.head
    const decrypt = vi.fn(decryptGraph)
    const message: SyncMessage = {
      root: graph.root,
      head: remoteGraph.head,
      links: { [remoteHash]: remoteGraph.encryptedLinks[remoteHash] },
      parentMap: { [remoteHash]: [graph.root] },
    }

    const [nextGraph, state] = receiveMessage(
      graph,
      initSyncState(),
      message,
      keys,
      decrypt,
      undefined,
      { ...DEFAULT_SYNC_LIMITS, maxPendingLinks: 0 }
    )

    expect(nextGraph).toBe(graph)
    expect(state.failedSyncCount).toBe(1)
    expect(state.our.reportedError?.message).toMatch(/pending-link limit/)
    expect(decrypt).not.toHaveBeenCalled()
  })
})
