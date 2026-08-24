import { describe, expect, test } from 'vitest'
import { append, type Graph } from 'graph/index.js'
import { createStore } from 'store/index.js'
import { type Reducer } from 'store/types.js'
import { type Hash } from 'util/index.js'
import { createTestSigner, TEST_GRAPH_KEYS as keys } from 'util/testing/setup.js'
import {
  counterReducer,
  type CounterAction,
  type CounterState,
} from './shared/counterReducer.js'

const alice = createTestSigner('alice')
const eve = createTestSigner('eve')

const setupCounter = (reducer: Reducer<CounterState, CounterAction> = counterReducer) => {
  const store = createStore({ signer: alice, reducer, keys })
  store.dispatch({ type: 'INCREMENT' })
  store.dispatch({ type: 'INCREMENT' })
  return store
}

/** Corrupts one link's ciphertext, so the link no longer hashes to the value the graph records. */
const tamper = (graph: Graph<CounterAction, Record<string, unknown>>, hash: Hash) => {
  const original = graph.encryptedLinks[hash]
  const encryptedBody = Uint8Array.from(original.encryptedBody)
  encryptedBody[encryptedBody.length - 1] ^= 0xff
  return {
    ...graph,
    encryptedLinks: { ...graph.encryptedLinks, [hash]: { ...original, encryptedBody } },
  }
}

describe('a rejected input leaves the store untouched', () => {
  test('rejected merge', () => {
    const store = setupCounter()
    const head = store.getGraph().head
    const state = store.getState()

    // 🦹‍♀️ Eve appends a link and then tampers with its ciphertext
    const theirGraph = append({
      graph: store.getGraph(),
      action: { type: 'INCREMENT', payload: 100 },
      signer: eve,
      keys,
    })
    const tamperedGraph = tamper(theirGraph, theirGraph.head[0])

    expect(() => {
      store.merge(tamperedGraph)
    }).toThrow()

    // the store still has exactly what it had before, so a rejected peer can't poison later merges
    expect(store.getGraph().head).toEqual(head)
    expect(store.getState()).toEqual(state)
    expect(store.validate()).toEqual({ isValid: true })
  })

  test('rejected dispatch', () => {
    const rejectFives: Reducer<CounterState, CounterAction> = (state, link, logger, graph) => {
      const action = link.body
      if (action.type === 'INCREMENT' && action.payload === 5) {
        throw new Error('the reducer rejects this action')
      }

      return counterReducer(state, link, logger, graph)
    }

    const store = setupCounter(rejectFives)
    const head = store.getGraph().head
    const state = store.getState()

    expect(() => {
      store.dispatch({ type: 'INCREMENT', payload: 5 })
    }).toThrow()

    // the rejected link was never installed, so the next dispatch builds on the last good head
    expect(store.getGraph().head).toEqual(head)
    expect(store.getState()).toEqual(state)

    store.dispatch({ type: 'INCREMENT' })
    expect(store.getState().value).toBe(state.value + 1)
  })
})

describe('makeMachine', () => {
  test('refuses to reduce an invalid graph', () => {
    const store = setupCounter()
    const tamperedGraph = tamper(store.getGraph(), store.getGraph().head[0])

    // building a store around an invalid graph throws rather than silently reducing it
    expect(() =>
      createStore<CounterState, CounterAction, Record<string, unknown>>({
        signer: alice,
        graph: tamperedGraph,
        reducer: counterReducer,
        keys,
      })
    ).toThrow()
  })
})
