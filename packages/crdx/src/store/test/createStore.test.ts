import { asymmetric, signatures, LINK_AUTHORSHIP } from '@localfirst/crypto'
import { createGraph, getRoot, hashEncryptedLink, serialize } from 'graph/index.js'
import { createStore } from 'store/index.js'
import 'util/testing/expect/toBeValid'
import { createTestSigner, TEST_GRAPH_KEYS as keys } from 'util/testing/setup.js'
import { describe, expect, test } from 'vitest'
import {
  counterReducer,
  type CounterAction,
  type CounterState,
  type IncrementAction,
} from './shared/counterReducer.js'

const alice = createTestSigner('alice')
const bob = createTestSigner('bob')
const eve = createTestSigner('eve')

describe('createStore', () => {
  test('no graph provided', () => {
    const aliceStore = createStore({
      signer: alice,
      reducer: counterReducer,
      keys,
    })
    const graph = aliceStore.getGraph()
    expect(Object.keys(graph.links)).toHaveLength(1)
  })

  test('serialized graph provided', () => {
    const graph = createGraph<CounterAction>({
      signer: alice,
      name: 'counter',
      keys,
    })
    const aliceStore = createStore({
      signer: alice,
      graph,
      reducer: counterReducer,
      keys,
    })
    aliceStore.dispatch({ type: 'INCREMENT' })
    aliceStore.dispatch({ type: 'INCREMENT' })

    const serializedGraph = aliceStore.save()

    const bobStore = createStore<CounterState, IncrementAction, Record<string, unknown>>({
      signer: bob,
      graph: serializedGraph,
      reducer: counterReducer,
      keys,
    })
    const bobState = bobStore.getState()
    expect(bobState.value).toEqual(2)
  })

  test('Eve tampers with the serialized graph', () => {
    // 👩🏾 Alice makes a new store and saves it
    const graph = createGraph<CounterAction>({
      signer: alice,
      name: 'counter',
      keys,
    })
    const aliceStore = createStore({
      signer: alice,
      graph,
      reducer: counterReducer,
      keys,
    })

    // 🦹‍♀️ Eve tampers with the serialized graph
    const tamperedGraph = aliceStore.getGraph()
    const rootLink = getRoot(tamperedGraph)
    rootLink.body.signer = eve.info // she names herself as the author of the root

    // 🦹‍♀️ She reencrypts and re-signs the link with her own keys — the team keys let her build a
    // well-formed box, and nothing stops her signing her own handiwork
    const encryptedBody = asymmetric.encryptBytes({
      secret: rootLink.body,
      recipientPublicKey: keys.encryption.publicKey,
      senderSecretKey: eve.keys.encryption.secretKey,
    })
    graph.encryptedLinks[tamperedGraph.root] = {
      encryptedBody,
      signature: signatures.sign(
        hashEncryptedLink(encryptedBody),
        eve.keys.signature.secretKey,
        LINK_AUTHORSHIP
      ),
      recipientPublicKey: keys.encryption.publicKey,
      senderPublicKey: eve.keys.encryption.publicKey,
    }

    const tamperedSerializedGraph = serialize(tamperedGraph)

    // 👩🏾 Alice is not fooled: the root's contents no longer hash to the root hash, and an invalid
    // graph fails closed while the store is being built, before any caller can observe or persist
    // the state derived from it
    expect(() =>
      createStore<CounterState, IncrementAction, Record<string, unknown>>({
        signer: alice,
        graph: tamperedSerializedGraph,
        reducer: counterReducer,
        keys,
      })
    ).toThrow()
  })
})
