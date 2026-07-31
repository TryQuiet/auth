import { asymmetric } from '@localfirst/crypto'
import { baseResolver, createGraph, getRoot, serialize } from 'graph/index.js'
import { createStore, makeMachine } from 'store/index.js'
import { createUser } from 'user/index.js'
import 'util/testing/expect/toBeValid'
import { TEST_GRAPH_KEYS as keys } from 'util/testing/setup.js'
import { fail, type ValidatorSet } from 'validator/index.js'
import { describe, expect, test, vi } from 'vitest'
import {
  counterReducer,
  type CounterAction,
  type CounterState,
  type IncrementAction,
} from './shared/counterReducer.js'

const alice = createUser('alice')
const bob = createUser('bob')
const eve = createUser('eve')

describe('createStore', () => {
  test('no graph provided', () => {
    const aliceStore = createStore({
      user: alice,
      reducer: counterReducer,
      keys,
    })
    const graph = aliceStore.getGraph()
    expect(Object.keys(graph.links)).toHaveLength(1)
  })

  test('serialized graph provided', () => {
    const graph = createGraph<CounterAction>({
      user: alice,
      name: 'counter',
      keys,
    })
    const aliceStore = createStore({
      user: alice,
      graph,
      reducer: counterReducer,
      keys,
    })
    aliceStore.dispatch({ type: 'INCREMENT' })
    aliceStore.dispatch({ type: 'INCREMENT' })

    const serializedGraph = aliceStore.save()

    const bobStore = createStore<CounterState, IncrementAction, Record<string, unknown>>({
      user: bob,
      graph: serializedGraph,
      reducer: counterReducer,
      keys,
    })
    const bobState = bobStore.getState()
    expect(bobState.value).toEqual(2)
  })

  test('reuses an opaque machine result without reducing the graph again', () => {
    const graph = createGraph<CounterAction>({ user: alice, name: 'counter', keys })
    const initialState = {} as CounterState
    const reducer = vi.fn(counterReducer)
    const machine = makeMachine<CounterState, CounterAction, Record<string, unknown>>({
      initialState,
      reducer,
      resolver: baseResolver,
    })
    const machineResult = machine.derive(graph)
    expect(reducer).toHaveBeenCalledTimes(1)
    reducer.mockClear()

    const store = createStore<CounterState, CounterAction, Record<string, unknown>>({
      user: bob,
      graph,
      initialState,
      reducer,
      resolver: baseResolver,
      keys,
      machineResult,
    })

    expect(store.getState()).toBe(machineResult.state)
    expect(reducer).not.toHaveBeenCalled()
    expect(() =>
      createStore<CounterState, CounterAction, Record<string, unknown>>({
        user: bob,
        graph,
        initialState,
        reducer,
        resolver: baseResolver,
        keys,
        machineResult,
      })
    ).toThrow('Machine result does not match')
  })

  test('rejects a machine result derived from a different graph', () => {
    const firstGraph = createGraph<CounterAction>({ user: alice, name: 'first', keys })
    const secondGraph = createGraph<CounterAction>({ user: alice, name: 'second', keys })
    const initialState = {} as CounterState
    const machine = makeMachine<CounterState, CounterAction, Record<string, unknown>>({
      initialState,
      reducer: counterReducer,
      resolver: baseResolver,
    })
    const machineResult = machine.derive(firstGraph)

    expect(() =>
      createStore<CounterState, CounterAction, Record<string, unknown>>({
        user: bob,
        graph: secondGraph,
        initialState,
        reducer: counterReducer,
        resolver: baseResolver,
        keys,
        machineResult,
      })
    ).toThrow('Machine result does not match')
  })

  test('rejects a machine result when its graph changed after derivation', () => {
    const graph = createGraph<CounterAction>({ user: alice, name: 'counter', keys })
    const initialState = {} as CounterState
    const machine = makeMachine<CounterState, CounterAction, Record<string, unknown>>({
      initialState,
      reducer: counterReducer,
      resolver: baseResolver,
    })
    const machineResult = machine.derive(graph)
    graph.links[graph.root].body.timestamp += 1

    expect(() =>
      createStore<CounterState, CounterAction, Record<string, unknown>>({
        user: bob,
        graph,
        initialState,
        reducer: counterReducer,
        resolver: baseResolver,
        keys,
        machineResult,
      })
    ).toThrow('Machine result does not match')
  })

  test('rejects a machine result when its derived state changed before consumption', () => {
    const graph = createGraph<CounterAction>({ user: alice, name: 'counter', keys })
    const initialState = {} as CounterState
    const machine = makeMachine<CounterState, CounterAction, Record<string, unknown>>({
      initialState,
      reducer: counterReducer,
      resolver: baseResolver,
    })
    const machineResult = machine.derive(graph)
    machineResult.state.value = 99

    expect(() =>
      createStore<CounterState, CounterAction, Record<string, unknown>>({
        user: bob,
        graph,
        initialState,
        reducer: counterReducer,
        resolver: baseResolver,
        keys,
        machineResult,
      })
    ).toThrow('Machine result does not match')
  })

  test('rejects a machine result when validators changed after derivation', () => {
    const graph = createGraph<CounterAction>({ user: alice, name: 'counter', keys })
    const initialState = {} as CounterState
    const validators: ValidatorSet = {}
    const machine = makeMachine<CounterState, CounterAction, Record<string, unknown>>({
      initialState,
      reducer: counterReducer,
      resolver: baseResolver,
      validators,
    })
    const machineResult = machine.derive(graph)
    validators.rejectLateChange = () => fail('late validator')

    expect(() =>
      createStore<CounterState, CounterAction, Record<string, unknown>>({
        user: bob,
        graph,
        initialState,
        reducer: counterReducer,
        resolver: baseResolver,
        validators,
        keys,
        machineResult,
      })
    ).toThrow('Machine result does not match')
  })

  test('Eve tampers with the serialized graph', () => {
    // 👩🏾 Alice makes a new store and saves it
    const graph = createGraph<CounterAction>({
      user: alice,
      name: 'counter',
      keys,
    })
    const aliceStore = createStore({
      user: alice,
      graph,
      reducer: counterReducer,
      keys,
    })

    // 🦹‍♀️ Eve tampers with the serialized graph
    const tamperedGraph = aliceStore.getGraph()
    const rootLink = getRoot(tamperedGraph)
    rootLink.body.userId = eve.userId // she replaces Alice's user info in the root with Eve
    graph.encryptedLinks[tamperedGraph.root] = {
      encryptedBody: asymmetric.encryptBytes({
        secret: rootLink.body,
        recipientPublicKey: keys.encryption.publicKey,
        senderSecretKey: eve.keys.encryption.secretKey,
      }),
      recipientPublicKey: keys.encryption.publicKey,
      senderPublicKey: eve.keys.encryption.publicKey,
    }

    const tamperedSerializedGraph = serialize(tamperedGraph)

    // 👩🏾 Alice tries to load the modified graph
    // 👩🏾 Alice is not fooled because invalid graphs fail closed during initial load
    expect(() =>
      createStore<CounterState, IncrementAction, Record<string, unknown>>({
        user: alice,
        graph: tamperedSerializedGraph,
        reducer: counterReducer,
        keys,
      })
    ).toThrow()
  })
})
