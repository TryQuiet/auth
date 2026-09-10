import { createTestSigner, TEST_GRAPH_KEYS as keys } from 'util/testing/setup.js'
import { describe, expect, test } from 'vitest'
import { createStore } from 'store/index.js'
import { counterReducer } from './shared/counterReducer.js'

/*
This is intended to be the simplest possible proof of concept: An increment-only counter. There is
no custom resolver because there are no conflicts possible. 
*/

const alice = createTestSigner('alice')
const bob = createTestSigner('bob')

const setupCounter = () => {
  const aliceStore = createStore({ signer: alice, reducer: counterReducer, keys })

  const saved = aliceStore.getGraph()
  const bobStore = createStore({
    signer: bob,
    graph: saved,
    reducer: counterReducer,
    keys,
  })

  return { store: aliceStore, aliceStore, bobStore }
}

describe('counter', () => {
  describe('createStore', () => {
    test('initial state', () => {
      const { store } = setupCounter()
      expect(store.getState()).toEqual({ value: 0 })
    })

    test('increment', () => {
      const { store } = setupCounter()
      store.dispatch({ type: 'INCREMENT' })
      expect(store.getState().value).toEqual(1)
    })

    test('multiple increments', () => {
      const { store } = setupCounter()
      store.dispatch({ type: 'INCREMENT' })
      store.dispatch({ type: 'INCREMENT' })
      store.dispatch({ type: 'INCREMENT' })
      expect(store.getState().value).toEqual(3)
    })
  })

  describe('merge', () => {
    test('concurrent changes are merged', () => {
      const { aliceStore, bobStore } = setupCounter()

      // Bob and Alice make concurrent increments
      aliceStore.dispatch({ type: 'INCREMENT' })
      bobStore.dispatch({ type: 'INCREMENT' })

      // They each only have their own increments
      expect(aliceStore.getState().value).toEqual(1)
      expect(bobStore.getState().value).toEqual(1)

      // They sync up
      aliceStore.merge(bobStore.getGraph())
      bobStore.merge(aliceStore.getGraph())

      // They each have both increments
      expect(aliceStore.getState().value).toEqual(2)
      expect(bobStore.getState().value).toEqual(2)
    })
  })
})
