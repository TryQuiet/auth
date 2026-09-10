import { TEST_GRAPH_KEYS as keys, setup } from 'util/testing/setup.js'
import { describe, expect, test } from 'vitest'
import { append, createGraph, getHead, getRoot } from 'graph/index.js'
import { validate } from 'validator/index.js'
import 'util/testing/expect/toBeValid'

const { alice } = setup('alice')
const defaultSigner = alice

const _ = expect.objectContaining

describe('graphs', () => {
  test('append', () => {
    const graph1 = createGraph({ signer: defaultSigner, name: 'a', keys })
    const graph2 = append({
      graph: graph1,
      action: { type: 'FOO', payload: 'b' },
      signer: defaultSigner,
      keys,
    })

    expect(validate(graph2)).toBeValid()

    expect(getRoot(graph2)).toEqual(_({ body: _({ payload: _({ name: 'a' }) }) }))
    expect(getHead(graph2)).toEqual([_({ body: _({ payload: 'b' }) })])
  })
})
