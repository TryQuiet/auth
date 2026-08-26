import { getChildMap } from '@localfirst/crdx'
import { decryptTeamGraph } from 'team/decryptTeamGraph.js'
import { setup } from 'util/testing/index.js'
import { describe, expect, it } from 'vitest'

describe('decryptTeamGraph traversal', () => {
  it('decrypts every link of a well-formed graph', () => {
    const { alice } = setup('alice')
    alice.team.setTeamName('Updated team')
    const { graph } = alice.team

    const decrypted = decryptTeamGraph({
      encryptedGraph: { ...graph, childMap: getChildMap(graph) },
      teamKeys: alice.team.teamKeyring(),
      deviceKeys: alice.device.keys,
    })

    expect(Object.keys(decrypted.links).sort()).toEqual(Object.keys(graph.links).sort())
  })

  it('rejects a cyclic child map instead of walking it forever', () => {
    const { alice } = setup('alice')
    const { graph } = alice.team
    const childMap = getChildMap(graph)

    expect(() =>
      decryptTeamGraph({
        encryptedGraph: {
          ...graph,
          childMap: { ...childMap, [graph.root]: [...(childMap[graph.root] ?? []), graph.root] },
        },
        teamKeys: alice.team.teamKeyring(),
        deviceKeys: alice.device.keys,
      })
    ).toThrow(/cycle/)
  })

  it('bounds how far it will walk', () => {
    const { alice } = setup('alice')
    alice.team.setTeamName('Updated team')
    const { graph } = alice.team

    expect(() =>
      decryptTeamGraph({
        encryptedGraph: { ...graph, childMap: getChildMap(graph) },
        teamKeys: alice.team.teamKeyring(),
        deviceKeys: alice.device.keys,
        maxTraversalSteps: 1,
      })
    ).toThrow(/traversal limit/)
  })

  it('skips children it has no ciphertext for rather than failing', () => {
    const { alice } = setup('alice')
    const { graph } = alice.team
    const childMap = getChildMap(graph)

    const decrypted = decryptTeamGraph({
      encryptedGraph: {
        ...graph,
        childMap: { ...childMap, [graph.root]: [...(childMap[graph.root] ?? []), 'nonexistent'] },
      },
      teamKeys: alice.team.teamKeyring(),
      deviceKeys: alice.device.keys,
    })

    expect(Object.keys(decrypted.links)).not.toContain('nonexistent')
  })
})
