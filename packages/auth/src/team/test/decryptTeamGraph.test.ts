import { asymmetric } from '@localfirst/crypto'
import { getChildMap } from '@localfirst/crdx'
import type { TeamGraph } from 'team/types.js'
import { setup } from 'util/testing/index.js'
import { describe, expect, it, vi } from 'vitest'
import { decryptTeamGraph } from '../decryptTeamGraph.js'
import { decryptTrustedTeamGraph } from '../decryptTrustedTeamGraph.js'

describe('decryptTeamGraph trusted plaintext reuse', () => {
  it('does not decrypt links retained from the exact trusted graph', () => {
    const { alice } = setup('alice')
    alice.team.setTeamName('Updated team')
    const { graph } = alice.team
    const decrypt = vi.spyOn(asymmetric, 'decryptBytes')

    try {
      const decrypted = decryptTrustedTeamGraph({
        encryptedGraph: { ...graph, childMap: getChildMap(graph) },
        teamKeys: alice.team.teamKeyring(),
        deviceKeys: alice.device.keys,
        trustedGraph: graph,
      })

      expect(graphDecryptions(decrypt.mock.calls, graph)).toBe(0)
      for (const hash of Object.keys(graph.links)) {
        expect(decrypted.links[hash]).toBe(graph.links[hash])
      }
    } finally {
      decrypt.mockRestore()
    }
  })

  it('decrypts a link whose encrypted object was replaced instead of trusting its plaintext', () => {
    const { alice } = setup('alice')
    alice.team.setTeamName('Authenticated name')
    const trustedGraph = alice.team.graph
    const [head] = trustedGraph.head
    const encryptedGraph = {
      ...trustedGraph,
      childMap: getChildMap(trustedGraph),
      encryptedLinks: {
        ...trustedGraph.encryptedLinks,
        [head]: { ...trustedGraph.encryptedLinks[head] },
      },
      links: {
        ...trustedGraph.links,
        [head]: {
          ...trustedGraph.links[head],
          body: { ...trustedGraph.links[head].body, payload: { teamName: 'Forged name' } },
        },
      },
    }
    const decrypt = vi.spyOn(asymmetric, 'decryptBytes')

    try {
      const decrypted = decryptTrustedTeamGraph({
        encryptedGraph,
        teamKeys: alice.team.teamKeyring(),
        deviceKeys: alice.device.keys,
        trustedGraph,
      })

      expect(graphDecryptions(decrypt.mock.calls, trustedGraph)).toBe(1)
      expect(decrypted.links[head].body).toEqual(trustedGraph.links[head].body)
      expect(decrypted.links[head]).not.toBe(encryptedGraph.links[head])
    } finally {
      decrypt.mockRestore()
    }
  })

  it('does not accept a trusted graph smuggled into the public options object', () => {
    const { alice } = setup('alice')
    alice.team.setTeamName('Authenticated name')
    const { graph } = alice.team
    const decrypt = vi.spyOn(asymmetric, 'decryptBytes')

    try {
      decryptTeamGraph({
        encryptedGraph: { ...graph, childMap: getChildMap(graph) },
        teamKeys: alice.team.teamKeyring(),
        deviceKeys: alice.device.keys,
        trustedGraph: graph,
      } as Parameters<typeof decryptTeamGraph>[0])

      expect(graphDecryptions(decrypt.mock.calls, graph)).toBe(Object.keys(graph.links).length)
    } finally {
      decrypt.mockRestore()
    }
  })
})

type DecryptCall = Parameters<typeof asymmetric.decryptBytes>

const graphDecryptions = (calls: DecryptCall[], graph: TeamGraph): number => {
  const ciphertexts = Object.values(graph.encryptedLinks).map(link => link.encryptedBody)
  return calls.filter(([options]) =>
    ciphertexts.some(ciphertext => bytesAreEqual(options.cipher, ciphertext))
  ).length
}

const bytesAreEqual = (left: Uint8Array, right: Uint8Array): boolean =>
  left.length === right.length && left.every((byte, index) => byte === right[index])
