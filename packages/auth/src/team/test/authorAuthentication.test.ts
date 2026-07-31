import { append, createKeyring, createUser } from '@localfirst/crdx'
import * as teams from 'team/index.js'
import type { TeamAction, TeamContext, TeamGraph } from 'team/types.js'
import { setup } from 'util/testing/index.js'
import { describe, expect, it } from 'vitest'

describe('team action author authentication', () => {
  it("rejects an action that claims a member's identity but is encrypted by another key", () => {
    const { alice, eve } = setup('alice', { user: 'eve', member: false })
    const forgedAuthor = { ...eve.user, userId: alice.userId }
    const forgedGraph = append<TeamAction, TeamContext>({
      graph: alice.team.graph,
      action: { type: 'SET_TEAM_NAME', payload: { teamName: 'forged' } },
      user: forgedAuthor,
      context: { deviceId: eve.device.deviceId },
      keys: alice.team.teamKeys(),
    })

    expect(() =>
      teams.load(
        forgedGraph,
        alice.localContext,
        createKeyring(alice.team.teamKeys())
      )
    ).toThrow(/current encryption key/)
  })

  it('rejects an action from an unknown author', () => {
    const { alice } = setup('alice')
    const outsider = createUser('mallory')
    const forgedGraph = append<TeamAction, TeamContext>({
      graph: alice.team.graph,
      action: { type: 'SET_TEAM_NAME', payload: { teamName: 'forged' } },
      user: outsider,
      context: { deviceId: 'unknown-device' },
      keys: alice.team.teamKeys(),
    })

    expect(() =>
      teams.load(
        forgedGraph,
        alice.localContext,
        createKeyring(alice.team.teamKeys())
      )
    ).toThrow(/unknown or ambiguous/)
  })

  it('rejects actions authored after the member was removed', () => {
    const { alice, bob } = setup('alice', 'bob')
    alice.team.remove(bob.userId)
    const forgedGraph = append<TeamAction, TeamContext>({
      graph: alice.team.graph,
      action: { type: 'SET_METADATA', payload: { metadata: alice.team.state.metadata } },
      user: bob.user,
      context: { deviceId: bob.device.deviceId },
      keys: alice.team.teamKeys(),
    })

    expect(() =>
      teams.load(
        forgedGraph,
        alice.localContext,
        alice.team.teamKeyring()
      )
    ).toThrow(/unknown or ambiguous/)
  })

  it('ignores caller-supplied plaintext when merging through the public API', () => {
    const { alice, bob } = setup('alice', 'bob')
    bob.team.setTeamName('Authenticated name')
    const remoteGraph = bob.team.graph
    const head = remoteGraph.head[0]
    const forgedGraph = {
      ...remoteGraph,
      links: {
        ...remoteGraph.links,
        [head]: {
          ...remoteGraph.links[head],
          body: { ...remoteGraph.links[head].body, payload: { teamName: 'Forged name' } },
        },
      },
    } as TeamGraph

    alice.team.merge(forgedGraph)

    expect(alice.team.teamName).toBe('Authenticated name')
  })
})
