import {
  append,
  createKeyring,
  createKeyset,
  createUser,
  merge,
  redactKeys,
  type UserWithSecrets,
} from '@localfirst/crdx'
import * as teams from 'team/index.js'
import type { TeamAction, TeamContext, TeamGraph } from 'team/types.js'
import { KeyType } from 'util/index.js'
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
    ).toThrow(/causal frontier/)
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

  it.each(['before', 'after'] as const)(
    'accepts a concurrent pre-rotation action ordered %s the rotation',
    order => {
      const fixture = concurrentRotationFixture(order)

      expect(() =>
        teams.load(
          fixture.graph,
          fixture.localContext,
          createKeyring(fixture.teamKeys)
        )
      ).not.toThrow()
    }
  )

  it('rejects an old-key action when the rotation is in its causal past', () => {
    const fixture = concurrentRotationFixture('after')
    const staleGraph = append<TeamAction, TeamContext>({
      graph: fixture.rotationGraph,
      action: { type: 'SET_TEAM_NAME', payload: { teamName: 'stale' } },
      user: fixture.oldAuthor,
      context: { deviceId: fixture.localContext.device.deviceId },
      keys: fixture.teamKeys,
    })

    expect(() =>
      teams.load(staleGraph, fixture.localContext, createKeyring(fixture.teamKeys))
    ).toThrow(/causal frontier/)
  })

  it('accepts the rotated key after concurrent branches merge', () => {
    const fixture = concurrentRotationFixture('after')
    const mergedGraph = append<TeamAction, TeamContext>({
      graph: fixture.graph,
      action: { type: 'SET_TEAM_NAME', payload: { teamName: 'post-merge' } },
      user: { ...fixture.oldAuthor, keys: fixture.newKeys },
      context: { deviceId: fixture.localContext.device.deviceId },
      keys: fixture.teamKeys,
    })

    expect(() =>
      teams.load(mergedGraph, fixture.localContext, createKeyring(fixture.teamKeys))
    ).not.toThrow()
  })
})

const concurrentRotationFixture = (oldActionOrder: 'before' | 'after') => {
  const { alice } = setup('alice')
  const baseGraph = alice.team.graph
  const teamKeys = alice.team.teamKeys()
  const oldAuthor = structuredClone(alice.user) as UserWithSecrets
  const newKeys = createKeyset({ type: KeyType.USER, name: alice.userId })
  newKeys.generation = oldAuthor.keys.generation + 1
  const rotationGraph = append<TeamAction, TeamContext>({
    graph: baseGraph,
    action: {
      type: 'CHANGE_MEMBER_KEYS',
      payload: { keys: redactKeys(newKeys) },
    },
    user: oldAuthor,
    context: { deviceId: alice.device.deviceId },
    keys: teamKeys,
  })
  const rotationHash = rotationGraph.head[0]

  let oldActionGraph: TeamGraph | undefined
  for (let attempt = 0; attempt < 100; attempt++) {
    const candidate = append<TeamAction, TeamContext>({
      graph: baseGraph,
      action: {
        type: 'SET_METADATA',
        payload: { metadata: { selfAssignableRoles: [`candidate-${attempt}`] } },
      },
      user: oldAuthor,
      context: { deviceId: alice.device.deviceId },
      keys: teamKeys,
    })
    const candidateIsBefore = candidate.head[0] < rotationHash
    if (candidateIsBefore === (oldActionOrder === 'before')) {
      oldActionGraph = candidate
      break
    }
  }
  if (oldActionGraph === undefined) throw new Error('Could not generate the requested hash order')

  return {
    graph: merge(rotationGraph, oldActionGraph) as TeamGraph,
    rotationGraph,
    oldAuthor,
    newKeys,
    teamKeys,
    localContext: alice.localContext,
  }
}
