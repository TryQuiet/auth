import { append, createKeyring } from '@localfirst/crdx'
import * as teams from 'team/index.js'
import { serializeTeamGraph } from 'team/serialize.js'
import type { TeamAction } from 'team/types.js'
import { setup } from 'util/testing/index.js'
import { describe, expect, it } from 'vitest'

const CHANNEL = 'private-channel-role'

describe('lockbox rotation under honest concurrency (#63)', () => {
  // Protocol 4 disables removal/rotation; retained as a historical revocation specification.
  it.skip('does not poison the graph when a role add lands before a concurrent re-key', () => {
    const { alice, bob, charlie, dave } = setup(
      'alice',
      'bob',
      { user: 'charlie', admin: false },
      { user: 'dave', admin: false }
    )
    const teamKeys = alice.team.teamKeys()

    alice.team.addRole(CHANNEL)
    alice.team.addMemberRole(charlie.userId, CHANNEL)

    // Both admins are looking at the same state.
    const graph0 = serializeTeamGraph(alice.team.graph)
    bob.team = teams.load(graph0, bob.localContext, createKeyring(teamKeys))

    // 👨🏻‍🦲 Bob re-keys the channel (removing Charlie from it). His payload re-boxes generation 1 to
    // exactly the holders he can see: no Dave, because Dave isn't in the channel yet as far as he
    // knows.
    bob.team.removeMemberRole(charlie.userId, CHANNEL)
    const rotation = bob.team.graph.links[bob.team.graph.head[0]].body as TeamAction

    // 👩🏾 Concurrently, Alice adds 👨🏫 Dave to the channel, which boxes the *current* generation to him.
    alice.team.addMemberRole(dave.userId, CHANNEL)

    // The merge sequences Alice's add before Bob's re-key. Appending Bob's already-computed payload
    // on top of Alice's graph reproduces exactly the state the resolver hands the reducer in that
    // order (topoSort orders concurrent branches by hash, so which one lands first is a coin flip —
    // this pins the losing side).
    const merged = append({
      graph: alice.team.graph,
      action: { type: rotation.type, payload: rotation.payload } as TeamAction,
      signer: bob.signer,
      keys: teamKeys,
    })

    // Nothing dishonest happened here. If this throws, one honest merge has permanently bricked the
    // team's graph for everyone (#58: getTeamState throws on a link it can't reduce).
    expect(() =>
      teams.load(serializeTeamGraph(merged), alice.localContext, createKeyring(teamKeys))
    ).not.toThrow()
  })
})
