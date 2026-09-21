import { createKeyset, merge, redactKeys, type KeyScope } from '@localfirst/crdx'
import * as lockbox from 'lockbox/index.js'
import { pack, unpack } from 'msgpackr'
import { ADMIN } from 'role/index.js'
import { createServer, redactServer } from 'server/index.js'
import * as teams from 'team/index.js'
import { serializeTeamGraph } from 'team/serialize.js'
import type { TeamAction, TeamState } from 'team/types.js'
import { KeyType } from 'util/index.js'
import { setup, type UserStuff } from 'util/testing/index.js'
import { describe, expect, it, vi } from 'vitest'
import { forge } from './forgeHelpers.js'

const CHANNEL = 'private-channel'

const fixture = () => {
  const users = setup('alice', { user: 'bob', admin: false }, 'charlie')
  const { alice, bob } = users
  alice.team.addRole(CHANNEL)
  alice.team.addMemberRole(alice.userId, CHANNEL)
  alice.team.addMemberRole(bob.userId, CHANNEL)
  const server = createServer({ host: 'relay.example', seed: 'removal-gate-relay' })
  alice.team.addServer(redactServer(server))
  for (const peer of Object.values(users)) peer.team.merge(alice.team.graph)
  return { alice, bob, charlie: users.charlie, server }
}

type Fixture = ReturnType<typeof fixture>
type Operation = { peer: UserStuff; run: () => void; legacyAction?: () => TeamAction }

const keyChangeOperation = (peer: UserStuff, scope: KeyScope): Operation => ({
  peer,
  run: () => peer.team.changeKeys(createKeyset(scope)),
  legacyAction() {
    const keys = createKeyset(scope)
    keys.generation = 1
    // Protocol 3's key-change producer; the protocol 4 API refuses before changing a keyset.
    // @ts-expect-error Exercise the old lockbox producer without publishing its result.
    const lockboxes = peer.team.rotateKeys(keys)
    return {
      type: scope.type === KeyType.SERVER ? 'CHANGE_SERVER_KEYS' : 'CHANGE_MEMBER_KEYS',
      payload: { keys: redactKeys(keys), lockboxes },
    }
  },
})

const operations: Record<string, (f: Fixture) => Operation> = {
  REMOVE_MEMBER: ({ alice, bob }) => ({ peer: alice, run: () => alice.team.remove(bob.userId) }),
  REMOVE_MEMBER_ROLE: ({ alice, bob }) => ({
    peer: alice,
    run: () => alice.team.removeMemberRole(bob.userId, CHANNEL),
  }),
  REMOVE_ROLE: ({ alice }) => ({ peer: alice, run: () => alice.team.removeRole(CHANNEL) }),
  REMOVE_DEVICE: ({ bob }) => ({ peer: bob, run: () => bob.team.removeDevice(bob.deviceId) }),
  REMOVE_SERVER: ({ alice, server }) => ({
    peer: alice,
    run: () => alice.team.removeServer(server.serverId),
  }),
  CHANGE_MEMBER_KEYS: ({ bob }) =>
    keyChangeOperation(bob, { type: KeyType.USER, name: bob.userId }),
  CHANGE_SERVER_KEYS: ({ alice, server }) =>
    keyChangeOperation(alice, { type: KeyType.SERVER, name: server.serverId }),
  ROTATE_KEYS: ({ alice, bob }) => ({
    peer: alice,
    run() {
      // The exact payload an unpatched admin emits for a deferred rotation.
      // @ts-expect-error Exercise the existing producer without publishing its result.
      const lockboxes = alice.team.rotateKeys({ type: KeyType.USER, name: alice.userId })
      alice.team.dispatch({ type: 'ROTATE_KEYS', payload: { userId: bob.userId, lockboxes } })
    },
  }),
}

/** Capture a legacy producer's payload before it can alter local state, then sign it via CRDX.
 * This models a modified peer without an off-switch in the production protocol gate. */
const modifiedPeerGraph = ({ peer, run, legacyAction }: Operation) => {
  let action = legacyAction?.()
  if (action === undefined) {
    const captured = new Error('captured modified-peer action')
    const dispatch = vi.spyOn(peer.team, 'dispatch').mockImplementation(nextAction => {
      action = nextAction
      throw captured
    })
    try {
      expect(run).toThrow(captured)
    } finally {
      dispatch.mockRestore()
    }
  }
  expect(action).toBeDefined()
  return forge({
    graph: peer.team.graph,
    action: action!,
    signer: peer.signer,
    teamKeys: peer.team.teamKeys(),
  })
}

const withoutHead = ({ head: _head, ...state }: TeamState) => unpack(pack(state))

describe('removal and rotation are disabled on the Quiet protocol', () => {
  it.each(Object.entries(operations))(
    'refuses to emit %s without changing state or graph',
    (_type, operation) => {
      const f = fixture()
      const { peer, run } = operation(f)
      const state = unpack(pack(peer.team.state))
      const graph = peer.team.save()
      const keys = unpack(pack(peer.user.keys))

      expect(run).toThrow(/removal and key rotation are disabled/i)
      expect(unpack(pack(peer.team.state))).toEqual(state)
      expect(peer.team.save()).toEqual(graph)
      expect(peer.user.keys).toEqual(keys)
    }
  )

  it.each(Object.entries(operations))(
    'ignores a signed modified-peer %s on merge and both load paths',
    (_type, operation) => {
      const f = fixture()
      const graph = modifiedPeerGraph(operation(f))
      const { charlie } = f
      const state = withoutHead(charlie.team.state)
      const keyring = charlie.team.teamKeyring()

      charlie.team.merge(graph)
      expect(withoutHead(charlie.team.state)).toEqual(state)
      expect(charlie.team.graph.head).toEqual(graph.head)
      expect(charlie.team.teamKeys().generation).toBe(0)
      expect(charlie.team.roleKeys(CHANNEL).generation).toBe(0)

      for (const source of [graph, serializeTeamGraph(graph)]) {
        const loaded = teams.load(source, charlie.localContext, keyring)
        expect(withoutHead(loaded.state)).toEqual(state)
      }
      // Accepted inert history remains loadable using only the original keys.
      expect(
        withoutHead(teams.load(charlie.team.save(), charlie.localContext, keyring).state)
      ).toEqual(state)
    }
  )

  it.each(['REMOVE_MEMBER', 'REMOVE_DEVICE', 'REMOVE_MEMBER_ROLE'])(
    '%s cannot censor the target or a concurrent role grant',
    type => {
      const f = fixture()
      const { alice, bob, charlie } = f
      const removal = modifiedPeerGraph(
        type === 'REMOVE_MEMBER_ROLE'
          ? { peer: alice, run: () => alice.team.removeMemberRole(charlie.userId, ADMIN) }
          : type === 'REMOVE_DEVICE'
            ? { peer: alice, run: () => alice.team.removeDevice(charlie.deviceId) }
            : { peer: alice, run: () => alice.team.remove(charlie.userId) }
      )
      charlie.team.addRole('concurrent-channel')
      charlie.team.addMemberRole(bob.userId, 'concurrent-channel')
      const concurrent = charlie.team.graph
      const keyring = alice.team.teamKeyring()

      const replicas = [
        teams.load(alice.team.save(), alice.localContext, keyring),
        teams.load(alice.team.save(), alice.localContext, keyring),
      ]
      replicas[0].merge(removal).merge(concurrent)
      replicas[1].merge(concurrent).merge(removal)
      expect(replicas[0].state).toEqual(replicas[1].state)
      for (const replica of replicas) {
        expect(replica.memberIsAdmin(charlie.userId)).toBe(true)
        expect(replica.hasDevice(charlie.deviceId)).toBe(true)
        expect(replica.memberHasRole(bob.userId, 'concurrent-channel')).toBe(true)
        expect(replica.state.pendingKeyRotations).toEqual([])
      }
      const loaded = teams.load(
        serializeTeamGraph(merge(removal, concurrent)),
        alice.localContext,
        keyring
      )
      expect(loaded.memberHasRole(bob.userId, 'concurrent-channel')).toBe(true)
    }
  )

  it('does not publish deferred rotations even when invalid admission cleanup requests one', () => {
    const { alice, bob } = fixture()
    // The invalid-link reducer can request rotations independently of REMOVE_* actions.
    alice.team.state.pendingKeyRotations.push(bob.userId)
    const before = alice.team.save()
    expect(() => alice.team.emit('updated', { head: alice.team.graph.head })).not.toThrow()
    expect(alice.team.save()).toEqual(before)
    expect(alice.team.teamKeys().generation).toBe(0)
  })

  it('does not mutate a supplied keyset that aliases the caller’s current keys', () => {
    const { bob } = fixture()
    const keys = unpack(pack(bob.user.keys))
    expect(() => bob.team.changeKeys(bob.user.keys)).toThrow(/disabled/i)
    expect(bob.user.keys).toEqual(keys)
  })

  it('rejects a descendant encrypted under an ignored rotation atomically, then accepts ordinary updates', () => {
    const f = fixture()
    const { alice, charlie } = f
    const rotate = operations.ROTATE_KEYS
    const rotation = modifiedPeerGraph(rotate(f))
    const action = rotation.links[rotation.head[0]].body
    expect(action.type).toBe('ROTATE_KEYS')
    if (action.type !== 'ROTATE_KEYS') throw new Error('expected rotation')
    const box = action.payload.lockboxes.find(
      box => box.contents.type === KeyType.TEAM && box.recipient.name === charlie.userId
    )!
    // Recover the modified writer's next TEAM generation as an old peer would. The honest
    // receiver is never given this key and must not learn it from the disabled action.
    const rotatedKeys = lockbox.open(box, charlie.user.keys)
    expect(rotatedKeys.generation).toBe(1)
    const descendant = forge({
      graph: rotation,
      action: { type: 'SET_TEAM_NAME', payload: { teamName: 'only readable after rotating' } },
      signer: alice.signer,
      teamKeys: rotatedKeys,
    })
    const before = charlie.team.save()
    const state = unpack(pack(charlie.team.state))
    expect(() => charlie.team.merge(descendant)).toThrow()
    expect(charlie.team.save()).toEqual(before)
    expect(unpack(pack(charlie.team.state))).toEqual(state)
    expect(Object.values(charlie.team.teamKeyring()).map(key => key.generation)).toEqual([0])
    expect(() =>
      teams.load(serializeTeamGraph(descendant), charlie.localContext, charlie.team.teamKeyring())
    ).toThrow()

    alice.team.setTeamName('still usable')
    charlie.team.merge(alice.team.graph)
    expect(charlie.team.teamName).toBe('still usable')
    expect(
      teams.load(charlie.team.save(), charlie.localContext, charlie.team.teamKeyring()).teamName
    ).toBe('still usable')
  })

  it('retains invitations, additions, private encryption and the admin channel-delete predicate', () => {
    const { alice, bob, charlie } = fixture()
    expect(alice.team.memberCanRemoveMembersFromRole(CHANNEL, alice.userId)).toBe(false)
    expect(alice.team.memberCanRemoveMembersFromRole(CHANNEL, bob.userId)).toBe(false)
    expect(alice.team.memberCanDeleteRole(CHANNEL, alice.userId)).toBe(true)
    expect(alice.team.memberCanDeleteRole(CHANNEL, bob.userId)).toBe(false)
    expect(() => alice.team.removeRole(CHANNEL)).toThrow(/removal and key rotation are disabled/i)

    const { id } = alice.team.inviteMember()
    expect(alice.team.getInvitation(id).revoked).not.toBe(true)
    alice.team.addMemberRole(charlie.userId, CHANNEL)
    charlie.team.merge(alice.team.graph)
    expect(charlie.team.decrypt(alice.team.encrypt('private message', CHANNEL))).toBe(
      'private message'
    )
    expect(charlie.team.memberCanDeleteRole(CHANNEL, charlie.userId)).toBe(true)
  })
})
