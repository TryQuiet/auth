import {
  append,
  createKeyring,
  createKeyset,
  getChildMap,
  merge,
  redactKeys,
  validate,
} from '@localfirst/crdx'
import { symmetric } from '@localfirst/crypto'
import * as lockbox from 'lockbox/index.js'
import * as teams from 'team/index.js'
import { serializeTeamGraph } from 'team/serialize.js'
import { visibleScopes } from 'team/selectors/visibleScopes.js'
import { keyMap } from 'team/selectors/keyMap.js'
import type { TeamAction, TeamState } from 'team/types.js'
import { KeyType } from 'util/index.js'
import { setup } from 'util/testing/index.js'
import { describe, expect, it } from 'vitest'
import {
  buildEncryptedLink,
  expectRejectedEverywhere,
  forge,
  linkBody,
  withInjectedLink,
} from './forgeHelpers.js'

const CHANNEL = 'security-poc-channel'

describe('security candidate PoCs: team and lockbox state', () => {
  it('does not let a phantom role holder rotate a role after copying its public commitment', () => {
    const { alice, eve } = setup('alice', { user: 'eve', admin: false })
    alice.team.addRole(CHANNEL)

    const teamKeys = alice.team.teamKeys()
    eve.team = teams.load(
      serializeTeamGraph(alice.team.graph),
      eve.localContext,
      createKeyring(teamKeys)
    )

    const legitimate = alice.team.state.lockboxes.find(
      ({ contents }) =>
        contents.type === KeyType.ROLE && contents.name === CHANNEL && contents.generation === 0
    )
    expect(legitimate).toBeDefined()

    // Eve cannot open the copied box: the ciphertext contains Eve's keyset, while the public
    // manifest advertises the established role commitment.
    const phantomKeys = createKeyset({ type: KeyType.ROLE, name: CHANNEL }, 'phantom-role-keys')
    const copied = lockbox.create(phantomKeys, eve.user.keys)
    copied.contents = { ...legitimate!.contents }
    expect(() => lockbox.open(copied, eve.user.keys)).toThrow()

    const poisonedGraph = append({
      graph: eve.team.graph,
      action: {
        type: 'ADD_LOCKBOXES',
        payload: { lockboxes: [copied] },
      } as TeamAction,
      signer: eve.signer,
      keys: teamKeys,
    })

    // Authorization reads the recipient manifest and the copied commitment, not whether Eve can
    // decrypt the ciphertext, so the phantom holder enters the current holder set.
    alice.team.merge(poisonedGraph)
    eve.team.merge(poisonedGraph)
    expect(
      eve.team.state.lockboxes.some(
        ({ contents }) => contents.commitment === copied.contents.commitment
      )
    ).toBe(true)
    expect(() => eve.team.roleKeys(CHANNEL)).toThrow()

    const attackerRoleKeys = createKeyset(
      { type: KeyType.ROLE, name: CHANNEL },
      'attacker-controls-next-role-key'
    )
    attackerRoleKeys.generation = 1
    const rotationLockboxes = alice.team.state.lockboxes
      .filter(
        ({ contents }) =>
          contents.type === KeyType.ROLE && contents.name === CHANNEL && contents.generation === 0
      )
      .map(({ recipient }) => lockbox.create(attackerRoleKeys, recipient))

    const rotation = append({
      graph: eve.team.graph,
      action: {
        type: 'ADD_LOCKBOXES',
        payload: { lockboxes: rotationLockboxes },
      } as TeamAction,
      signer: eve.signer,
      keys: teamKeys,
    })
    alice.team.merge(rotation)

    expect(alice.team.roleKeys(CHANNEL).generation).toBe(0)
    expect(alice.team.roleKeys(CHANNEL).secretKey).not.toBe(attackerRoleKeys.secretKey)
    const message = alice.team.encrypt('role traffic remains on the admin-established key', CHANNEL)
    expect(() => symmetric.decryptBytes(message.contents, attackerRoleKeys.secretKey)).toThrow()
  })

  it('does not deliver the replacement role key to the principal removed by the rotation', () => {
    const { alice, bob } = setup('alice', { user: 'bob', admin: false })
    alice.team.addRole(CHANNEL)
    alice.team.addMemberRole(bob.userId, CHANNEL)

    const beforeRemoval = serializeTeamGraph(alice.team.graph)
    bob.team = teams.load(beforeRemoval, bob.localContext, createKeyring(alice.team.teamKeys()))
    const oldRoleKeys = bob.team.roleKeys(CHANNEL)

    alice.team.removeMemberRole(bob.userId, CHANNEL)
    const removal = alice.team.graph.links[alice.team.graph.head[0]].body as TeamAction
    const leaked = removal.payload.lockboxes?.find(
      ({ contents, recipient }) =>
        contents.type === KeyType.ROLE &&
        contents.name === CHANNEL &&
        contents.generation === oldRoleKeys.generation + 1 &&
        recipient.type === KeyType.USER &&
        recipient.name === bob.userId
    )

    expect(leaked).toBeUndefined()

    const futureMessage = alice.team.encrypt('removed principal cannot read this', CHANNEL)
    expect(() => symmetric.decryptBytes(futureMessage.contents, oldRoleKeys.secretKey)).toThrow()
  })

  it('keeps a malformed rotation on the retired generic delivery channel inert', () => {
    const { alice, charlie } = setup('alice', { user: 'charlie', admin: false })
    alice.team.addRole(CHANNEL)
    alice.team.addMemberRole(charlie.userId, CHANNEL)

    const base = serializeTeamGraph(alice.team.graph)
    const teamKeys = createKeyring(alice.team.teamKeys())
    charlie.team = teams.load(base, charlie.localContext, teamKeys)

    const nextRoleKeys = createKeyset({ type: KeyType.ROLE, name: CHANNEL }, 'split-rotation')
    nextRoleKeys.generation = 1
    const current = alice.team.state.lockboxes.filter(
      ({ contents }) =>
        contents.type === KeyType.ROLE && contents.name === CHANNEL && contents.generation === 0
    )
    const rotationLockboxes = current.map(({ recipient }) =>
      lockbox.create(nextRoleKeys, recipient)
    )
    const charlieBox = rotationLockboxes.find(box => box.recipient.name === charlie.userId)
    expect(charlieBox).toBeDefined()

    // The public manifests and commitment still agree, but this recipient cannot open its box.
    charlieBox!.encryptedPayload = Uint8Array.of(1, 2, 3)
    expect(() => lockbox.open(charlieBox!, charlie.user.keys)).toThrow()

    const rotation = append({
      graph: alice.team.graph,
      action: {
        type: 'ADD_LOCKBOXES',
        payload: { lockboxes: rotationLockboxes },
      } as TeamAction,
      signer: alice.signer,
      keys: alice.team.teamKeys(),
    })
    alice.team.merge(rotation)
    charlie.team.merge(rotation)

    // A retired generic link is not a carrier action, so it cannot establish a rotation from
    // metadata that appears otherwise committed.
    expect(alice.team.roleKeys(CHANNEL).generation).toBe(0)
    expect(charlie.team.roleKeys(CHANNEL).generation).toBe(0)
    expect(
      alice.team.state.lockboxes.some(
        ({ contents }) => contents.commitment === nextRoleKeys.commitment
      )
    ).toBe(false)
  })

  it('does not deliver replacement USER or TEAM keys to a fully removed member', () => {
    const { alice, bob } = setup('alice', { user: 'bob', admin: false })
    const beforeRemoval = serializeTeamGraph(alice.team.graph)
    bob.team = teams.load(beforeRemoval, bob.localContext, createKeyring(alice.team.teamKeys()))
    const oldTeamKeys = bob.team.teamKeys()
    alice.team.remove(bob.userId)
    const removal = alice.team.graph.links[alice.team.graph.head[0]].body as TeamAction
    const replacementUserBox = removal.payload.lockboxes?.find(
      ({ contents }) =>
        contents.type === KeyType.USER &&
        contents.name === bob.userId &&
        contents.generation === oldTeamKeys.generation + 1
    )

    expect(replacementUserBox).toBeUndefined()

    const futureMessage = alice.team.encrypt('removed member cannot read team traffic')
    expect(() => symmetric.decryptBytes(futureMessage.contents, oldTeamKeys.secretKey)).toThrow()
  })

  it('can leave the target of a losing concurrent member removal with the winning team key', () => {
    const { alice, bob, dave, charlie } = setup(
      'alice',
      { user: 'bob', admin: false },
      { user: 'dave', admin: true },
      { user: 'charlie', admin: false }
    )
    const base = serializeTeamGraph(alice.team.graph)
    const baseKeys = createKeyring(alice.team.teamKeys())
    dave.team = teams.load(base, dave.localContext, baseKeys)

    // These are valid concurrent admin actions. Each action independently rotates TEAM generation
    // 0 to generation 1, so only one lockbox batch can establish the generation.
    alice.team.remove(bob.userId)
    dave.team.remove(charlie.userId)

    const merged = merge(alice.team.graph, dave.team.graph)
    const loaded = teams.load(
      serializeTeamGraph(merged),
      alice.localContext,
      createKeyring(alice.team.teamKeyring())
    )
    const aliceAction = alice.team.graph.links[alice.team.graph.head[0]].body as TeamAction
    const daveAction = dave.team.graph.links[dave.team.graph.head[0]].body as TeamAction
    const actions = [aliceAction, daveAction]
    const winningAction = actions.find(action =>
      action.payload.lockboxes?.some(
        ({ contents }) =>
          contents.type === KeyType.TEAM &&
          contents.generation === loaded.teamKeys().generation &&
          contents.publicKey === loaded.teamKeys().encryption.publicKey
      )
    )
    const losingAction = actions.find(action => action !== winningAction)
    expect(winningAction).toBeDefined()
    expect(losingAction).toBeDefined()

    const removedByLosingAction = losingAction.payload.userId
    const loser = removedByLosingAction === bob.userId ? bob : charlie
    const winningTeamBoxForLoser = winningAction!.payload.lockboxes?.find(
      ({ contents, recipient }) =>
        contents.type === KeyType.TEAM &&
        contents.generation === loaded.teamKeys().generation &&
        recipient.type === KeyType.USER &&
        recipient.name === removedByLosingAction
    )

    expect(loaded.has(removedByLosingAction)).toBe(false)
    expect(winningTeamBoxForLoser).toBeDefined()
    const currentTeamKeys = lockbox.open(winningTeamBoxForLoser, loser.user.keys)
    expect(currentTeamKeys.secretKey).toBe(loaded.teamKeys().secretKey)

    const futureMessage = loaded.encrypt('removed member still has current team access')
    expect(symmetric.decryptBytes(futureMessage.contents, currentTeamKeys.secretKey)).toBe(
      'removed member still has current team access'
    )
  })

  it('rejects an admin-authored cross-user key replacement on live merge and cold load', () => {
    const { alice, bob } = setup('alice', 'bob')
    const teamKeys = alice.team.teamKeys()
    const replacement = createKeyset(
      { type: KeyType.USER, name: bob.userId },
      'alice-rotates-bob'
    )
    replacement.generation = bob.team.members(bob.userId).keys.generation + 1

    // Build the exact graph a modified administrator would publish, bypassing the public API's
    // local dispatch validation. Remote replicas and serialized cold load must independently
    // reject it at the replicated authorization boundary.
    // @ts-expect-error Exercise the attacker's ability to reproduce the exported rotation data.
    const lockboxes = alice.team.rotateKeys(replacement)
    const attack = forge({
      graph: alice.team.graph,
      action: {
        type: 'CHANGE_MEMBER_KEYS',
        payload: { keys: redactKeys(replacement), lockboxes },
      },
      signer: alice.signer,
      teamKeys,
    })

    expectRejectedEverywhere({
      forged: attack,
      teamKeys,
      peers: [alice, bob],
      message: /Can't change another user's keys/,
    })
  })

  it('can fail to recover a descendant written under a losing concurrent team rotation', () => {
    const { alice, bob } = setup('alice', 'bob')
    const base = serializeTeamGraph(alice.team.graph)
    const baseKeys = createKeyring(alice.team.teamKeys())
    bob.team = teams.load(base, bob.localContext, baseKeys)

    alice.team.changeKeys(
      createKeyset({ type: KeyType.USER, name: alice.userId }, 'alice-rotation')
    )
    bob.team.changeKeys(createKeyset({ type: KeyType.USER, name: bob.userId }, 'bob-rotation'))
    // This descendant is encrypted with Bob's independently generated generation-1 team key.
    bob.team.setTeamName('descendant on the other rotation branch')

    const merged = merge(alice.team.graph, bob.team.graph)
    expect(() =>
      teams.load(
        serializeTeamGraph(merged),
        alice.localContext,
        createKeyring(alice.team.teamKeyring())
      )
    ).toThrow()
    expect(() =>
      teams.load(
        serializeTeamGraph(merged),
        bob.localContext,
        createKeyring(bob.team.teamKeyring())
      )
    ).not.toThrow()
  })

  it('does not mutate Object.prototype when a visible keyset uses the __proto__ scope name', () => {
    const { alice } = setup('alice')
    const keyset = createKeyset({ type: KeyType.ROLE, name: '__proto__' }, 'prototype-pollution')
    const state = {
      ...alice.team.state,
      lockboxes: [lockbox.create(keyset, alice.user.keys)],
    } as TeamState
    const prototype = Object.prototype as Record<string, unknown>
    const previous = prototype[0]

    try {
      const keys = keyMap(state, alice.user.keys)
      expect(prototype[0]).toBe(previous)
      expect(Object.hasOwn(keys, KeyType.ROLE)).toBe(false)
    } finally {
      if (previous === undefined) delete prototype[0]
      else prototype[0] = previous
    }
  })

  it('does not mutate a shared built-in when a role uses an inherited property name', () => {
    const { alice } = setup('alice')
    const previous = Object.getOwnPropertyDescriptor(Object, '0')

    try {
      expect(() => alice.team.addRole('constructor')).toThrow(/Role name .* is reserved/)
      expect(alice.team.hasRole('constructor')).toBe(false)
      expect(Object.hasOwn(Object, '0')).toBe(false)
    } finally {
      if (previous === undefined) Reflect.deleteProperty(Object, '0')
      else Object.defineProperty(Object, '0', previous)
    }
  })

  it('accepts an inherited property name as a missing parent before child-map construction crashes', () => {
    const { alice, bob } = setup('alice', 'bob')
    const body = linkBody(
      alice.team.graph,
      { type: 'ADD_ROLE', payload: { roleName: 'prototype-parent-poc' } } as TeamAction,
      alice.signer.info
    )
    body.prev = ['__proto__']

    const poisonedGraph = withInjectedLink(
      alice.team.graph,
      buildEncryptedLink({
        body,
        teamKeys: alice.team.teamKeys(),
        senderKeys: alice.device.keys,
        signWith: alice.device.keys,
      })
    )

    // The graph validator mistakes Object.prototype for a link with this hash because it uses
    // `hash in graph.links` instead of checking for an own property.
    expect(validate(poisonedGraph)).toEqual({ isValid: true })

    // Normal merge/load paths derive a child map before team-level validation. The inherited
    // Object.prototype value is treated as the parent's child array and crashes the operation.
    expect(() => getChildMap(poisonedGraph)).toThrow(TypeError)
    expect(() => bob.team.merge(poisonedGraph)).toThrow(TypeError)
  })

  it('overflows the call stack on a deep acyclic lockbox scope chain', () => {
    const { alice } = setup('alice')
    const depth = 12_000
    const lockboxes = Array.from({ length: depth }, (_, index) => {
      const from = index === 0 ? 'root' : `scope-${index}`
      const to = `scope-${index + 1}`
      return {
        encryptionKey: { type: 'EPHEMERAL', name: 'EPHEMERAL', publicKey: 'unused' },
        recipient: { type: 'TEST', name: from, generation: 0, publicKey: 'unused' },
        contents: {
          type: 'TEST',
          name: to,
          generation: 0,
          publicKey: 'unused',
          version: 1,
          commitment: 'unused',
        },
        encryptedPayload: new Uint8Array(),
      }
    })
    const state = { ...alice.team.state, lockboxes } as unknown as TeamState

    expect(() => visibleScopes(state, { type: 'TEST', name: 'root' })).toThrow(RangeError)
  })
})
