import { append, createKeyring, createKeyset, merge } from '@localfirst/crdx'
import * as lockbox from 'lockbox/index.js'
import * as teams from 'team/index.js'
import { serializeTeamGraph } from 'team/serialize.js'
import type { TeamAction, TeamGraph } from 'team/types.js'
import { KeyType } from 'util/index.js'
import { setup } from 'util/testing/index.js'
import { describe, expect, it } from 'vitest'

const CHANNEL = 'committed-channel'

describe('complete-keyset manifest authorization', () => {
  it('permits redistribution only for the exact established keyset', () => {
    const { alice } = setup('alice')
    alice.team.addRole(CHANNEL)
    const established = alice.team.roleKeys(CHANNEL)
    const recipient = createKeyset({ type: 'TEST_RECIPIENT', name: 'reader' })
    const redistributed = lockbox.create(established, recipient)

    alice.team.dispatch({
      type: 'ADD_LOCKBOXES',
      payload: { lockboxes: [redistributed] },
    })

    expect(
      alice.team.state.lockboxes.some(
        ({ contents, recipient: manifest }) =>
          contents.commitment === redistributed.contents.commitment &&
          manifest.publicKey === recipient.encryption.publicKey
      )
    ).toBe(true)
    expect(lockbox.open(redistributed, recipient)).toEqual(established)
  })

  it('drops a conflicting historical-generation redistribution', () => {
    const { alice, bob } = setup('alice', { user: 'bob', admin: false })
    alice.team.addRole(CHANNEL)
    alice.team.addMemberRole(bob.userId, CHANNEL)
    const establishedGenerationZero = alice.team.roleKeys(CHANNEL, 0)

    alice.team.removeMemberRole(bob.userId, CHANNEL)
    expect(alice.team.roleKeys(CHANNEL).generation).toBe(1)

    const conflictingHistorical = createKeyset(
      { type: KeyType.ROLE, name: CHANNEL },
      'conflicting-history'
    )
    const forged = lockbox.create(conflictingHistorical, alice.team.members(alice.userId).keys)
    forged.contents.publicKey = establishedGenerationZero.encryption.publicKey

    expect(() =>
      alice.team.dispatch({
        type: 'ADD_LOCKBOXES',
        payload: { lockboxes: [forged] },
      })
    ).not.toThrow()

    expect(
      alice.team.state.lockboxes.some(
        ({ contents }) => contents.commitment === forged.contents.commitment
      )
    ).toBe(false)
    expect(alice.team.roleKeys(CHANNEL, 0).secretKey).toBe(establishedGenerationZero.secretKey)
  })

  it.each([
    ['first', 'second'],
    ['second', 'first'],
  ] as const)(
    'drops a divergent initial distribution in %s/%s recipient order',
    (first, second) => {
      const { alice, bob } = setup('alice', { user: 'bob', admin: false })
      const scope = { type: KeyType.ROLE, name: `${CHANNEL}-${first}` }
      const firstKeys = createKeyset(scope, 'first-initial-keyset')
      const secondKeys = createKeyset(scope, 'second-initial-keyset')
      const distributions = {
        first: lockbox.create(firstKeys, alice.team.members(alice.userId).keys),
        second: lockbox.create(secondKeys, bob.user.keys),
      }

      expect(() =>
        alice.team.dispatch({
          type: 'ADD_ROLE',
          payload: {
            roleName: scope.name,
            createdBy: alice.userId,
            lockboxes: [distributions[first], distributions[second]],
          },
        } as TeamAction)
      ).not.toThrow()

      // The surrounding role-creation link still applies, but neither conflicting distribution
      // gets to establish the role's generation-zero keyset.
      expect(alice.team.hasRole(scope.name)).toBe(true)
      expect(
        alice.team.state.lockboxes.filter(
          ({ contents }) => contents.type === scope.type && contents.name === scope.name
        )
      ).toHaveLength(0)
    }
  )

  it.each([
    ['first', 'second'],
    ['second', 'first'],
  ] as const)(
    'drops a divergent next-generation rotation in %s/%s recipient order',
    (first, second) => {
      const { alice, bob } = setup('alice', { user: 'bob', admin: false })
      alice.team.addRole(CHANNEL)
      alice.team.addMemberRole(bob.userId, CHANNEL)

      const firstKeys = createKeyset({ type: KeyType.ROLE, name: CHANNEL }, 'first-next-keyset')
      const secondKeys = createKeyset({ type: KeyType.ROLE, name: CHANNEL }, 'second-next-keyset')
      firstKeys.generation = 1
      secondKeys.generation = 1
      const distributions = {
        first: lockbox.create(firstKeys, alice.team.adminKeys()),
        second: lockbox.create(secondKeys, bob.user.keys),
      }
      // Make both manifests advertise the same encryption public key. Authorization must still
      // identify their different signature/symmetric material through the commitments.
      distributions.second.contents.publicKey = distributions.first.contents.publicKey

      expect(() =>
        alice.team.dispatch({
          type: 'ADD_LOCKBOXES',
          payload: { lockboxes: [distributions[first], distributions[second]] },
        })
      ).not.toThrow()

      expect(alice.team.roleKeys(CHANNEL).generation).toBe(0)
      expect(
        alice.team.state.lockboxes.filter(
          ({ contents }) =>
            contents.type === KeyType.ROLE && contents.name === CHANNEL && contents.generation === 1
        )
      ).toHaveLength(0)
    }
  )

  it('drops missing and malformed commitments without rejecting the link', () => {
    const { alice } = setup('alice')
    alice.team.addRole(CHANNEL)
    const established = alice.team.roleKeys(CHANNEL)
    const recipient = createKeyset({ type: 'TEST_RECIPIENT', name: 'reader' })
    const missing = lockbox.create(established, recipient)
    const malformed = lockbox.create(established, recipient)
    delete (missing.contents as Partial<lockbox.KeyManifest>).commitment
    Object.assign(malformed.contents, { commitment: 'not-base58' })
    const before = alice.team.state.lockboxes.length

    expect(() =>
      alice.team.dispatch({
        type: 'ADD_LOCKBOXES',
        payload: { lockboxes: [missing, malformed] },
      })
    ).not.toThrow()

    expect(alice.team.state.lockboxes).toHaveLength(before)
    expect(alice.team.roleKeys(CHANNEL).secretKey).toBe(established.secretKey)
  })

  it('keeps the established key under both append and merge orders', () => {
    const { alice, bob } = setup('alice', { user: 'bob', admin: false })
    alice.team.addRole(CHANNEL)
    const base = alice.team.graph
    const teamKeys = alice.team.teamKeys()
    const established = alice.team.roleKeys(CHANNEL)
    const recipient = createKeyset({ type: 'TEST_RECIPIENT', name: 'ordered-reader' })
    const exact = lockbox.create(established, recipient)
    const conflictingKeys = createKeyset({ type: KeyType.ROLE, name: CHANNEL }, 'ordered-conflict')
    const conflicting = lockbox.create(conflictingKeys, recipient)
    conflicting.contents.publicKey = exact.contents.publicKey

    const post = (graph: TeamGraph, box: lockbox.Lockbox, signer: typeof alice.signer) =>
      append({
        graph,
        action: {
          type: 'ADD_LOCKBOXES',
          payload: { lockboxes: [box] },
        } as TeamAction,
        signer,
        keys: teamKeys,
      })

    const exactBranch = post(base, exact, alice.signer)
    const conflictingBranch = post(base, conflicting, bob.signer)
    const orderedGraphs = [
      post(exactBranch, conflicting, bob.signer),
      post(conflictingBranch, exact, alice.signer),
      merge(exactBranch, conflictingBranch),
      merge(conflictingBranch, exactBranch),
    ]

    for (const graph of orderedGraphs) {
      const loaded = teams.load(
        serializeTeamGraph(graph),
        alice.localContext,
        createKeyring(teamKeys)
      )
      expect(loaded.roleKeys(CHANNEL).secretKey).toBe(established.secretKey)
      expect(
        loaded.state.lockboxes.some(
          ({ contents }) => contents.commitment === conflicting.contents.commitment
        )
      ).toBe(false)
      expect(
        loaded.state.lockboxes.some(
          ({ contents, recipient: manifest }) =>
            contents.commitment === exact.contents.commitment &&
            manifest.publicKey === recipient.encryption.publicKey
        )
      ).toBe(true)
    }
  })
})
