import { append, createKeyring, createKeyset, merge } from '@localfirst/crdx'
import * as lockbox from 'lockbox/index.js'
import { createServer, redactServer } from 'server/index.js'
import * as teams from 'team/index.js'
import { serializeTeamGraph } from 'team/serialize.js'
import type { TeamAction } from 'team/types.js'
import { KeyType } from 'util/index.js'
import { setup } from 'util/testing/index.js'
import { describe, expect, it } from 'vitest'
import { memberAdmission } from './helpers.js'

const CHANNEL = 'authorization-hardening-channel'

describe('lockbox authorization hardening', () => {
  it('requires every current holder recipient generation and public key during rotation', () => {
    const { alice, bob, charlie } = setup(
      'alice',
      { user: 'bob', admin: false },
      { user: 'charlie', admin: false }
    )
    alice.team.addRole(CHANNEL)
    alice.team.addMemberRole(bob.userId, CHANNEL)
    alice.team.addMemberRole(charlie.userId, CHANNEL)

    const teamKeys = alice.team.teamKeys()
    const current = alice.team.state.lockboxes.filter(
      ({ contents }) =>
        contents.type === KeyType.ROLE && contents.name === CHANNEL && contents.generation === 0
    )
    const nextKeys = createKeyset({ type: KeyType.ROLE, name: CHANNEL }, 'holder-substitution')
    nextKeys.generation = 1
    const attackerRecipient = createKeyset(
      { type: KeyType.USER, name: 'attacker-recipient' },
      'attacker-recipient'
    )

    const forged = current.map(previous => {
      if (previous.recipient.type !== KeyType.USER || previous.recipient.name !== charlie.userId) {
        return lockbox.create(nextKeys, previous.recipient)
      }

      const poisoned = lockbox.create(nextKeys, attackerRecipient)
      // The old scope-only holder check saw "USER:charlie" and accepted this. The generation and
      // encryption public key still identify the attacker's recipient keyset.
      poisoned.recipient.type = KeyType.USER
      poisoned.recipient.name = charlie.userId
      return poisoned
    })

    const attack = append({
      graph: alice.team.graph,
      action: { type: 'ADD_LOCKBOXES', payload: { lockboxes: forged } } as TeamAction,
      signer: bob.signer,
      keys: teamKeys,
    })

    const loaded = teams.load(
      serializeTeamGraph(attack),
      alice.localContext,
      createKeyring(teamKeys)
    )
    expect(loaded.roleKeys(CHANNEL).generation).toBe(0)
    expect(
      loaded.state.lockboxes.some(
        ({ contents }) => contents.commitment === forged[0].contents.commitment
      )
    ).toBe(false)
  })

  it('does not let an unrelated member pre-seed a future USER generation', () => {
    const { alice, bob } = setup('alice', { user: 'bob', admin: false })
    const nextKeys = createKeyset(
      { type: KeyType.USER, name: alice.userId },
      'legitimate-next-user-keys'
    )
    nextKeys.generation = 1
    const poisonedKeys = createKeyset(
      { type: KeyType.USER, name: alice.userId },
      'poisoned-next-user-keys'
    )
    poisonedKeys.generation = 1
    const poisoned = lockbox.create(poisonedKeys, bob.user.keys)
    // Even knowing the public encryption key Alice will advertise must not let Bob bind a
    // different complete keyset commitment before Alice's CHANGE_MEMBER_KEYS link.
    poisoned.contents.publicKey = nextKeys.encryption.publicKey

    const attack = append({
      graph: alice.team.graph,
      action: {
        type: 'ADD_LOCKBOXES',
        payload: { lockboxes: [poisoned] },
      } as TeamAction,
      signer: bob.signer,
      keys: alice.team.teamKeys(),
    })

    expect(() => alice.team.merge(attack)).not.toThrow()
    expect(
      alice.team.state.lockboxes.some(
        ({ contents }) => contents.commitment === poisoned.contents.commitment
      )
    ).toBe(false)

    alice.team.changeKeys(nextKeys)
    expect(alice.team.members(alice.userId).keys.generation).toBe(1)
    expect(alice.team.members(alice.userId).keys.encryption).toBe(nextKeys.encryption.publicKey)
    expect(alice.team.teamKeys().generation).toBe(1)
    expect(alice.team.adminKeys().generation).toBe(1)
  })

  it('selects the legitimate USER key change in both concurrent merge orders', () => {
    const { alice, bob } = setup('alice', { user: 'bob', admin: false })
    const base = alice.team.graph
    const nextKeys = createKeyset(
      { type: KeyType.USER, name: alice.userId },
      'concurrent-legitimate-user-keys'
    )
    nextKeys.generation = 1
    const poisonedKeys = createKeyset(
      { type: KeyType.USER, name: alice.userId },
      'concurrent-poisoned-user-keys'
    )
    poisonedKeys.generation = 1
    const poisoned = lockbox.create(poisonedKeys, bob.user.keys)
    poisoned.contents.publicKey = nextKeys.encryption.publicKey

    const attackBranch = append({
      graph: base,
      action: {
        type: 'ADD_LOCKBOXES',
        payload: { lockboxes: [poisoned] },
      } as TeamAction,
      signer: bob.signer,
      keys: alice.team.teamKeys(),
    })
    alice.team.changeKeys(nextKeys)
    const legitimateBranch = alice.team.graph
    const keyring = alice.team.teamKeyring()

    for (const graph of [
      merge(legitimateBranch, attackBranch),
      merge(attackBranch, legitimateBranch),
    ]) {
      const loaded = teams.load(serializeTeamGraph(graph), alice.localContext, keyring)
      expect(loaded.members(alice.userId).keys.encryption).toBe(nextKeys.encryption.publicKey)
      expect(loaded.teamKeys().generation).toBe(1)
      expect(
        loaded.state.lockboxes.some(
          ({ contents }) => contents.commitment === poisoned.contents.commitment
        )
      ).toBe(false)
    }
  })

  it('does not let an unrelated member pre-seed a future SERVER generation', () => {
    const { alice, bob } = setup('alice', { user: 'bob', admin: false })
    const serverWithSecrets = createServer({ host: 'sync.example', seed: 'registered-server' })
    alice.team.addServer(redactServer(serverWithSecrets))

    const nextKeys = createKeyset(
      { type: KeyType.SERVER, name: serverWithSecrets.serverId },
      'legitimate-next-server-keys'
    )
    nextKeys.generation = 1
    const poisonedKeys = createKeyset(
      { type: KeyType.SERVER, name: serverWithSecrets.serverId },
      'poisoned-next-server-keys'
    )
    poisonedKeys.generation = 1
    const poisoned = lockbox.create(poisonedKeys, bob.user.keys)
    poisoned.contents.publicKey = nextKeys.encryption.publicKey

    const attack = append({
      graph: alice.team.graph,
      action: {
        type: 'ADD_LOCKBOXES',
        payload: { lockboxes: [poisoned] },
      } as TeamAction,
      signer: bob.signer,
      keys: alice.team.teamKeys(),
    })

    expect(() => alice.team.merge(attack)).not.toThrow()
    expect(
      alice.team.state.lockboxes.some(
        ({ contents }) => contents.commitment === poisoned.contents.commitment
      )
    ).toBe(false)

    alice.team.changeKeys(nextKeys)
    expect(alice.team.servers(serverWithSecrets.serverId).keys.generation).toBe(1)
    expect(alice.team.servers(serverWithSecrets.serverId).keys.encryption).toBe(
      nextKeys.encryption.publicKey
    )
    expect(alice.team.teamKeys().generation).toBe(1)
  })

  it('does not let an ADMIT_MEMBER link pre-poison the USER commitment before join', () => {
    const { alice, bob } = setup('alice', { user: 'bob', member: false })
    const { seed } = alice.team.inviteMember()
    const [proof, claim, possessionProof] = memberAdmission(seed, bob)
    const poisonedKeys = createKeyset(
      { type: KeyType.USER, name: bob.userId },
      'admission-pre-poison'
    )
    const poisoned = lockbox.create(poisonedKeys, claim.device.keys)
    poisoned.contents.publicKey = claim.memberKeys.encryption
    const teamForBob = lockbox.create(alice.team.teamKeys(), claim.memberKeys)

    expect(() =>
      alice.team.dispatch({
        type: 'ADMIT_MEMBER',
        payload: {
          id: proof.id,
          proof,
          claim,
          possessionProof,
          lockboxes: [teamForBob, poisoned],
        },
      })
    ).not.toThrow()
    expect(alice.team.has(bob.userId)).toBe(true)
    expect(
      alice.team.state.lockboxes.some(
        ({ contents }) => contents.commitment === poisoned.contents.commitment
      )
    ).toBe(false)

    const keyring = alice.team.teamKeyring()
    bob.team = teams.load(alice.team.save(), bob.localContext, keyring)
    bob.team.join(keyring)
    expect(() => alice.team.merge(bob.team.graph)).not.toThrow()
    expect(
      alice.team.state.lockboxes.some(
        ({ contents, recipient }) =>
          contents.type === KeyType.USER &&
          contents.name === bob.userId &&
          recipient.publicKey === bob.device.keys.encryption.publicKey
      )
    ).toBe(true)
  })

  it('preserves an authenticated ROTATE_KEYS recipient transition', () => {
    const { alice } = setup('alice')

    // This is the same action `checkForPendingKeyRotations` emits after a resolver marks a
    // compromised identity for deferred rotation.
    // @ts-expect-error exercising the private rotation helper at its reducer boundary
    const lockboxes = alice.team.rotateKeys({ type: KeyType.USER, name: alice.userId })
    expect(() =>
      alice.team.dispatch({
        type: 'ROTATE_KEYS',
        payload: { userId: 'resolved-conflict', lockboxes },
      })
    ).not.toThrow()

    expect(alice.team.teamKeys().generation).toBe(1)
    expect(alice.team.adminKeys().generation).toBe(1)
  })

  it('drops an unidentifiable malformed sibling instead of partially establishing a batch', () => {
    const { alice } = setup('alice')
    const roleName = `${CHANNEL}-malformed-initial`
    const keys = createKeyset({ type: KeyType.ROLE, name: roleName }, 'malformed-initial')
    const valid = lockbox.create(keys, alice.team.adminKeys())

    expect(() =>
      alice.team.dispatch({
        type: 'ADD_ROLE',
        payload: {
          roleName,
          createdBy: alice.userId,
          lockboxes: [valid, null],
        },
      } as unknown as TeamAction)
    ).not.toThrow()

    expect(alice.team.hasRole(roleName)).toBe(true)
    expect(
      alice.team.state.lockboxes.filter(
        ({ contents }) => contents.type === KeyType.ROLE && contents.name === roleName
      )
    ).toHaveLength(0)
  })

  it('does not partially establish a batch when a malformed sibling lacks identity coordinates', () => {
    const { alice } = setup('alice')
    const roleName = `${CHANNEL}-missing-coordinates`
    const keys = createKeyset({ type: KeyType.ROLE, name: roleName }, 'missing-coordinates')
    const valid = lockbox.create(keys, alice.team.adminKeys())
    const malformed = {
      ...valid,
      contents: { ...valid.contents },
    }
    delete (malformed.contents as Partial<lockbox.KeyManifest>).generation

    expect(() =>
      alice.team.dispatch({
        type: 'ADD_ROLE',
        payload: {
          roleName,
          createdBy: alice.userId,
          lockboxes: [valid, malformed],
        },
      } as unknown as TeamAction)
    ).not.toThrow()

    expect(alice.team.hasRole(roleName)).toBe(true)
    expect(
      alice.team.state.lockboxes.filter(
        ({ contents }) => contents.type === KeyType.ROLE && contents.name === roleName
      )
    ).toHaveLength(0)
  })

  it('drops a whole rotation batch when a sibling has a malformed recipient', () => {
    const { alice, bob } = setup('alice', { user: 'bob', admin: false })
    alice.team.addRole(CHANNEL)
    alice.team.addMemberRole(bob.userId, CHANNEL)
    const current = alice.team.state.lockboxes.filter(
      ({ contents }) =>
        contents.type === KeyType.ROLE && contents.name === CHANNEL && contents.generation === 0
    )
    const nextKeys = createKeyset({ type: KeyType.ROLE, name: CHANNEL }, 'malformed-rotation')
    nextKeys.generation = 1
    const next = current.map(({ recipient }) => lockbox.create(nextKeys, recipient))
    const malformed = { ...next.pop(), recipient: null }

    expect(() =>
      alice.team.dispatch({
        type: 'ADD_LOCKBOXES',
        payload: { lockboxes: [...next, malformed] },
      } as unknown as TeamAction)
    ).not.toThrow()

    expect(alice.team.roleKeys(CHANNEL).generation).toBe(0)
    expect(
      alice.team.state.lockboxes.filter(
        ({ contents }) =>
          contents.type === KeyType.ROLE && contents.name === CHANNEL && contents.generation === 1
      )
    ).toHaveLength(0)
  })

  it('drops a non-array lockbox payload while still applying the surrounding link', () => {
    const { alice } = setup('alice')

    expect(() =>
      alice.team.dispatch({
        type: 'SET_TEAM_NAME',
        payload: { teamName: 'still-reduced', lockboxes: { malformed: true } },
      } as unknown as TeamAction)
    ).not.toThrow()

    expect(alice.team.teamName).toBe('still-reduced')
  })
})
