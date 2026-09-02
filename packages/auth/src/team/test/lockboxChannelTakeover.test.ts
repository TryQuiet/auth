import { append, createKeyring, createKeyset } from '@localfirst/crdx'
import * as lockbox from 'lockbox/index.js'
import * as teams from 'team/index.js'
import { serializeTeamGraph } from 'team/serialize.js'
import type { TeamAction } from 'team/types.js'
import { KeyType } from 'util/index.js'
import { setup, type UserStuff } from 'util/testing/index.js'
import { describe, expect, it } from 'vitest'

/**
 * A Quiet "private channel" is an @localfirst/auth ROLE: its messages are symmetrically encrypted
 * with the role's key, which reaches members in lockboxes on the graph. Reading the channel means
 * holding that key.
 *
 * This is the HONEST-authorship sibling of forgedChannelTakeover.test.ts. There, Eve had to forge a
 * link as an admin — which device-signed links now stop. Here she forges nothing: she
 * signs as *herself*, using ADD_LOCKBOXES, an action every member may author, and simply hangs
 * channel-rekey lockboxes on its payload. The reducer swept in the lockboxes on any link's payload,
 * and `getLatestGeneration` / `select.keys` then adopted the highest generation present — so a
 * non-admin who is not even in the channel could mint a generation-1 channel keyset, hand it out to
 * a subset that leaves out the victim, and have honest clients silently encrypt future channel
 * traffic under the key she controls: effective removal of the victim plus takeover (#61).
 *
 * The fix (`lockboxAuthorization.ts`) *drops* those lockboxes instead of adopting them, and — unlike
 * a throwing validator — leaves the link itself alone. So the assertions here are that the attack
 * has no effect and the team keeps working, not that the graph blows up. See
 * `lockboxRotationConcurrency.test.ts` for why the difference matters.
 */
const CHANNEL = 'private-channel-role'

const ATTACK_SCOPES = [
  { label: 'team', type: KeyType.TEAM, name: KeyType.TEAM },
  { label: 'private-channel', type: KeyType.ROLE, name: CHANNEL },
] as const

/** A link the attacker signs honestly as herself, carrying lockboxes for a key she minted. */
const rideLockboxesOnHonestLink = (attacker: UserStuff, lockboxes: lockbox.Lockbox[]) =>
  append({
    graph: attacker.team.graph,
    action: { type: 'ADD_LOCKBOXES', payload: { lockboxes } } as TeamAction,
    signer: attacker.signer, // no lie — she signs with her own device
    keys: attacker.team.teamKeys(),
  })

const setupSharedScopes = () => {
  const users = setup('alice', { user: 'bob', admin: false }, { user: 'charlie', admin: false })
  users.alice.team.addRole(CHANNEL)
  users.alice.team.addMemberRole(users.bob.userId, CHANNEL)
  users.alice.team.addMemberRole(users.charlie.userId, CHANNEL)
  return users
}

const recipientsAtGenerationZero = (alice: UserStuff, scope: (typeof ATTACK_SCOPES)[number]) =>
  alice.team.state.lockboxes
    .filter(
      ({ contents }) =>
        contents.type === scope.type && contents.name === scope.name && contents.generation === 0
    )
    .map(({ recipient }) => recipient)

const rotationRecipientsFor = (
  alice: UserStuff,
  removed: UserStuff,
  scope: (typeof ATTACK_SCOPES)[number]
) => {
  const current = recipientsAtGenerationZero(alice, scope)
  const removedRecipients = current.filter(
    recipient =>
      recipient.type === removed.user.keys.type &&
      recipient.name === removed.user.keys.name &&
      recipient.generation === removed.user.keys.generation &&
      recipient.publicKey === removed.user.keys.encryption.publicKey
  )
  const expected = current.filter(recipient => !removedRecipients.includes(recipient))

  // These are the preconditions for the exact-recipient tests. If the fixture stops making Bob a
  // holder, or stops having other holders, omission/extra-recipient cases must fail loudly rather
  // than pass because they accidentally supplied the right set.
  expect(removedRecipients).toHaveLength(1)
  expect(expected.length).toBeGreaterThan(1)
  expect(current).toHaveLength(expected.length + 1)

  return { expected, removed: removedRecipients[0] }
}

const dispatchDeclaredRotation = (
  alice: UserStuff,
  removed: UserStuff,
  scope: (typeof ATTACK_SCOPES)[number],
  lockboxes: lockbox.Lockbox[]
) => {
  if (scope.type === KeyType.TEAM) {
    alice.team.dispatch({
      type: 'REMOVE_MEMBER',
      payload: { userId: removed.userId, lockboxes },
    })
    return
  }

  alice.team.dispatch({
    type: 'REMOVE_MEMBER_ROLE',
    payload: { userId: removed.userId, roleName: scope.name, lockboxes },
  })
}

const expectDeclaredRemovalApplied = (
  alice: UserStuff,
  removed: UserStuff,
  scope: (typeof ATTACK_SCOPES)[number]
) => {
  if (scope.type === KeyType.TEAM) {
    expect(alice.team.has(removed.userId)).toBe(false)
  } else {
    expect(alice.team.memberHasRole(removed.userId, scope.name)).toBe(false)
  }
}

const generationFor = (alice: UserStuff, scope: (typeof ATTACK_SCOPES)[number]) =>
  scope.type === KeyType.TEAM
    ? alice.team.teamKeys().generation
    : alice.team.roleKeys(scope.name).generation

const expectNoGeneration = (
  alice: UserStuff,
  scope: (typeof ATTACK_SCOPES)[number],
  generation: number
) => {
  expect(generationFor(alice, scope)).toBe(0)
  expect(
    alice.team.state.lockboxes.filter(
      ({ contents }) =>
        contents.type === scope.type &&
        contents.name === scope.name &&
        contents.generation === generation
    )
  ).toHaveLength(0)
}

describe('honest lockbox private-channel takeover (#61)', () => {
  it('drops a re-key of a private channel by a member who is not in it', () => {
    const { alice, bob, eve } = setup('alice', 'bob', { user: 'eve', admin: false })
    const teamKeys = alice.team.teamKeys()

    // 👩🏾 Alice (admin) creates a private channel and admits 👨🏻‍🦲 Bob. 🦹‍♀️ Eve is NOT in it.
    alice.team.addRole(CHANNEL)
    alice.team.addMemberRole(bob.userId, CHANNEL)

    const graph0 = serializeTeamGraph(alice.team.graph)
    bob.team = teams.load(graph0, bob.localContext, createKeyring(teamKeys))
    eve.team = teams.load(graph0, eve.localContext, createKeyring(teamKeys))

    // Baseline (generation 0): Bob reads the channel; Eve, never admitted, cannot.
    const oldMessage = 'gen-0: legitimate channel members only'
    const oldEnvelope = alice.team.encrypt(oldMessage, CHANNEL)
    expect(bob.team.decrypt(oldEnvelope)).toEqual(oldMessage)
    expect(() => eve.team.decrypt(oldEnvelope)).toThrow()

    // 🦹‍♀️ Eve mints a generation-1 keyset she controls and ships it to herself and to Alice —
    // Alice being the honest client whose adoption of generation 1 is what makes the attack pay.
    const evilKeys = createKeyset({ type: KeyType.ROLE, name: CHANNEL }, 'eve-controls-this-key')
    evilKeys.generation = 1
    const attack = rideLockboxesOnHonestLink(eve, [
      lockbox.create(evilKeys, eve.team.members(eve.userId).keys),
      lockbox.create(evilKeys, eve.team.members(alice.userId).keys),
    ])

    // The link is honestly signed and the action is one Eve may take, so it merges — but her
    // lockboxes never reach state, and a cold load reaches the same state.
    expect(() => alice.team.merge(attack)).not.toThrow()
    expect(() => bob.team.merge(attack)).not.toThrow()
    expect(() =>
      teams.load(serializeTeamGraph(attack), alice.localContext, createKeyring(teamKeys))
    ).not.toThrow()

    // The channel stays on its legitimate generation: Bob still reads new traffic; Eve still can't.
    expect(alice.team.roleKeys(CHANNEL).generation).toBe(0)
    expect(bob.team.roleKeys(CHANNEL).generation).toBe(0)
    const newMessage = 'generation 0 remains private after the rejected re-key'
    const newEnvelope = alice.team.encrypt(newMessage, CHANNEL)
    expect(newEnvelope.recipient.generation).toBe(0)
    expect(bob.team.decrypt(newEnvelope)).toEqual(newMessage)
    expect(() => eve.team.decrypt(newEnvelope)).toThrow()
  })

  it('drops a complete channel re-key by a non-admin channel member', () => {
    const { alice, bob, charlie } = setup(
      'alice',
      { user: 'bob', admin: false },
      { user: 'charlie', admin: false }
    )
    const teamKeys = alice.team.teamKeys()

    alice.team.addRole(CHANNEL)
    alice.team.addMemberRole(bob.userId, CHANNEL)
    alice.team.addMemberRole(charlie.userId, CHANNEL)

    const graph0 = serializeTeamGraph(alice.team.graph)
    bob.team = teams.load(graph0, bob.localContext, createKeyring(teamKeys))
    charlie.team = teams.load(graph0, charlie.localContext, createKeyring(teamKeys))

    // 👨🏻‍🦲 Bob is a legitimate channel member and supplies the new generation to every current
    // recipient. The batch is otherwise a valid rotation, but holding the channel key does not give
    // a non-admin authority to replace it.
    const evilKeys = createKeyset({ type: KeyType.ROLE, name: CHANNEL }, 'bob-controls-this-key')
    evilKeys.generation = 1
    const currentRecipients = bob.team.state.lockboxes
      .filter(
        ({ contents }) =>
          contents.type === KeyType.ROLE && contents.name === CHANNEL && contents.generation === 0
      )
      .map(({ recipient }) => recipient)
    const attack = rideLockboxesOnHonestLink(
      bob,
      currentRecipients.map(recipient => lockbox.create(evilKeys, recipient))
    )

    expect(() => alice.team.merge(attack)).not.toThrow()
    expect(() => charlie.team.merge(attack)).not.toThrow()

    expect(alice.team.roleKeys(CHANNEL).generation).toBe(0)
    const newMessage = 'charlie is still in this channel'
    const newEnvelope = alice.team.encrypt(newMessage, CHANNEL)
    expect(charlie.team.decrypt(newEnvelope)).toEqual(newMessage)
  })

  it('drops a complete team re-key by a non-admin member', () => {
    const { alice, bob, charlie } = setup(
      'alice',
      { user: 'bob', admin: false },
      { user: 'charlie', admin: false }
    )
    const teamKeys = alice.team.teamKeys()

    const graph0 = serializeTeamGraph(alice.team.graph)
    charlie.team = teams.load(graph0, charlie.localContext, createKeyring(teamKeys))

    // Every member holds the team key. Bob reaches every current recipient with one committed
    // generation, so the only reason to reject this otherwise valid batch is that he is not admin.
    const evilKeys = createKeyset({ type: KeyType.TEAM, name: KeyType.TEAM }, 'bob-controls-this')
    evilKeys.generation = 1
    const currentRecipients = bob.team.state.lockboxes
      .filter(({ contents }) => contents.type === KeyType.TEAM && contents.generation === 0)
      .map(({ recipient }) => recipient)
    const attack = rideLockboxesOnHonestLink(
      bob,
      currentRecipients.map(recipient => lockbox.create(evilKeys, recipient))
    )

    expect(() => alice.team.merge(attack)).not.toThrow()
    expect(alice.team.teamKeys().generation).toBe(0)

    // Charlie can still read what the team writes after the attempt.
    charlie.team.merge(attack)
    const envelope = alice.team.encrypt('charlie is still on this team')
    expect(charlie.team.decrypt(envelope)).toEqual('charlie is still on this team')
  })

  for (const scope of ATTACK_SCOPES) {
    it(`drops an admin-signed ${scope.label} rotation that skips a generation`, () => {
      const { alice, bob } = setupSharedScopes()
      const { expected } = rotationRecipientsFor(alice, bob, scope)
      const skippedKeys = createKeyset(
        { type: scope.type, name: scope.name },
        `${scope.label}-generation-skip`
      )
      skippedKeys.generation = 2

      const lockboxes = expected.map(recipient => lockbox.create(skippedKeys, recipient))
      expect(lockboxes).toHaveLength(expected.length)

      // REMOVE_MEMBER and REMOVE_MEMBER_ROLE are declared rotation carriers. Every recipient is
      // correct, so this batch is rejected specifically because generation 2 skips generation 1.
      expect(() => dispatchDeclaredRotation(alice, bob, scope, lockboxes)).not.toThrow()
      expectDeclaredRemovalApplied(alice, bob, scope)
      expectNoGeneration(alice, scope, 2)
    })

    it(`drops an admin-signed ${scope.label} rotation that omits an authorized recipient`, () => {
      const { alice, bob } = setupSharedScopes()
      const { expected } = rotationRecipientsFor(alice, bob, scope)
      const nextKeys = createKeyset(
        { type: scope.type, name: scope.name },
        `${scope.label}-omitted-recipient`
      )
      nextKeys.generation = 1

      // The missing final delivery is the exclusion attack from #61: the advertised generation
      // must not become current merely because some of its legitimate holders received it.
      const lockboxes = expected.slice(0, -1).map(recipient => lockbox.create(nextKeys, recipient))
      expect(lockboxes).toHaveLength(expected.length - 1)

      expect(() => dispatchDeclaredRotation(alice, bob, scope, lockboxes)).not.toThrow()
      expectDeclaredRemovalApplied(alice, bob, scope)
      expectNoGeneration(alice, scope, 1)
    })

    it(`drops an admin-signed ${scope.label} rotation that retains the removed recipient`, () => {
      const { alice, bob } = setupSharedScopes()
      const { expected, removed } = rotationRecipientsFor(alice, bob, scope)
      const nextKeys = createKeyset(
        { type: scope.type, name: scope.name },
        `${scope.label}-unauthorized-recipient`
      )
      nextKeys.generation = 1

      // This is the revocation-defeat case from #61: the generation reaches every post-action
      // holder, but it also reaches Bob after the declared removal says he is no longer authorized.
      const lockboxes = [...expected, removed].map(recipient => lockbox.create(nextKeys, recipient))
      expect(lockboxes).toHaveLength(expected.length + 1)

      expect(() => dispatchDeclaredRotation(alice, bob, scope, lockboxes)).not.toThrow()
      expectDeclaredRemovalApplied(alice, bob, scope)
      expectNoGeneration(alice, scope, 1)
    })
  }

  it('still lets an admin rotate the team key when removing a member', () => {
    const { alice, bob, charlie } = setupSharedScopes()
    const teamKeys = alice.team.teamKeys()

    expect(() => alice.team.remove(bob.userId)).not.toThrow()
    expect(alice.team.has(bob.userId)).toBe(false)
    expect(alice.team.teamKeys().generation).toBe(1)

    const graph1 = serializeTeamGraph(alice.team.graph)
    charlie.team = teams.load(graph1, charlie.localContext, createKeyring(teamKeys))
    bob.team = teams.load(graph1, bob.localContext, createKeyring(teamKeys))

    const message = 'generation 1 reaches exactly the remaining team members'
    const envelope = alice.team.encrypt(message)
    expect(envelope.recipient.generation).toBe(1)
    expect(charlie.team.decrypt(envelope)).toEqual(message)
    expect(() => bob.team.decrypt(envelope)).toThrow()
  })

  it('still lets an admin rotate the channel key when removing a member from it', () => {
    const { alice, bob, charlie } = setup(
      'alice',
      { user: 'bob', admin: false },
      { user: 'charlie', admin: false }
    )
    const teamKeys = alice.team.teamKeys()
    alice.team.addRole(CHANNEL)
    alice.team.addMemberRole(bob.userId, CHANNEL)
    alice.team.addMemberRole(charlie.userId, CHANNEL)

    // 👩🏾 Alice (admin) removes 👨🏻‍🦲 Bob from the channel. That legitimately rotates the channel key
    // to generation 1 and re-boxes it to the current holders — including Bob, whose access is taken
    // away by the removal's own reducer, not by leaving him out of the rotation.
    expect(() => alice.team.removeMemberRole(bob.userId, CHANNEL)).not.toThrow()
    expect(alice.team.roleKeys(CHANNEL).generation).toBe(1)

    const graph1 = serializeTeamGraph(alice.team.graph)
    charlie.team = teams.load(graph1, charlie.localContext, createKeyring(teamKeys))
    bob.team = teams.load(graph1, bob.localContext, createKeyring(teamKeys))

    const newMessage = 'gen-1: only remaining channel members'
    const newEnvelope = alice.team.encrypt(newMessage, CHANNEL)
    expect(newEnvelope.recipient.generation).toBe(1)
    expect(charlie.team.decrypt(newEnvelope)).toEqual(newMessage)
    expect(() => bob.team.decrypt(newEnvelope)).toThrow()
  })
})
