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

/** A link the attacker signs honestly as herself, carrying lockboxes for a key she minted. */
const rideLockboxesOnHonestLink = (attacker: UserStuff, lockboxes: lockbox.Lockbox[]) =>
  append({
    graph: attacker.team.graph,
    action: { type: 'ADD_LOCKBOXES', payload: { lockboxes } } as TeamAction,
    signer: attacker.signer, // no lie — she signs with her own device
    keys: attacker.team.teamKeys(),
  })

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

  it('drops a channel member re-keying the channel to lock another member out', () => {
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

    // 👨🏻‍🦲 Bob *is* in the channel, so he holds its key and clears check (a). What he may not do is
    // re-key it to a holder set that quietly omits 👳🏽‍♂️ Charlie — that would evict Charlie with no
    // REMOVE_MEMBER_ROLE link and no admin rights.
    const evilKeys = createKeyset({ type: KeyType.ROLE, name: CHANNEL }, 'bob-controls-this-key')
    evilKeys.generation = 1
    const attack = rideLockboxesOnHonestLink(bob, [
      lockbox.create(evilKeys, bob.team.members(bob.userId).keys),
      lockbox.create(evilKeys, bob.team.members(alice.userId).keys),
    ])

    expect(() => alice.team.merge(attack)).not.toThrow()
    expect(() => charlie.team.merge(attack)).not.toThrow()

    expect(alice.team.roleKeys(CHANNEL).generation).toBe(0)
    const newMessage = 'charlie is still in this channel'
    const newEnvelope = alice.team.encrypt(newMessage, CHANNEL)
    expect(charlie.team.decrypt(newEnvelope)).toEqual(newMessage)
  })

  it('drops a member re-keying the *team* key to lock another member out', () => {
    const { alice, bob, charlie } = setup(
      'alice',
      { user: 'bob', admin: false },
      { user: 'charlie', admin: false }
    )
    const teamKeys = alice.team.teamKeys()

    const graph0 = serializeTeamGraph(alice.team.graph)
    charlie.team = teams.load(graph0, charlie.localContext, createKeyring(teamKeys))

    // Every member holds the team key, so scope authority alone can't stop this one: what stops it
    // is that a re-key has to reach *every* current holder.
    const evilKeys = createKeyset({ type: KeyType.TEAM, name: KeyType.TEAM }, 'bob-controls-this')
    evilKeys.generation = 1
    const attack = rideLockboxesOnHonestLink(bob, [
      lockbox.create(evilKeys, bob.team.members(bob.userId).keys),
      lockbox.create(evilKeys, bob.team.members(alice.userId).keys),
    ])

    expect(() => alice.team.merge(attack)).not.toThrow()
    expect(alice.team.teamKeys().generation).toBe(0)

    // Charlie can still read what the team writes after the attempt.
    charlie.team.merge(attack)
    const envelope = alice.team.encrypt('charlie is still on this team')
    expect(charlie.team.decrypt(envelope)).toEqual('charlie is still on this team')
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
