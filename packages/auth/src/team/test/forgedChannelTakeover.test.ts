import { createKeyring, createKeyset } from '@localfirst/crdx'
import * as lockbox from 'lockbox/index.js'
import * as teams from 'team/index.js'
import { serializeTeamGraph } from 'team/serialize.js'
import type { TeamAction } from 'team/types.js'
import { KeyType } from 'util/index.js'
import { setup } from 'util/testing/index.js'
import { describe, expect, it } from 'vitest'
import { expectRejectedEverywhere, forge, impersonate } from './forgeHelpers.js'

/**
 * The headline attack this whole refactor exists to stop.
 *
 * A Quiet private channel is an @localfirst/auth ROLE. Its messages are symmetrically encrypted
 * with the role's key, which reaches members in lockboxes on the graph. Forging authorship doesn't
 * hand an outsider that key — but it lets her *replace* it, because:
 *
 *   - the reducer's `collectLockboxes` applies the lockboxes on any link's payload without asking
 *     who they're for or what's in them, and
 *   - the link claiming to be from an admin was, until now, just a string in the body saying so.
 *
 * So 🦹‍♀️ Eve mints a generation-1 channel keyset of her own, ships it in lockboxes to herself and
 * to one honest member (not to the member she's locking out), and forges the re-key. Honest
 * clients adopt generation 1 and encrypt future traffic under a key Eve holds.
 *
 * The lockbox half of that is still unguarded — a genuinely compromised admin device can still do
 * this (see PR #33). What's closed here is the authorship half: you now have to *be* an admin
 * device, not merely say you are.
 */
const CHANNEL = 'private-channel-role'

describe('forged private-channel takeover', () => {
  it('rejects a re-key forged by a member who is not in the channel', () => {
    const { alice, bob, eve } = setup('alice', 'bob', { user: 'eve', admin: false })
    const teamKeys = alice.team.teamKeys()

    // 👩🏾 Alice (admin) creates a private channel and admits 👨🏻‍🦲 Bob. 🦹‍♀️ Eve is not in it.
    alice.team.addRole(CHANNEL)
    alice.team.addMemberRole(bob.userId, CHANNEL)

    const graph0 = serializeTeamGraph(alice.team.graph)
    bob.team = teams.load(graph0, bob.localContext, createKeyring(teamKeys))
    eve.team = teams.load(graph0, eve.localContext, createKeyring(teamKeys))

    // Baseline at generation 0: Bob reads the channel, Eve can't.
    const oldMessage = 'gen-0: legitimate channel members only'
    const oldEnvelope = alice.team.encrypt(oldMessage, CHANNEL)
    expect(bob.team.decrypt(oldEnvelope)).toEqual(oldMessage)
    expect(() => eve.team.decrypt(oldEnvelope)).toThrow()

    // 🦹‍♀️ Eve mints a generation-1 keyset she controls and hands it out to herself and to Alice —
    // Alice being the honest client whose adoption of generation 1 is what makes the attack pay.
    const evilKeys = createKeyset({ type: KeyType.ROLE, name: CHANNEL }, 'eve-controls-this-key')
    evilKeys.generation = 1
    const lockboxes = [
      lockbox.create(evilKeys, eve.team.members(eve.userId).keys),
      lockbox.create(evilKeys, eve.team.members(alice.userId).keys),
    ]

    const forged = forge({
      graph: eve.team.graph,
      action: {
        type: 'ADD_MEMBER_ROLE',
        payload: { userId: eve.userId, roleName: CHANNEL, lockboxes },
      } as TeamAction,
      signer: impersonate(alice, eve), // Alice's device id, Eve's keys
      teamKeys,
    })

    expectRejectedEverywhere({
      forged,
      teamKeys,
      peers: [bob, alice],
      message: /signature does not verify/,
    })

    // The channel is still on the generation the team agreed on, Eve is still not in it, and new
    // traffic is still readable by exactly the people it was before.
    expect(alice.team.roleKeys(CHANNEL).generation).toBe(0)
    expect(alice.team.memberHasRole(eve.userId, CHANNEL)).toBe(false)

    const newMessage = 'generation 0 remains private after the rejected forgery'
    const newEnvelope = alice.team.encrypt(newMessage, CHANNEL)
    expect(newEnvelope.recipient.generation).toBe(0)
    expect(bob.team.decrypt(newEnvelope)).toEqual(newMessage)
    expect(() => eve.team.decrypt(newEnvelope)).toThrow()
    expect(() => eve.team.decrypt(oldEnvelope)).toThrow()
  })

  it('rejects the same re-key when the excluded member forges it as a fellow channel member', () => {
    const { alice, bob, eve } = setup('alice', 'bob', { user: 'eve', admin: false })
    const teamKeys = alice.team.teamKeys()

    alice.team.addRole(CHANNEL)
    alice.team.addMemberRole(bob.userId, CHANNEL)

    const graph0 = serializeTeamGraph(alice.team.graph)
    bob.team = teams.load(graph0, bob.localContext, createKeyring(teamKeys))
    eve.team = teams.load(graph0, eve.localContext, createKeyring(teamKeys))

    // Impersonating 👨🏻‍🦲 Bob rather than an admin: Bob is in the channel, which is the other half
    // of what `memberCanRemoveMembersFromRole` wants. It makes no difference — the rejection
    // happens before any permission is consulted, because there is no established author yet.
    const evilKeys = createKeyset({ type: KeyType.ROLE, name: CHANNEL }, 'eve-controls-this-key')
    evilKeys.generation = 1

    const forged = forge({
      graph: eve.team.graph,
      action: {
        type: 'ADD_MEMBER_ROLE',
        payload: {
          userId: eve.userId,
          roleName: CHANNEL,
          lockboxes: [lockbox.create(evilKeys, eve.team.members(eve.userId).keys)],
        },
      } as TeamAction,
      signer: impersonate(bob, eve),
      teamKeys,
    })

    expectRejectedEverywhere({
      forged,
      teamKeys,
      peers: [alice, bob],
      message: /signature does not verify/,
    })

    expect(alice.team.memberHasRole(eve.userId, CHANNEL)).toBe(false)
  })

  it('CONTROL: an admin really can add a member to the channel, and the member can then read it', () => {
    const { alice, bob, eve } = setup('alice', 'bob', { user: 'eve', admin: false })
    const teamKeys = alice.team.teamKeys()

    alice.team.addRole(CHANNEL)
    alice.team.addMemberRole(bob.userId, CHANNEL)

    // 👩🏾 Alice, signing as herself, adds 🦹‍♀️ Eve to the channel. Everything about the forged link
    // above was fine except who signed it.
    alice.team.addMemberRole(eve.userId, CHANNEL)

    eve.team = teams.load(
      serializeTeamGraph(alice.team.graph),
      eve.localContext,
      createKeyring(teamKeys)
    )
    expect(eve.team.memberHasRole(eve.userId, CHANNEL)).toBe(true)

    const message = 'welcome to the channel'
    const envelope = alice.team.encrypt(message, CHANNEL)
    expect(eve.team.decrypt(envelope)).toEqual(message)
    expect(bob.team.merge(alice.team.graph).decrypt(envelope)).toEqual(message)
  })
})
