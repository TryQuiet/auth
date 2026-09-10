import { createKeyring, createKeyset } from '@localfirst/crdx'
import * as lockbox from 'lockbox/index.js'
import { castServer, createServer, redactServer } from 'server/index.js'
import type { Host } from 'server/index.js'
import * as teams from 'team/index.js'
import { serializeTeamGraph } from 'team/serialize.js'
import type { TeamAction } from 'team/types.js'
import { KeyType } from 'util/index.js'
import { setup as setupHumans, type SetupConfig } from 'util/testing/index.js'
import { describe, expect, it } from 'vitest'
import { memberAdmission } from './helpers.js'
import { expectRejectedEverywhere, forge, forgedSigner } from './forgeHelpers.js'

/**
 * The server instantiation of the channel-takeover attack — the one that models Quiet's real
 * deployment.
 *
 * QSS is handed the team keyring on CREATE_COMMUNITY, and is added as an LFA `Server` with
 * `roles: []`, so by design it never receives a channel key and cannot read private channels. But
 * the keyring is a *write* capability: `append` needs only the team keyset as the encryption
 * recipient plus any keypair to sign with. A malicious or compromised QSS operator could therefore
 * post an admin-authored channel re-key to a keyset it generated.
 *
 * Two separate things now stop it. A server's links are checked against its registered, immutable
 * `identityKeys`, so it can't sign as anybody else; and a server may only ever author `ADMIT_*`, so
 * even signing honestly as itself it has no business re-keying a channel.
 */
const CHANNEL = 'private-channel-role'
const HOST = 'qss.quiet.example' as Host

describe('forged private-channel takeover — by a QSS-equivalent server', () => {
  /**
   * A team with a QSS-equivalent server on it. `loadServer()` gives the server's own view of the
   * team as it stands when it's called, which is how QSS gets one: `save()` plus the keyring.
   */
  const setup = (...humans: SetupConfig) => {
    const users = setupHumans(...humans)
    const [founder] = Object.values(users)

    const serverWithSecrets = createServer({ host: HOST, seed: 'qss-seed' })
    founder.team.addServer(redactServer(serverWithSecrets))

    // Everybody re-loads the team that has the server on it
    const teamKeys = founder.team.teamKeys()
    const graph = serializeTeamGraph(founder.team.graph)
    for (const user of Object.values(users)) {
      if (user.team.has(founder.userId)) {
        user.team = teams.load(graph, user.localContext, createKeyring(teamKeys))
      }
    }

    const loadServer = () =>
      teams.load(founder.team.save(), { server: serverWithSecrets }, founder.team.teamKeyring())

    return { users, serverWithSecrets, teamKeys, loadServer }
  }

  /** A private channel with 👨🏻‍🦲 Bob in it and nobody else. */
  const withChannel = (...humans: SetupConfig) => {
    const context = setup(...humans)
    const { users, teamKeys } = context
    const { alice, bob } = users

    alice.team.addRole(CHANNEL)
    alice.team.addMemberRole(bob.userId, CHANNEL)

    const graph = serializeTeamGraph(alice.team.graph)
    bob.team = teams.load(graph, bob.localContext, createKeyring(teamKeys))

    return { ...context, qss: context.loadServer() }
  }

  const evilChannelKeys = () => {
    const keys = createKeyset({ type: KeyType.ROLE, name: CHANNEL }, 'qss-controls-this-key')
    keys.generation = 1
    return keys
  }

  it('rejects a channel re-key the server signs honestly as itself', () => {
    const { users, qss, serverWithSecrets, teamKeys } = withChannel('alice', 'bob', 'carol')
    const { alice, bob, carol } = users

    // CONTROL for the read boundary: the server holds the team keyring but no channel key
    const oldMessage = 'gen-0: legitimate channel members only'
    const oldEnvelope = alice.team.encrypt(oldMessage, CHANNEL)
    expect(bob.team.decrypt(oldEnvelope)).toEqual(oldMessage)
    expect(() => qss.roleKeys(CHANNEL)).toThrow()
    expect(() => qss.decrypt(oldEnvelope)).toThrow()

    // 🖥️ The server signs with its own registered identity keys — no impersonation at all — and
    // covers the re-key as "add 👩🏼 Carol to the channel", so it isn't even a self-assignment.
    const evilKeys = evilChannelKeys()
    const forged = forge({
      graph: qss.graph,
      action: {
        type: 'ADD_MEMBER_ROLE',
        payload: {
          userId: carol.userId,
          roleName: CHANNEL,
          lockboxes: [
            lockbox.create(evilKeys, qss.members(alice.userId).keys),
            lockbox.create(evilKeys, redactServer(serverWithSecrets).keys),
          ],
        },
      } as TeamAction,
      signer: castServer.toSigner(serverWithSecrets),
      teamKeys,
    })

    // A server relays; it doesn't govern. This one is refused on the action, not on the signature.
    expectRejectedEverywhere({
      forged,
      teamKeys,
      peers: [alice, bob],
      message: /server cannot author ADD_MEMBER_ROLE/,
    })

    expect(alice.team.roleKeys(CHANNEL).generation).toBe(0)
    const newEnvelope = alice.team.encrypt('still private', CHANNEL)
    expect(newEnvelope.recipient.generation).toBe(0)
    expect(bob.team.decrypt(newEnvelope)).toEqual('still private')
    expect(() => qss.decrypt(newEnvelope)).toThrow()
  })

  it('rejects a channel re-key the server forges in an admin’s name', () => {
    const { users, qss, serverWithSecrets, teamKeys } = withChannel('alice', 'bob', 'carol')
    const { alice, bob, carol } = users

    // 🖥️ So the server tries it the other way round: claim 👩🏾 Alice's device, whose id is public
    // on the graph, and sign with the only keypair it has.
    const evilKeys = evilChannelKeys()
    const forged = forge({
      graph: qss.graph,
      action: {
        type: 'ADD_MEMBER_ROLE',
        payload: {
          userId: carol.userId,
          roleName: CHANNEL,
          lockboxes: [lockbox.create(evilKeys, qss.members(alice.userId).keys)],
        },
      } as TeamAction,
      signer: forgedSigner(alice.deviceId, serverWithSecrets.identityKeys),
      teamKeys,
    })

    expectRejectedEverywhere({
      forged,
      teamKeys,
      peers: [alice, bob],
      message: /signature does not verify/,
    })

    expect(alice.team.roleKeys(CHANNEL).generation).toBe(0)
    expect(alice.team.memberHasRole(carol.userId, CHANNEL)).toBe(false)
  })

  it('rejects a server link signed with its rotatable keys instead of its identity keys', () => {
    const { users, serverWithSecrets, teamKeys, loadServer } = setup('alice', 'bob', {
      user: 'charlie',
      member: false,
    })
    const { alice, bob, charlie } = users

    // A server has two keysets: `identityKeys`, which never rotate and are what its serverId is the
    // fingerprint of, and `keys`, which rotate and only ever open lockboxes. The rotatable pair is
    // not a second identity — a server that re-keyed and then signed with the new keys would be
    // indistinguishable from someone who had helped themselves to them.
    const { seed } = alice.team.inviteMember()
    const qss = loadServer()

    // Everything about this admission is correct and would be accepted from this server. The only
    // thing wrong with it is which of the server's two keysets made the signature.
    const [proof, claim, possessionProof] = memberAdmission(seed, charlie)
    const forged = forge({
      graph: qss.graph,
      action: {
        type: 'ADMIT_MEMBER',
        payload: {
          id: proof.id,
          proof,
          claim,
          possessionProof,
          lockboxes: [lockbox.create(teamKeys, claim.memberKeys)],
        },
      } as unknown as TeamAction,
      signer: forgedSigner(serverWithSecrets.serverId, serverWithSecrets.keys, 'server'),
      teamKeys,
    })

    expectRejectedEverywhere({
      forged,
      teamKeys,
      peers: [alice, bob],
      message: /signature does not verify/,
    })
    expect(alice.team.has(charlie.userId)).toBe(false)
  })

  it('rejects a member impersonating the server', () => {
    const { users, serverWithSecrets, teamKeys } = setup('alice', 'bob', {
      user: 'eve',
      admin: false,
    })
    const { alice, eve } = users

    // The server's id is as public as anybody's, and 🦹‍♀️ Eve would like the admit-anyone power it
    // has. Her device keys are perfectly valid; they're just not the ones the server registered.
    const forged = forge({
      graph: eve.team.graph,
      action: { type: 'ADD_ROLE', payload: { roleName: 'managers' } } as TeamAction,
      signer: forgedSigner(serverWithSecrets.serverId, eve.device.keys, 'server'),
      teamKeys,
    })

    expectRejectedEverywhere({
      forged,
      teamKeys,
      peers: [alice, eve],
      message: /signature does not verify/,
    })
  })

  it('CONTROL: the server can still do the one thing it is for — admitting an invited member', () => {
    const { users, loadServer } = setup('alice', 'bob', { user: 'charlie', member: false })
    const { alice, charlie } = users

    // 👩🏾 Alice issues an invitation; 🖥️ the server is the peer 👳🏽‍♂️ Charlie happens to reach.
    const { seed } = alice.team.inviteMember()
    const qss = loadServer()

    qss.admitMember(...memberAdmission(seed, charlie))

    // ✅ The admission is signed by the server's identity keys and accepted by every member
    expect(qss.has(charlie.userId)).toBe(true)
    alice.team.merge(qss.graph)
    expect(alice.team.has(charlie.userId)).toBe(true)
    expect(alice.team.hasDevice(charlie.deviceId)).toBe(true)

    // ...and by a replica validating the whole chain cold
    const reloaded = teams.load(qss.save(), alice.localContext, alice.team.teamKeyring())
    expect(reloaded.has(charlie.userId)).toBe(true)
  })
})
