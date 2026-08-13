import { createKeyring, verifyLinkSignature } from '@localfirst/crdx'
import { generateStarterKeys } from 'invitation/index.js'
import * as teams from 'team/index.js'
import { getTeamState } from 'team/getTeamState.js'
import * as select from 'team/selectors/index.js'
import { serializeTeamGraph } from 'team/serialize.js'
import type { Team } from 'team/Team.js'
import { SignerKind, type TeamGraph, type TeamLink } from 'team/types.js'
import { KeyType } from 'util/index.js'
import { setup } from 'util/testing/index.js'
import { describe, expect, it } from 'vitest'
import { deviceAdmission, memberAdmission } from './helpers.js'

/**
 * The control for the whole attack suite: nothing forged, everything works.
 *
 * Each rejection test above is only worth something if the honest version of what it rejects
 * succeeds — otherwise a validator that said no to everything would pass all of them. This walks
 * the full lifecycle the other tests carve pieces out of: found a team, invite and admit a member
 * with their first device, have that member post their own lockboxes, invite and admit a second
 * device, and confirm the result survives both acceptance paths.
 */
describe('the honest path', () => {
  /** Every link in the graph is signed by a key the graph itself registers for its signer. */
  const everyLinkVerifies = (team: Team) => {
    const state = team.state
    for (const link of Object.values(team.graph.links) as TeamLink[]) {
      const { signer } = link.body
      const record = select.signerRecord(state, signer, { includeRemoved: true })
      expect(record, `no registered signer for ${signer.kind}:${signer.id}`).toBeDefined()

      const publicKey =
        record!.kind === SignerKind.DEVICE
          ? record!.device.keys.signature
          : record!.server.identityKeys.signature
      expect(
        verifyLinkSignature({ hash: link.hash, signature: link.signature, publicKey }),
        `link ${link.body.type} does not verify against ${signer.id}`
      ).toBe(true)
    }
  }

  it('creates a team, admits a member and a second device, and validates on every path', () => {
    const { alice, bob } = setup('alice', { user: 'bob', member: false })

    // 👩🏾 Alice founds the team. The root registers her and her laptop, and is signed by that laptop.
    expect(alice.team.hasDevice(alice.deviceId)).toBe(true)
    expect(Object.keys(alice.team.graph.links)).toHaveLength(1)

    // ── 👨🏻‍🦲 Bob is invited and admitted, with his first device in the same link ──────────────
    const { seed } = alice.team.inviteMember()
    alice.team.admitMember(...memberAdmission(seed, bob))

    expect(alice.team.has(bob.userId)).toBe(true)
    expect(alice.team.hasDevice(bob.deviceId)).toBe(true)
    expect(alice.team.memberByDeviceId(bob.deviceId).userId).toBe(bob.userId)

    // 👨🏻‍🦲 Bob receives the graph and the keyring, and posts lockboxes so his laptop can get at his
    // user keys on its own. His device was registered by the admission, so this link is authored by
    // a signer the team already knows — which is the whole reason `join()` no longer registers one.
    const teamKeyring = alice.team.teamKeyring()
    bob.team = teams.load(alice.team.save(), bob.localContext, teamKeyring)
    bob.team.join(teamKeyring)

    alice.team.merge(bob.team.graph)
    expect(alice.team.members(bob.userId).devices).toHaveLength(1)

    // ── 📱 Bob adds a second device ────────────────────────────────────────────────────────────
    const { seed: deviceSeed } = bob.team.inviteDevice()
    bob.team.admitDevice(...deviceAdmission(deviceSeed, bob.phone!))

    expect(bob.team.members(bob.userId).devices).toHaveLength(2)
    expect(bob.team.hasDevice(bob.phone!.deviceId)).toBe(true)

    // 📱 The phone gets Bob's user keys out of the lockbox addressed to the invitation's starter
    // keys, then loads the team and posts lockboxes of its own.
    const serialized = bob.team.save()
    const bobsUser = {
      userId: bob.userId,
      userName: bob.userName,
      keys: select.keys(getTeamState(serialized, teamKeyring), generateStarterKeys(deviceSeed), {
        type: KeyType.USER,
        name: bob.userId,
      }),
    }
    const phoneTeam = teams.load(serialized, { user: bobsUser, device: bob.phone! }, teamKeyring)
    phoneTeam.join(teamKeyring)

    expect(phoneTeam.members(bob.userId).devices).toHaveLength(2)

    // ── everything validates, from bytes and from a merge ──────────────────────────────────────
    alice.team.merge(phoneTeam.graph)
    expect(alice.team.members(bob.userId).devices).toHaveLength(2)
    expect(alice.team.has(bob.userId)).toBe(true)

    const reloaded = teams.load(
      serializeTeamGraph(alice.team.graph as TeamGraph),
      alice.localContext,
      teamKeyring
    )
    expect(reloaded.has(bob.userId)).toBe(true)
    expect(reloaded.members(bob.userId).devices).toHaveLength(2)
    expect(reloaded.hasDevice(bob.deviceId)).toBe(true)
    expect(reloaded.hasDevice(bob.phone!.deviceId)).toBe(true)

    // ...and from the object form, which is re-decrypted rather than taken at its word.
    const fromObject = teams.load(alice.team.graph, alice.localContext, teamKeyring)
    expect(fromObject.members(bob.userId).devices).toHaveLength(2)

    everyLinkVerifies(alice.team)
    everyLinkVerifies(reloaded)
  })

  it('keeps every replica in agreement after the members merge in both directions', () => {
    const { alice, bob, charlie } = setup('alice', 'bob', 'charlie')
    const teamKeyring = alice.team.teamKeyring()

    // Three replicas act independently and then sync every which way. Nothing here is adversarial;
    // the point is that the signer-resolution rules don't depend on the order links arrive in.
    alice.team.addRole('managers')
    bob.team.addRole('editors')
    charlie.team.addRole('reviewers')

    alice.team.merge(bob.team.graph)
    charlie.team.merge(alice.team.graph)
    alice.team.merge(charlie.team.graph)
    bob.team.merge(charlie.team.graph)

    for (const team of [alice.team, bob.team, charlie.team]) {
      expect(team.hasRole('managers')).toBe(true)
      expect(team.hasRole('editors')).toBe(true)
      expect(team.hasRole('reviewers')).toBe(true)
      everyLinkVerifies(team)
    }

    const reloaded = teams.load(
      serializeTeamGraph(alice.team.graph as TeamGraph),
      charlie.localContext,
      createKeyring(teamKeyring)
    )
    expect(reloaded.hasRole('editors')).toBe(true)
    everyLinkVerifies(reloaded)
  })
})
