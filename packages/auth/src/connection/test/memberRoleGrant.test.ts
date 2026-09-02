import { eventPromise } from '@localfirst/shared'
import { deriveId } from 'invitation/index.js'
import { createServer, redactServer } from 'server/index.js'
import * as teams from 'team/index.js'
import { createTestUser, joinTestChannel, setup, TestChannel } from 'util/testing/index.js'
import { describe, expect, it } from 'vitest'
import type { InviteeDeviceContext, InviteeMemberContext, ServerContext } from '../types.js'

describe('granting the member role on admission', () => {
  it("doesn't try to grant the role to our own user when the peer is our own device", async () => {
    const { bob } = setup('bob')

    // The team defines a `member` role that Bob himself doesn't hold. On admission we grant that
    // role to the peer — but when the peer is another of *our* devices, "the peer" is us, and
    // `canOnlySelfAddCertainRoles` rejects a self-assignment of `member`. That throw escapes into
    // the state machine, so both sides used to die instead of connecting.
    bob.team.addRole('member')
    expect(bob.team.members(bob.userId).roles).not.toContain('member')

    const { userId: _userId, ...phone } = bob.phone!
    const { seed, teamId } = bob.team.inviteDevice()
    const phoneContext: InviteeDeviceContext = {
      userName: bob.userName,
      device: phone,
      invitationSeed: seed,
      expectedTeamId: teamId,
    }

    const join = joinTestChannel(new TestChannel())
    const laptopConnection = join(bob.connectionContext)
    const phoneConnection = join(phoneContext)

    const connected = Promise.all([
      eventPromise(laptopConnection, 'connected'),
      eventPromise(phoneConnection, 'connected'),
    ])
    laptopConnection.start()
    phoneConnection.start()
    await connected

    expect(phoneConnection.team!.hasDevice(phone.deviceId)).toBe(true)
  })

  it('lets a server relay an encrypted grant without learning the member key', async () => {
    const alice = createTestUser('alice')
    const bob = createTestUser('bob')
    const team = teams.createTeam('server-relayed-member-grant', alice, undefined, {
      selfAssignableRoles: ['member'],
    })
    team.addRole('member')
    team.addMemberRole(alice.user.userId, 'member')

    const server = createServer({ host: 'qss.example', seed: 'qss-role-grant-test' })
    team.addServer(redactServer(server))
    const { seed, teamId } = team.inviteMember({ roleNames: ['member'] })
    const serverTeam = teams.load(team.save(), { server }, team.teamKeyring())

    // QSS can read the team graph and the public role manifest, but its keys cannot open the
    // invitation-bound ciphertext.
    expect(() => serverTeam.roleKeys('member')).toThrow()

    const serverContext: ServerContext = { server, team: serverTeam }
    const inviteeContext: InviteeMemberContext = {
      user: bob.user,
      device: bob.device,
      invitationSeed: seed,
      expectedTeamId: teamId,
    }
    const join = joinTestChannel(new TestChannel())
    const serverConnection = join(serverContext)
    const inviteeConnection = join(inviteeContext)
    const connected = Promise.all([
      eventPromise(serverConnection, 'connected'),
      eventPromise(inviteeConnection, 'connected'),
    ])

    serverConnection.start()
    inviteeConnection.start()
    await connected

    const inviteeTeam = inviteeConnection.team!
    expect(inviteeTeam.memberHasRole(bob.user.userId, 'member')).toBe(true)
    expect(inviteeTeam.roleKeys('member')).toEqual(team.roleKeys('member'))

    const encrypted = inviteeTeam.encrypt('member-only message', 'member')
    expect(team.decrypt(encrypted)).toBe('member-only message')
    expect(() => serverConnection.team!.roleKeys('member')).toThrow()
    expect(() => serverConnection.team!.decrypt(encrypted)).toThrow()
  })

  it('lets an invitee self-claim member when admitted by a non-admin peer', async () => {
    const { alice, bob } = setup('alice', { user: 'bob', admin: false })
    alice.team.dispatch({
      type: 'SET_METADATA',
      payload: { metadata: { selfAssignableRoles: ['member'] } },
    })
    alice.team.addRole('member')
    alice.team.addMemberRole(bob.userId, 'member')
    const charlie = createTestUser('non-admin-admission-charlie')
    const { seed, teamId } = alice.team.inviteMember({ roleNames: ['member'] })
    bob.team.merge(alice.team.graph)

    const inviteeContext: InviteeMemberContext = {
      user: charlie.user,
      device: charlie.device,
      invitationSeed: seed,
      expectedTeamId: teamId,
    }
    const join = joinTestChannel(new TestChannel())
    const bobConnection = join(bob.connectionContext)
    const charlieConnection = join(inviteeContext)
    const connected = Promise.all([
      eventPromise(bobConnection, 'connected'),
      eventPromise(charlieConnection, 'connected'),
    ])

    bobConnection.start()
    charlieConnection.start()
    await connected

    expect(charlieConnection.team!.memberHasRole(charlie.user.userId, 'member')).toBe(true)
    expect(charlieConnection.team!.roleKeys('member')).toEqual(alice.team.roleKeys('member'))
  })

  it('rejects a missing member grant before a non-admin peer admits the invitee', async () => {
    const { alice, bob } = setup('alice', { user: 'bob', admin: false })
    alice.team.dispatch({
      type: 'SET_METADATA',
      payload: { metadata: { selfAssignableRoles: ['member'] } },
    })
    alice.team.addRole('member')
    alice.team.addMemberRole(bob.userId, 'member')
    const charlie = createTestUser('missing-grant-charlie')
    const { seed, teamId } = alice.team.inviteMember({ roleNames: [] })
    bob.team.merge(alice.team.graph)

    const join = joinTestChannel(new TestChannel())
    const bobConnection = join(bob.connectionContext)
    const charlieConnection = join({
      user: charlie.user,
      device: charlie.device,
      invitationSeed: seed,
      expectedTeamId: teamId,
    } satisfies InviteeMemberContext)
    const rejected = eventPromise(charlieConnection, 'remoteError')

    bobConnection.start()
    charlieConnection.start()

    await expect(rejected).resolves.toMatchObject({ type: 'INVITATION_PROOF_INVALID' })
    expect(bobConnection.team!.has(charlie.user.userId)).toBe(false)
  })

  it('rejects a stale member grant before a non-admin peer admits the invitee', async () => {
    const { alice, bob } = setup('alice', { user: 'bob', admin: false })
    alice.team.dispatch({
      type: 'SET_METADATA',
      payload: { metadata: { selfAssignableRoles: ['member'] } },
    })
    alice.team.addRole('member')
    alice.team.addMemberRole(bob.userId, 'member')
    const charlie = createTestUser('stale-peer-charlie')
    const { seed, teamId } = alice.team.inviteMember({ roleNames: ['member'] })

    // Rotate the member role after issuing the invitation, making its encrypted grant stale.
    alice.team.removeMemberRole(alice.userId, 'member')
    bob.team.merge(alice.team.graph)
    expect(bob.team.hasCurrentInvitationRoleGrant(invitationId(seed), 'member')).toBe(false)

    const join = joinTestChannel(new TestChannel())
    const bobConnection = join(bob.connectionContext)
    const charlieConnection = join({
      user: charlie.user,
      device: charlie.device,
      invitationSeed: seed,
      expectedTeamId: teamId,
    } satisfies InviteeMemberContext)
    const rejected = eventPromise(charlieConnection, 'remoteError')

    bobConnection.start()
    charlieConnection.start()

    await expect(rejected).resolves.toMatchObject({ type: 'INVITATION_PROOF_INVALID' })
    expect(bobConnection.team!.has(charlie.user.userId)).toBe(false)
  })

  it('rejects a stale grant before the server admits the invitee', async () => {
    const alice = createTestUser('stale-alice')
    const bob = createTestUser('stale-bob')
    const team = teams.createTeam('stale-server-relayed-member-grant', alice, undefined, {
      selfAssignableRoles: ['member'],
    })
    team.addRole('member')
    team.addMemberRole(alice.user.userId, 'member')

    const server = createServer({ host: 'stale-qss.example', seed: 'stale-qss-role-grant-test' })
    team.addServer(redactServer(server))
    const { seed, teamId } = team.inviteMember({ roleNames: ['member'] })

    // Rotation makes the invitation grant stale after creation but before redemption.
    team.removeMemberRole(alice.user.userId, 'member')
    const serverTeam = teams.load(team.save(), { server }, team.teamKeyring())
    expect(serverTeam.hasCurrentInvitationRoleGrant(invitationId(seed), 'member')).toBe(false)

    const serverContext: ServerContext = { server, team: serverTeam }
    const inviteeContext: InviteeMemberContext = {
      user: bob.user,
      device: bob.device,
      invitationSeed: seed,
      expectedTeamId: teamId,
    }
    const join = joinTestChannel(new TestChannel())
    const serverConnection = join(serverContext)
    const inviteeConnection = join(inviteeContext)
    const rejected = eventPromise(inviteeConnection, 'remoteError')

    serverConnection.start()
    inviteeConnection.start()

    await expect(rejected).resolves.toMatchObject({ type: 'INVITATION_PROOF_INVALID' })
    expect(serverConnection.team!.has(bob.user.userId)).toBe(false)
  })

  it('rejects a grant whose role is no longer self-assignable before admission', async () => {
    const alice = createTestUser('policy-alice')
    const bob = createTestUser('policy-bob')
    const team = teams.createTeam('revoked-self-assignment-policy', alice, undefined, {
      selfAssignableRoles: ['member'],
    })
    team.addRole('member')
    team.addMemberRole(alice.user.userId, 'member')

    const server = createServer({ host: 'policy-qss.example', seed: 'policy-qss-role-grant-test' })
    team.addServer(redactServer(server))
    const { seed, teamId } = team.inviteMember({ roleNames: ['member'] })

    team.dispatch({
      type: 'SET_METADATA',
      payload: { metadata: { selfAssignableRoles: [] } },
    })
    const serverTeam = teams.load(team.save(), { server }, team.teamKeyring())
    expect(serverTeam.hasCurrentInvitationRoleGrant(invitationId(seed), 'member')).toBe(false)

    const serverContext: ServerContext = { server, team: serverTeam }
    const inviteeContext: InviteeMemberContext = {
      user: bob.user,
      device: bob.device,
      invitationSeed: seed,
      expectedTeamId: teamId,
    }
    const join = joinTestChannel(new TestChannel())
    const serverConnection = join(serverContext)
    const inviteeConnection = join(inviteeContext)
    const rejected = eventPromise(inviteeConnection, 'remoteError')

    serverConnection.start()
    inviteeConnection.start()

    await expect(rejected).resolves.toMatchObject({ type: 'INVITATION_PROOF_INVALID' })
    expect(serverConnection.team!.has(bob.user.userId)).toBe(false)
  })
})

/** Test-only shorthand for deriving the graph id of an invitation seed. */
const invitationId = (seed: string) => deriveId(seed)
