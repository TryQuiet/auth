import { merge } from '@localfirst/crdx'
import { randomKey } from '@localfirst/crypto'
import { eventPromise } from '@localfirst/shared'
import type { ConnectionMessage } from 'connection/message.js'
import type {
  Context,
  InviteeDeviceContext,
  InviteeMemberContext,
  MemberContext,
} from 'connection/types.js'
import { redactDevice, redactFirstUseDevice } from 'device/index.js'
import { createPossessionProof, generateProof } from 'invitation/index.js'
import { pack, unpack } from 'msgpackr'
import * as teams from 'team/index.js'
import { serializeTeamGraph } from 'team/serialize.js'
import type { Team } from 'team/Team.js'
import type { TeamGraph } from 'team/types.js'
import { deriveUserId } from 'util/userId.js'
import {
  invitationNonces,
  joinTestChannel,
  memberClaim,
  setup,
  TestChannel,
} from 'util/testing/index.js'
import { describe, expect, it } from 'vitest'
import type { NumberedMessage } from '../MessageQueue.js'
import { deviceAdmission, memberAdmission } from '../../team/test/helpers.js'

type AcceptanceMessage = Extract<ConnectionMessage, { type: 'ACCEPT_INVITATION' }>
type AcceptancePayload = AcceptanceMessage['payload']
type Rewrite = (payload: AcceptancePayload) => AcceptancePayload

// Exercise Path A end to end. Rewriting only ACCEPT_INVITATION lets each test present the same
// adversarial graph as the source suite without importing the source branch's validator.
describe('exact effective invitation admission validation', () => {
  it('accepts exact member and device admissions', async () => {
    const { alice, bob } = setup('alice', { user: 'bob', member: false })
    const memberInvite = alice.team.inviteMember()
    const member = await connectInvitee({
      acceptor: alice.connectionContext,
      invitee: { user: bob.user, device: bob.device, invitationSeed: memberInvite.seed },
    })
    expect(member.outcome.kind).toBe('joined')

    const { bob: laptop } = setup('bob')
    const deviceInvite = laptop.team.inviteDevice()
    const device = await connectInvitee({
      acceptor: laptop.connectionContext,
      invitee: {
        userName: laptop.userName,
        device: laptop.phone!,
        invitationSeed: deviceInvite.seed,
      },
    })
    expect(device.outcome.kind).toBe('joined')
  })

  it('opens and validates an acceptance payload exactly once', async () => {
    const { alice, bob } = setup('alice', { user: 'bob', member: false })
    const { seed } = alice.team.inviteMember()
    const result = await connectInvitee({
      acceptor: alice.connectionContext,
      invitee: { user: bob.user, device: bob.device, invitationSeed: seed },
    })

    expect(result.channel.acceptanceCount).toBe(1)
    expect(result.channel.acceptance).toHaveProperty('version', 2)
    expect(result.channel.acceptance).toHaveProperty('encryptedAcceptance', expect.any(Uint8Array))
  })

  it('classifies an unauthenticated acceptance before graph validation', async () => {
    const { alice, bob } = setup('alice', { user: 'bob', member: false })
    const { seed } = alice.team.inviteMember()
    const result = await connectInvitee({
      acceptor: alice.connectionContext,
      invitee: { user: bob.user, device: bob.device, invitationSeed: seed },
      rewrite: payload => {
        const serializedGraph = payload.serializedGraph.slice()
        serializedGraph[Math.floor(serializedGraph.length / 2)] ^= 1
        return { ...payload, serializedGraph }
      },
    })

    expect(result.outcome).toMatchObject({
      kind: 'rejected',
      error: { type: 'ACCEPTANCE_INVALID' },
    })
  })

  it('rejects an identity that exists without an ADMIT action', async () => {
    const { alice, bob } = setup('alice', { user: 'bob', member: false })
    const { seed } = alice.team.inviteMember()
    const spoof = cloneTeam(alice.team, alice.connectionContext)
    spoof.addForTesting(bob.user, [], redactDevice(bob.device))

    const result = await connectInvitee({
      acceptor: alice.connectionContext,
      invitee: { user: bob.user, device: bob.device, invitationSeed: seed },
      rewrite: acceptanceFrom(spoof),
    })

    expect(result.outcome.kind).toBe('rejected')
  })

  it('rejects a self-consistent replacement team with the wrong root', async () => {
    const { alice, bob } = setup('alice', { user: 'bob', member: false })
    const { seed } = alice.team.inviteMember()
    const { mallory } = setup('mallory')
    mallory.team.inviteMember({ seed })

    const result = await connectInvitee({
      acceptor: mallory.connectionContext,
      invitee: { user: bob.user, device: bob.device, invitationSeed: seed },
    })

    expect(result.outcome.kind).toBe('rejected')
  })

  it('rejects an identity admitted by another invitation ID', async () => {
    const { alice, bob } = setup('alice', { user: 'bob', member: false })
    const first = alice.team.inviteMember()
    const second = alice.team.inviteMember()
    const acceptorTeam = cloneTeam(alice.team, alice.connectionContext)
    const spoof = cloneTeam(alice.team, alice.connectionContext)
    spoof.admitMember(...memberAdmission(first.seed, bob))

    const result = await connectInvitee({
      acceptor: withTeam(alice.connectionContext, acceptorTeam),
      invitee: { user: bob.user, device: bob.device, invitationSeed: second.seed },
      rewrite: acceptanceFrom(spoof),
    })

    expect(result.outcome.kind).toBe('rejected')
  })

  it('rejects an admission made with a different handshake proof', async () => {
    const { alice, bob } = setup('alice', { user: 'bob', member: false })
    const { seed } = alice.team.inviteMember()
    const acceptorTeam = cloneTeam(alice.team, alice.connectionContext)
    const spoof = cloneTeam(alice.team, alice.connectionContext)
    spoof.admitMember(...memberAdmission(seed, bob))

    const result = await connectInvitee({
      acceptor: withTeam(alice.connectionContext, acceptorTeam),
      invitee: { user: bob.user, device: bob.device, invitationSeed: seed },
      rewrite: acceptanceFrom(spoof),
    })

    expect(result.outcome.kind).toBe('rejected')
  })

  it('rejects a matching invitation ID with different public keys', async () => {
    const { alice, bob } = setup('alice', { user: 'bob', member: false })
    const { seed } = alice.team.inviteMember()
    const acceptorTeam = cloneTeam(alice.team, alice.connectionContext)
    const spoof = cloneTeam(alice.team, alice.connectionContext)
    const claim = memberClaim(bob.user, bob.device)
    const changedClaim = {
      ...claim,
      memberKeys: {
        ...claim.memberKeys,
        signature: randomKey(),
      },
    }
    const proof = generateProof({ seed, claim: changedClaim, ...invitationNonces() })
    const possessionProof = createPossessionProof({
      invitationId: proof.id,
      claim: changedClaim,
      device: bob.device,
    })
    spoof.admitMember(proof, changedClaim, possessionProof)

    const result = await connectInvitee({
      acceptor: withTeam(alice.connectionContext, acceptorTeam),
      invitee: { user: bob.user, device: bob.device, invitationSeed: seed },
      rewrite: acceptanceFrom(spoof),
    })

    expect(result.outcome.kind).toBe('rejected')
  })

  it('rejects a matching device found under the wrong member', async () => {
    const { alice, bob, eve } = setup('alice', 'bob', { user: 'eve', member: false })
    const { seed } = bob.team.inviteDevice()
    alice.team.merge(bob.team.graph)
    const acceptorTeam = cloneTeam(alice.team, alice.connectionContext)
    const spoof = cloneTeam(alice.team, alice.connectionContext)
    const phone = redactFirstUseDevice(bob.phone!)
    const wrongOwnerId = deriveUserId(phone.deviceId)
    const wrongOwner = {
      ...eve.user,
      userId: wrongOwnerId,
      keys: { ...eve.user.keys, name: wrongOwnerId },
    }
    spoof.addForTesting(wrongOwner, [], { ...phone, userId: wrongOwnerId })

    const result = await connectInvitee({
      acceptor: withTeam(alice.connectionContext, acceptorTeam),
      invitee: { userName: bob.userName, device: bob.phone!, invitationSeed: seed },
      rewrite: acceptanceFrom(spoof),
    })

    expect(result.outcome.kind).toBe('rejected')
  })

  it('rejects a raw matching admission invalidated by the membership resolver', async () => {
    const { alice, bob, charlie } = setup('alice', 'bob', {
      user: 'charlie',
      member: false,
    })
    alice.team.removeMemberRole(bob.userId, 'admin')
    const { seed } = bob.team.inviteMember()
    bob.team.admitMember(...memberAdmission(seed, charlie))
    const invalidGraph = serializeTeamGraph(merge(alice.team.graph, bob.team.graph) as TeamGraph)
    const invalidKeyring = {
      ...alice.team.teamKeyring(),
      ...bob.team.teamKeyring(),
    }
    const result = await connectInvitee({
      acceptor: bob.connectionContext,
      invitee: { user: charlie.user, device: charlie.device, invitationSeed: seed },
      rewrite: () => ({ serializedGraph: invalidGraph, teamKeyring: invalidKeyring }),
    })

    expect(result.outcome.kind).toBe('rejected')
  })

  it('rejects an admission followed by removal', async () => {
    const { alice, bob } = setup('alice', { user: 'bob', member: false })
    const { seed } = alice.team.inviteMember()
    const acceptorTeam = cloneTeam(alice.team, alice.connectionContext)
    const spoof = cloneTeam(alice.team, alice.connectionContext)
    spoof.admitMember(...memberAdmission(seed, bob))
    spoof.remove(bob.userId)

    const result = await connectInvitee({
      acceptor: withTeam(alice.connectionContext, acceptorTeam),
      invitee: { user: bob.user, device: bob.device, invitationSeed: seed },
      rewrite: acceptanceFrom(spoof),
    })

    expect(result.outcome.kind).toBe('rejected')
  })

  it('accepts only the matching admission from a multi-use member invitation', async () => {
    const { alice, bob, eve } = setup(
      'alice',
      { user: 'bob', member: false },
      { user: 'eve', member: false }
    )
    const { seed } = alice.team.inviteMember()
    const acceptorTeam = cloneTeam(alice.team, alice.connectionContext)
    acceptorTeam.admitMember(...memberAdmission(seed, eve))

    const result = await connectInvitee({
      acceptor: withTeam(alice.connectionContext, acceptorTeam),
      invitee: { user: bob.user, device: bob.device, invitationSeed: seed },
    })

    expect(result.outcome.kind).toBe('joined')
    expect(result.invitee.team?.has(bob.userId)).toBe(true)
    expect(result.invitee.team?.has(eve.userId)).toBe(true)
  })
})

class RewriteAcceptanceChannel extends TestChannel {
  acceptance?: AcceptancePayload
  acceptanceCount = 0

  constructor(private readonly rewrite?: Rewrite) {
    super()
  }

  override write(senderId: string, message: Uint8Array) {
    const numbered = unpack(message) as NumberedMessage<ConnectionMessage>
    if (numbered.type !== 'ACCEPT_INVITATION') {
      super.write(senderId, message)
      return
    }

    this.acceptanceCount += 1
    this.acceptance = numbered.payload
    const rewritten = pack({
      ...numbered,
      payload: this.rewrite?.(numbered.payload) ?? numbered.payload,
    })
    super.write(
      senderId,
      new Uint8Array(rewritten.buffer, rewritten.byteOffset, rewritten.byteLength)
    )
  }
}

type ConnectOptions = {
  acceptor: Context
  invitee: InviteeMemberContext | InviteeDeviceContext
  rewrite?: Rewrite
}

const connectInvitee = async ({
  acceptor: acceptorContext,
  invitee: inviteeContext,
  rewrite,
}: ConnectOptions) => {
  const channel = new RewriteAcceptanceChannel(rewrite)
  const join = joinTestChannel(channel)
  const acceptor = join(acceptorContext)
  const invitee = join(inviteeContext)
  const outcome = Promise.race([
    eventPromise(invitee, 'joined').then(() => ({ kind: 'joined' as const })),
    eventPromise(invitee, 'localError').then(error => ({
      kind: 'rejected' as const,
      error,
    })),
    eventPromise(invitee, 'remoteError').then(error => ({
      kind: 'rejected' as const,
      error,
    })),
  ])

  acceptor.start()
  invitee.start()
  const settled = await outcome
  acceptor.stop(false)
  invitee.stop(false)
  return { outcome: settled, channel, acceptor, invitee }
}

const cloneTeam = (team: Team, context: Context) =>
  teams.load(team.save(), asMemberContext(context), team.teamKeyring())

const withTeam = (context: Context, team: Team): MemberContext => ({
  user: asMemberContext(context).user,
  device: asMemberContext(context).device,
  team,
})

const asMemberContext = (context: Context): MemberContext => context as MemberContext

const acceptanceFrom =
  (team: Team): Rewrite =>
  () => ({
    serializedGraph: team.save(),
    teamKeyring: team.teamKeyring(),
  })
