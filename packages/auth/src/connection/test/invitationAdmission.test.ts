import { createUser } from '@localfirst/crdx'
import { eventPromise } from '@localfirst/shared'
import { createDevice } from 'device/index.js'
import { pack, unpack } from 'msgpackr'
import * as teams from 'team/index.js'
import { all, asFirstUseDevice, joinTestChannel, setup, TestChannel } from 'util/testing/index.js'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { Connection } from '../Connection.js'
import { ADMIT_MEMBER_LINK_MISSING, ENCRYPTION_FAILURE } from '../errors.js'
import type { ConnectionMessage } from '../message.js'
import type { NumberedMessage } from '../MessageQueue.js'
import type { InviteeDeviceContext, InviteeMemberContext, MemberContext } from '../types.js'

describe('connection invitation admission', () => {
  const activeConnections: Connection[] = []

  afterEach(() => {
    for (const connection of activeConnections.splice(0)) {
      connection.stop(false)
    }
    vi.restoreAllMocks()
  })

  it('requires an independently supplied team ID for invitees', () => {
    const { alice, bob } = setup('alice', { user: 'bob', member: false })
    const { seed } = alice.team.inviteMember()
    const unboundContext = {
      user: bob.user,
      device: bob.device,
      invitationSeed: seed,
    } as InviteeMemberContext

    expect(() => new Connection({ context: unboundContext, sendMessage: vi.fn() })).toThrow(
      /expected team ID/
    )
  })

  it('accepts the exact invited member when another member has the same username', async () => {
    const { alice, bob } = setup('alice', 'bob')
    alice.team.addRole('member')

    const invitedUser = createUser(bob.userName)
    const invitedDevice = createDevice({
      userId: invitedUser.userId,
      deviceName: 'new-bob-laptop',
    })
    const { seed } = alice.team.inviteMember()
    const inviteeContext: InviteeMemberContext = {
      user: invitedUser,
      device: invitedDevice,
      invitationSeed: seed,
      expectedTeamId: alice.team.id,
    }
    const connections = createConnectionPair(memberContext(alice), inviteeContext)
    const joined = eventPromise(connections.invitee, 'joined')

    await connect(connections)
    const admission = await joined

    expect(admission.user.userId).toBe(invitedUser.userId)
    expect(admission.team.has(invitedUser.userId)).toBe(true)
    expect(admission.team.hasDevice(invitedDevice.deviceId)).toBe(true)
    expect(
      admission.team.members().filter(member => member.userName === bob.userName)
    ).toHaveLength(2)
  })

  it('accepts a first-use device that does not know its user ID yet', async () => {
    const { bob } = setup('bob')
    bob.team.addRole('member')

    const phone = asFirstUseDevice(bob.phone!)
    const { seed } = bob.team.inviteDevice()
    const inviteeContext: InviteeDeviceContext = {
      userName: bob.userName,
      device: phone,
      invitationSeed: seed,
      expectedTeamId: bob.team.id,
    }
    const connections = createConnectionPair(memberContext(bob), inviteeContext)
    const joined = eventPromise(connections.invitee, 'joined')

    await connect(connections)
    const admission = await joined

    expect('userId' in phone).toBe(false)
    expect(admission.user.userId).toBe(bob.userId)
    expect(admission.team.hasDevice(phone.deviceId)).toBe(true)
    expect(admission.team.members(bob.userId).devices).toHaveLength(2)
  })

  it('accepts an invited device when a different member admits it', async () => {
    const { alice, bob } = setup('alice', 'bob')
    alice.team.addRole('member')
    alice.team.addMemberRole(bob.userId, 'member')
    bob.team = teams.load(alice.team.save(), bob.localContext, alice.team.teamKeyring())

    const phone = asFirstUseDevice(bob.phone!)
    const { seed } = bob.team.inviteDevice()
    alice.team = teams.load(bob.team.save(), alice.localContext, bob.team.teamKeyring())
    const inviteeContext: InviteeDeviceContext = {
      userName: bob.userName,
      device: phone,
      invitationSeed: seed,
      expectedTeamId: bob.team.id,
    }
    const connections = createConnectionPair(memberContext(alice), inviteeContext)
    const joined = eventPromise(connections.invitee, 'joined')

    await connect(connections)
    const admission = await joined

    expect(admission.user.userId).toBe(bob.userId)
    expect(admission.team.hasDevice(phone.deviceId)).toBe(true)
    expect(admission.team.members(bob.userId).devices).toHaveLength(2)
  })

  it('emits joined only after the invitation connection is secured', async () => {
    const { alice, bob } = setup('alice', { user: 'bob', member: false })
    alice.team.addRole('member')
    const { seed } = alice.team.inviteMember()
    const inviteeContext: InviteeMemberContext = {
      user: bob.user,
      device: bob.device,
      invitationSeed: seed,
      expectedTeamId: alice.team.id,
    }
    const connections = createConnectionPair(memberContext(alice), inviteeContext)
    const events: string[] = []
    let sessionKeyAtJoined: Uint8Array | undefined
    connections.invitee.on('connectionSecured', () => events.push('connectionSecured'))
    connections.invitee.on('joined', () => {
      sessionKeyAtJoined = connections.invitee._sessionKey
      events.push('joined')
    })

    await connect(connections)

    expect(events).toEqual(['connectionSecured', 'joined'])
    expect(sessionKeyAtJoined).toBeInstanceOf(Uint8Array)
  })

  it('does not emit joined when session negotiation fails after admission', async () => {
    const { alice, bob } = setup('alice', { user: 'bob', member: false })
    alice.team.addRole('member')
    const { seed } = alice.team.inviteMember()
    const inviteeContext: InviteeMemberContext = {
      user: bob.user,
      device: bob.device,
      invitationSeed: seed,
      expectedTeamId: alice.team.id,
    }
    const channel = new TamperedSeedChannel(alice.device.deviceId)
    const connections = createConnectionPair(memberContext(alice), inviteeContext, channel)
    const joined = vi.fn()
    connections.invitee.on('joined', joined)
    const error = eventPromise(connections.invitee, 'localError')

    start(connections)

    await expect(error).resolves.toMatchObject({ type: ENCRYPTION_FAILURE })
    expect(joined).not.toHaveBeenCalled()
  })

  it('rejects a graph that contains the invitation but omits the invited device', async () => {
    const { bob } = setup('bob')
    bob.team.addRole('member')

    const phone = asFirstUseDevice(bob.phone!)
    const { seed } = bob.team.inviteDevice()
    const graphBeforeAdmission = bob.team.save()
    vi.spyOn(bob.team, 'save').mockReturnValue(graphBeforeAdmission)
    const inviteeContext: InviteeDeviceContext = {
      userName: bob.userName,
      device: phone,
      invitationSeed: seed,
      expectedTeamId: bob.team.id,
    }
    const connections = createConnectionPair(memberContext(bob), inviteeContext)

    await expectAdmissionRejection(connections)

    expect(connections.invitee.team).toBeUndefined()
  })

  it('rejects a graph that contains a same-named member but omits the exact invitee', async () => {
    const { alice, bob } = setup('alice', 'bob')
    alice.team.addRole('member')

    const invitedUser = createUser(bob.userName)
    const invitedDevice = createDevice({
      userId: invitedUser.userId,
      deviceName: 'new-bob-laptop',
    })
    const { seed } = alice.team.inviteMember()
    const graphBeforeAdmission = alice.team.save()
    vi.spyOn(alice.team, 'save').mockReturnValue(graphBeforeAdmission)
    const inviteeContext: InviteeMemberContext = {
      user: invitedUser,
      device: invitedDevice,
      invitationSeed: seed,
      expectedTeamId: alice.team.id,
    }
    const connections = createConnectionPair(memberContext(alice), inviteeContext)

    await expectAdmissionRejection(connections)

    expect(connections.invitee.team).toBeUndefined()
  })

  const memberContext = ({
    user,
    device,
    team,
  }: {
    user: MemberContext['user']
    device: MemberContext['device']
    team: MemberContext['team']
  }): MemberContext => ({ user, device, team })

  const createConnectionPair = (
    existingMember: MemberContext,
    invitee: InviteeDeviceContext | InviteeMemberContext,
    channel = new TestChannel()
  ) => {
    const join = joinTestChannel(channel)
    const connections = {
      member: join(existingMember),
      invitee: join(invitee),
    }
    activeConnections.push(connections.member, connections.invitee)
    return connections
  }

  const start = ({ member, invitee }: ReturnType<typeof createConnectionPair>) => {
    member.start()
    invitee.start()
  }

  const connect = async (connections: ReturnType<typeof createConnectionPair>) => {
    const connected = all([connections.member, connections.invitee], 'connected')
    start(connections)
    await connected
  }

  const expectAdmissionRejection = async (connections: ReturnType<typeof createConnectionPair>) => {
    const error = eventPromise(connections.invitee, 'localError')
    const disconnected = eventPromise(connections.invitee, 'disconnected')
    start(connections)

    await expect(error).resolves.toMatchObject({ type: ADMIT_MEMBER_LINK_MISSING })
    await disconnected
  }
})

class TamperedSeedChannel extends TestChannel {
  constructor(private readonly senderToTamper: string) {
    super()
  }

  override write(senderId: string, message: Uint8Array) {
    const numberedMessage = unpack(message) as NumberedMessage<ConnectionMessage>
    if (senderId === this.senderToTamper && numberedMessage.type === 'SEED') {
      const encryptedSeed = numberedMessage.payload.encryptedSeed.slice()
      encryptedSeed[Math.floor(encryptedSeed.length / 2)] ^= 1
      const tampered = pack({
        ...numberedMessage,
        payload: { encryptedSeed },
      })
      super.write(
        senderId,
        new Uint8Array(tampered.buffer, tampered.byteOffset, tampered.byteLength)
      )
      return
    }
    super.write(senderId, message)
  }
}
