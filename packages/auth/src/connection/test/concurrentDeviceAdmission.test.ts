import { eventPromise, pause } from '@localfirst/shared'
import type { Connection } from 'connection/index.js'
import type { InviteeDeviceContext, MemberContext } from 'connection/types.js'
import type { TeamGraph } from 'team/types.js'
import {
  all,
  asFirstUseDevice,
  connect,
  connectWithInvitation,
  disconnect,
  joinTestChannel,
  setup,
  TestChannel,
} from 'util/testing/index.js'
import { afterEach, describe, expect, it, vi } from 'vitest'

type MergeAttempt = {
  peer: 'peer 1' | 'peer 2'
  result: 'merged' | 'rejected'
  error?: string
}

describe('concurrent device admission', () => {
  const activeConnections: Connection[] = []

  afterEach(() => {
    for (const connection of activeConnections.splice(0)) {
      connection.stop(false)
    }
    vi.restoreAllMocks()
  })

  it('rejects the merge after the same device invitation is admitted on two disconnected branches', async () => {
    const { alice: peer1, bob: peer2 } = setup('alice', {
      user: 'bob',
      member: false,
    })

    // Peer 1 creates both invitations before peer 2 joins, so the admitted member learns about the
    // still-unused device invitation as part of the team graph.
    const memberInvitation = peer1.team.inviteMember()
    const deviceInvitation = peer1.team.inviteDevice()

    await connectWithInvitation(peer1, peer2, memberInvitation.seed)
    await disconnect(peer1, peer2)

    const peer3Device = asFirstUseDevice(peer1.phone!)
    const peer3InviteeContext: InviteeDeviceContext = {
      userName: peer1.userName,
      device: peer3Device,
      invitationSeed: deviceInvitation.seed,
    }

    // Peer 3 completes the same device admission independently against each disconnected branch.
    const peer1Admission = await admitDevice(
      { user: peer1.user, device: peer1.device, team: peer1.team },
      peer3InviteeContext
    )
    const peer2Admission = await admitDevice(
      { user: peer2.user, device: peer2.device, team: peer2.team },
      peer3InviteeContext
    )

    expect(peer1Admission.team.hasDevice(peer3Device.deviceId)).toBe(true)
    expect(peer2Admission.team.hasDevice(peer3Device.deviceId)).toBe(true)
    expect(peer1Admission.team.device(peer3Device.deviceId).keys).toEqual(
      peer2Admission.team.device(peer3Device.deviceId).keys
    )
    expect(peer1.team.graph.head).not.toEqual(peer2.team.graph.head)

    peer1.connectionContext = { user: peer1.user, device: peer1.device, team: peer1.team }
    peer2.connectionContext = { user: peer2.user, device: peer2.device, team: peer2.team }
    const mergeAttempts: MergeAttempt[] = []
    recordMergeAttempt('peer 1', peer1.team.merge.bind(peer1.team), mergeAttempts, peer1.team)
    recordMergeAttempt('peer 2', peer2.team.merge.bind(peer2.team), mergeAttempts, peer2.team)

    // Peer 3 is disconnected from both branches. Reconnecting peers 1 and 2 now attempts to merge
    // the two independently valid ADMIT_DEVICE links.
    const connected = await connect(peer1, peer2)
    await pause(50)
    const mergeResult = {
      connected,
      mergeAttempts,
      peer1Head: peer1.team.graph.head,
      peer2Head: peer2.team.graph.head,
    }
    console.info('Concurrent device admission merge result:', mergeResult)

    expect(connected).toBe(false)
    expect(mergeAttempts).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          result: 'rejected',
          error: expect.stringMatching(/active device id .* is already in use/i),
        }),
      ])
    )
    expect(peer1.team.graph.head).not.toEqual(peer2.team.graph.head)
  })

  const admitDevice = async (
    memberContext: MemberContext,
    inviteeContext: InviteeDeviceContext
  ) => {
    const join = joinTestChannel(new TestChannel())
    const memberConnection = join(memberContext)
    const inviteeConnection = join(inviteeContext)
    activeConnections.push(memberConnection, inviteeConnection)
    const joined = eventPromise(inviteeConnection, 'joined')
    const connected = all([memberConnection, inviteeConnection], 'connected')

    memberConnection.start()
    inviteeConnection.start()

    const [admission] = await Promise.all([joined, connected])
    memberConnection.stop(false)
    inviteeConnection.stop(false)
    return admission
  }

  const recordMergeAttempt = (
    peer: MergeAttempt['peer'],
    originalMerge: (graph: TeamGraph) => unknown,
    attempts: MergeAttempt[],
    team: { merge: (graph: TeamGraph) => unknown }
  ) => {
    vi.spyOn(team, 'merge').mockImplementation(graph => {
      try {
        const result = originalMerge(graph)
        attempts.push({ peer, result: 'merged' })
        return result
      } catch (error) {
        attempts.push({
          peer,
          result: 'rejected',
          error: error instanceof Error ? error.message : String(error),
        })
        throw error
      }
    })
  }
})
