import { eventPromise, pause } from '@localfirst/shared'
import type { Connection } from 'connection/index.js'
import type { InviteeMemberContext, MemberContext } from 'connection/types.js'
import type { TeamGraph } from 'team/types.js'
import {
  all,
  connect,
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

describe('concurrent ADMIT_MEMBER', () => {
  const activeConnections: Connection[] = []

  afterEach(() => {
    for (const connection of activeConnections.splice(0)) {
      connection.stop(false)
    }
    vi.restoreAllMocks()
  })

  it('rejects the merge after the same member is admitted on two disconnected branches', async () => {
    const {
      alice: peer1,
      bob: peer2,
      charlie: peer3,
    } = setup('alice', 'bob', { user: 'charlie', member: false })

    // Peer 1 creates the invitation and shares its unused state with peer 2 before they disconnect.
    const memberInvitation = peer1.team.inviteMember()
    await connect(peer1, peer2)
    await disconnect(peer1, peer2)

    const peer3InviteeContext: InviteeMemberContext = {
      user: peer3.user,
      device: peer3.device,
      invitationSeed: memberInvitation.seed,
    }

    // Peer 3 presents the same identity and invitation independently to each disconnected branch.
    const peer1Admission = await admitMember(
      { user: peer1.user, device: peer1.device, team: peer1.team },
      peer3InviteeContext
    )
    const peer2Admission = await admitMember(
      { user: peer2.user, device: peer2.device, team: peer2.team },
      peer3InviteeContext
    )

    expect(peer1Admission.team.has(peer3.userId)).toBe(true)
    expect(peer2Admission.team.has(peer3.userId)).toBe(true)
    expect(peer1Admission.team.members(peer3.userId).keys).toEqual(
      peer2Admission.team.members(peer3.userId).keys
    )
    expect(peer1.team.graph.head).not.toEqual(peer2.team.graph.head)

    peer1.connectionContext = { user: peer1.user, device: peer1.device, team: peer1.team }
    peer2.connectionContext = { user: peer2.user, device: peer2.device, team: peer2.team }
    const mergeAttempts: MergeAttempt[] = []
    recordMergeAttempt('peer 1', peer1.team.merge.bind(peer1.team), mergeAttempts, peer1.team)
    recordMergeAttempt('peer 2', peer2.team.merge.bind(peer2.team), mergeAttempts, peer2.team)

    // Peer 3 is now disconnected from both branches. The original peers cannot reconcile their
    // independently valid ADMIT_MEMBER links because both introduce the same active member ID.
    const connected = await connect(peer1, peer2)
    await pause(50)
    const mergeResult = {
      connected,
      mergeAttempts,
      peer1Head: peer1.team.graph.head,
      peer2Head: peer2.team.graph.head,
    }
    console.info('Concurrent ADMIT_MEMBER merge result:', mergeResult)

    expect(connected).toBe(false)
    expect(mergeAttempts).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          result: 'rejected',
          error: expect.stringMatching(/active member id .* is already in use/i),
        }),
      ])
    )
    expect(peer1.team.graph.head).not.toEqual(peer2.team.graph.head)
  })

  const admitMember = async (
    memberContext: MemberContext,
    inviteeContext: InviteeMemberContext
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
