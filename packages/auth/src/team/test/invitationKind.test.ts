import { redactKeys } from '@localfirst/crdx'
import { redactDevice } from 'device/index.js'
import * as invitations from 'invitation/index.js'
import {
  deviceInvitationProof,
  memberInvitationProof,
  setup,
} from 'util/testing/index.js'
import { describe, expect, it } from 'vitest'

describe('invitation kind', () => {
  it('rejects a raw device invitation that names another member as its owner', () => {
    const { alice, eve } = setup('alice', { user: 'eve', admin: false })
    const invitation = invitations.create({
      seed: invitations.randomSeed(),
      userId: alice.userId,
    })

    expect(() =>
      eve.team.dispatch({
        type: 'INVITE_DEVICE',
        payload: { invitation },
      })
    ).toThrow(/device invitation must belong to its author/i)
  })

  it('rejects a device invitation used for a member without consuming it', () => {
    const { alice, bob } = setup('alice', { user: 'bob', member: false })
    const { id, seed } = alice.team.inviteDevice()

    expect(() =>
      alice.team.admitMember(
        memberInvitationProof(seed, bob.user, bob.device),
        bob.user.keys,
        bob.userName,
        redactDevice(bob.device)
      )
    ).toThrow(/device invitation cannot admit a member/)
    expect(alice.team.getInvitation(id).uses).toBe(0)
  })

  it('rejects a member invitation used for a device', () => {
    const { alice, bob } = setup('alice', { user: 'bob', member: false })
    const { seed } = alice.team.inviteMember()

    expect(() =>
      alice.team.admitDevice(
        deviceInvitationProof(seed, bob.userName, bob.device),
        redactDevice(bob.device),
        bob.userName
      )
    ).toThrow(/member invitation cannot admit a device/)
  })

  it('rejects a forged ADMIT_MEMBER that references an INVITE_DEVICE action', () => {
    const { alice, bob } = setup('alice', { user: 'bob', member: false })
    const { id, seed } = alice.team.inviteDevice()
    const proof = memberInvitationProof(seed, bob.user, bob.device)
    const claim = {
      invitationKind: 'member' as const,
      userName: bob.userName,
      userKeys: redactKeys(bob.user.keys),
      device: redactDevice(bob.device),
    }

    expect(() =>
      alice.team.dispatch({
        type: 'ADMIT_MEMBER',
        payload: {
          id,
          userName: bob.userName,
          memberKeys: redactKeys(bob.user.keys),
          proof,
          claim,
        },
      })
    ).toThrow(/device invitation cannot be used by ADMIT_MEMBER/)
    expect(alice.team.getInvitation(id).uses).toBe(0)
  })

  it('rejects a forged ADMIT_DEVICE that references an INVITE_MEMBER action', () => {
    const { alice, bob } = setup('alice', { user: 'bob', member: false })
    const { id, seed } = alice.team.inviteMember()
    const proof = deviceInvitationProof(seed, bob.userName, bob.device)
    const { userId: _userId, ...firstUseDevice } = redactDevice(bob.device)
    const claim = {
      invitationKind: 'device' as const,
      userName: bob.userName,
      device: firstUseDevice,
    }

    expect(() =>
      alice.team.dispatch({
        type: 'ADMIT_DEVICE',
        payload: { id, device: redactDevice(bob.device), proof, claim },
      })
    ).toThrow(/member invitation cannot be used by ADMIT_DEVICE/)
  })

  it('derives invitation kind from legacy action types without changing their payload', () => {
    const { alice } = setup('alice')
    const memberInvitation = alice.team.inviteMember()
    const deviceInvitation = alice.team.inviteDevice()
    const invitationLinks = Object.values(alice.team.graph.links).filter(
      link => link.body.type === 'INVITE_MEMBER' || link.body.type === 'INVITE_DEVICE'
    )

    for (const link of invitationLinks) {
      expect(link.body.payload.invitation).not.toHaveProperty('kind')
    }
    expect(alice.team.getInvitation(memberInvitation.id).kind).toBe('member')
    expect(alice.team.getInvitation(deviceInvitation.id).kind).toBe('device')
  })
})
