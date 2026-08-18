import * as invitations from 'invitation/index.js'
import { setup } from 'util/testing/index.js'
import { describe, expect, it } from 'vitest'
import { deviceAdmission, memberAdmission } from './helpers.js'

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

    expect(() => alice.team.admitMember(...memberAdmission(seed, bob))).toThrow(
      /device invitation cannot be used by ADMIT_MEMBER/
    )
    expect(alice.team.getInvitation(id)).toBeDefined()
    expect(alice.team.has(bob.userId)).toBe(false)
  })

  it('rejects a member invitation used for a device', () => {
    const { alice, bob } = setup('alice', { user: 'bob', member: false })
    const { seed } = alice.team.inviteMember()

    expect(() => alice.team.admitDevice(...deviceAdmission(seed, bob.device))).toThrow(
      /member invitation cannot be used by ADMIT_DEVICE/
    )
  })

  it('rejects a forged ADMIT_MEMBER that references an INVITE_DEVICE action', () => {
    const { alice, bob } = setup('alice', { user: 'bob', member: false })
    const { id, seed } = alice.team.inviteDevice()
    const [proof, claim, possessionProof] = memberAdmission(seed, bob)

    expect(() =>
      alice.team.dispatch({
        type: 'ADMIT_MEMBER',
        payload: {
          id,
          proof,
          claim,
          possessionProof,
        },
      })
    ).toThrow(/device invitation cannot be used by ADMIT_MEMBER/)
    expect(alice.team.getInvitation(id)).toBeDefined()
    expect(alice.team.has(bob.userId)).toBe(false)
  })

  it('rejects a forged ADMIT_DEVICE that references an INVITE_MEMBER action', () => {
    const { alice, bob } = setup('alice', { user: 'bob', member: false })
    const { id, seed } = alice.team.inviteMember()
    const [proof, claim, possessionProof] = deviceAdmission(seed, bob.device)

    expect(() =>
      alice.team.dispatch({
        type: 'ADMIT_DEVICE',
        payload: { id, proof, claim, possessionProof },
      })
    ).toThrow(/member invitation cannot be used by ADMIT_DEVICE/)
  })

  it('derives invitation kind from legacy action types without changing their payload', () => {
    const { alice } = setup('alice')
    const memberInvitation = alice.team.inviteMember()
    const deviceInvitation = alice.team.inviteDevice()
    for (const link of Object.values(alice.team.graph.links)) {
      if (link.body.type === 'INVITE_MEMBER' || link.body.type === 'INVITE_DEVICE') {
        expect(link.body.payload.invitation).not.toHaveProperty('kind')
      }
    }
    expect(alice.team.getInvitation(memberInvitation.id).kind).toBe('member')
    expect(alice.team.getInvitation(deviceInvitation.id).kind).toBe('device')
  })
})
