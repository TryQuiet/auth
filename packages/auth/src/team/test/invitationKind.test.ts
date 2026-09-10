import * as invitations from 'invitation/index.js'
import { setup } from 'util/testing/index.js'
import { describe, expect, it } from 'vitest'
import { deviceAdmission, memberAdmission } from './helpers.js'

/**
 * Every invitation has a kind — member or device — and admission must respect it: ADMIT_MEMBER may
 * only consume a member invitation, ADMIT_DEVICE only a device invitation, and a device invitation
 * belongs to the member who authored it. Without this, a device invitation (which also unlocks a
 * lockbox holding the author's user keys) could be redeemed to admit a brand-new member, or vice
 * versa, changing what the inviter authorized.
 *
 * The kind is not a field an author asserts; it is derived from which INVITE_* action created the
 * invitation, so it cannot be forged separately from the invitation itself. Tests below cover both
 * the Team API path and raw dispatches that bypass it (what a malicious client would append).
 */
describe('invitation kind', () => {
  // Team.inviteDevice always names its own author; this dispatches INVITE_DEVICE directly to forge
  // an invitation claiming to be for someone else's devices. If this were allowed, redeeming it
  // would attach a device (and its keys) to another member's identity.
  it('rejects an INVITE_DEVICE whose invitation names someone other than its author', () => {
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

  // Redeeming a device invitation to admit a new member must fail — and must fail cleanly: the
  // invitation survives (still redeemable by the device it was meant for) and no member appears.
  it('rejects ADMIT_MEMBER on a device invitation, leaving the invitation intact', () => {
    const { alice, bob } = setup('alice', { user: 'bob', member: false })
    const { id, seed } = alice.team.inviteDevice()

    expect(() => alice.team.admitMember(...memberAdmission(seed, bob))).toThrow(
      /device invitation cannot be used by ADMIT_MEMBER/
    )
    expect(alice.team.getInvitation(id)).toBeDefined()
    expect(alice.team.has(bob.userId)).toBe(false)
  })

  it('rejects ADMIT_DEVICE on a member invitation', () => {
    const { alice, bob } = setup('alice', { user: 'bob', member: false })
    const { seed } = alice.team.inviteMember()

    expect(() => alice.team.admitDevice(...deviceAdmission(seed, bob.device))).toThrow(
      /member invitation cannot be used by ADMIT_DEVICE/
    )
  })

  // Same cross-kind admissions as above, but appended as raw dispatches rather than through
  // Team.admitMember/admitDevice — proving the kind check lives in graph validation, where a
  // malicious client that skips the Team API is still subject to it.
  it('rejects a raw ADMIT_MEMBER referencing an INVITE_DEVICE action', () => {
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

  it('rejects a raw ADMIT_DEVICE referencing an INVITE_MEMBER action', () => {
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

  // The kind is derived at reduce time from the INVITE_* action type; it is never stored in the
  // invitation payload. That keeps the wire/graph format identical to graphs created before kinds
  // existed, so old graphs still validate and yield correct kinds.
  it('derives invitation kind from the action type without storing it in the payload', () => {
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
