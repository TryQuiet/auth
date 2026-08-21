import { type UnixTimestamp } from '@localfirst/crdx'
import * as invitations from 'invitation/index.js'
import { setup } from 'util/testing/index.js'
import { describe, expect, it } from 'vitest'

describe('invitation record immutability', () => {
  it('rejects re-posting a revoked device invitation', () => {
    const { alice } = setup('alice')

    const { id } = alice.team.inviteDevice()
    const invitation = alice.team.getInvitation(id)

    alice.team.revokeInvitation(id)
    const revokedInvitation = alice.team.getInvitation(id)

    expect(() =>
      alice.team.dispatch({
        type: 'INVITE_DEVICE',
        payload: { invitation },
      })
    ).toThrow()
    expect(alice.team.getInvitation(id)).toEqual(revokedInvitation)
    expect(alice.team.getInvitation(id).revoked).toBe(true)
  })

  it(
    'rejects replacing a revoked invitation with a later invitation operation using the same id',
    () => {
      const { alice } = setup('alice')

      const { id, seed } = alice.team.inviteDevice()
      const originalInvitation = alice.team.getInvitation(id)

      alice.team.revokeInvitation(id)
      const revokedInvitation = alice.team.getInvitation(id)

      const replacementInvitation = invitations.create({
        seed,
        expiration: (originalInvitation.expiration + 60_000) as UnixTimestamp,
        userId: alice.userId,
      })

      expect(replacementInvitation.id).toBe(id)
      expect(replacementInvitation.expiration).toBeGreaterThan(originalInvitation.expiration)
      expect(() =>
        alice.team.dispatch({
          type: 'INVITE_DEVICE',
          payload: { invitation: replacementInvitation },
        })
      ).toThrow()
      expect(alice.team.getInvitation(id)).toEqual(revokedInvitation)
      expect(alice.team.getInvitation(id).revoked).toBe(true)
    }
  )
})
