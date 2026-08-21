import { eventPromise } from '@localfirst/shared'
import { joinTestChannel, setup, TestChannel } from 'util/testing/index.js'
import { describe, expect, it } from 'vitest'
import type { InviteeDeviceContext } from '../types.js'

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
})
