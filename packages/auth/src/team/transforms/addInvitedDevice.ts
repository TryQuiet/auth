import type { UnixTimestamp } from '@localfirst/crdx'
import { assert } from '@localfirst/shared'
import { toOwnedDevice, type FirstUseDevice } from 'device/index.js'
import { type Transform } from 'team/types.js'
import { addDevice } from './addDevice.js'

/**
 * Registers a device admitted by a device invitation.
 *
 * The device's owner is taken from the invitation record on the graph, not from the claim: a device
 * invitation is issued *to* a particular user, and an invitee has no say in which user it joins.
 */
export const addInvitedDevice =
  (invitationId: string, device: FirstUseDevice, admittedAt: UnixTimestamp): Transform =>
  state => {
    const { userId } = state.invitations[invitationId]
    assert(userId, `Device invitation '${invitationId}' has no owner`)
    return addDevice(toOwnedDevice(device, userId), admittedAt)(state)
  }
