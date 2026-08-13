import type { UnixTimestamp } from '@localfirst/crdx'
import * as select from 'team/selectors/index.js'
import { type Member, type Transform } from 'team/types.js'

/**
 * Removes a device from its owner and tombstones it.
 *
 * The tombstone is what makes the removal stick: the id stays in `removedDevices` forever, so we
 * can still tell a removed signer from an unknown one, and the uniqueness rule can refuse to let
 * the id come back.
 */
export const removeDevice =
  (deviceId: string, removedAt: UnixTimestamp): Transform =>
  state => {
    const removedDevice = select.device(state, deviceId)

    const removeDeviceFromMember = (member: Member) =>
      member.userId === removedDevice.userId
        ? { ...member, devices: member.devices?.filter(d => d.deviceId !== deviceId) }
        : member

    return {
      ...state,
      members: state.members.map(removeDeviceFromMember),
      removedDevices: [...state.removedDevices, { ...removedDevice, removedAt }],
    }
  }
