import type { UnixTimestamp } from '@localfirst/crdx'
import { type Device } from 'device/index.js'
import { type Transform } from 'team/types.js'

/**
 * Registers a device to its owner.
 *
 * There is no re-add path for a genuinely removed device: a removed device id is tombstoned forever
 * (see `removeDevice`), and the uniqueness validator rejects any causal re-registration — otherwise
 * removing a compromised device would be undoable by whoever compromised it. The only tombstone this
 * clears is one left by a *concurrently-invalidated duplicate* of this same admission (the resolver
 * collapses duplicate registrations of one identity); registering the device for real means it must
 * not also remain tombstoned.
 */
export const addDevice =
  (device: Device, admittedAt: UnixTimestamp): Transform =>
  state => ({
    ...state,
    members: state.members.map(member =>
      member.userId === device.userId
        ? { ...member, devices: [...(member.devices ?? []), { ...device, admittedAt }] }
        : member
    ),
    removedDevices: state.removedDevices.filter(removed => removed.deviceId !== device.deviceId),
  })
