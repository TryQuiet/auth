import type { UnixTimestamp } from '@localfirst/crdx'
import { type Device } from 'device/index.js'
import { type Transform } from 'team/types.js'

/**
 * Registers a device to its owner.
 *
 * There is no re-add path: a removed device id is tombstoned forever (see `removeDevice`), and the
 * uniqueness validator rejects any link that tries to register an id we've already seen. Otherwise
 * removing a compromised device would be undoable by whoever compromised it.
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
  })
