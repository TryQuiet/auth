import type { UnixTimestamp } from '@localfirst/crdx'
import { type Device } from 'device/index.js'
import { type NewMember, type Transform } from 'team/types.js'

/**
 * Adds a member to the team, along with the devices they're registering (if any).
 *
 * A member is never re-added once removed — their userId is tombstoned along with everything else
 * in the id namespace — so there's no un-removal path here.
 */
export const addMember =
  (newMember: NewMember, devices: Device[] = [], admittedAt: UnixTimestamp): Transform =>
  state => ({
    ...state,
    members: [
      ...state.members,
      {
        ...newMember,
        roles: [],
        devices: devices.map(device => ({ ...device, admittedAt })),
      },
    ],
  })
