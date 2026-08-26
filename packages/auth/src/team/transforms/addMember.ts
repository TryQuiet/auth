import type { UnixTimestamp } from '@localfirst/crdx'
import { type Device } from 'device/index.js'
import { type NewMember, type Transform } from 'team/types.js'

/**
 * Adds a member to the team, along with the devices they're registering (if any).
 *
 * A removed member is never re-added — their userId is tombstoned along with everything else in the
 * id namespace, and the uniqueness validator rejects any causal re-registration. The one thing this
 * clears is a stale tombstone left by a *concurrently-invalidated duplicate* of this very admission:
 * when two branches admit the same identity, the resolver drops one, and if that dropped duplicate
 * was reduced first it tombstoned the member/device. Registering them for real here removes those
 * tombstones so the converged identity is live, not simultaneously live and removed.
 */
export const addMember =
  (newMember: NewMember, devices: Device[] = [], admittedAt: UnixTimestamp): Transform =>
  state => {
    const deviceIds = new Set(devices.map(device => device.deviceId))
    return {
      ...state,
      members: [
        ...state.members,
        {
          ...newMember,
          roles: [],
          devices: devices.map(device => ({ ...device, admittedAt })),
        },
      ],
      removedMembers: state.removedMembers.filter(member => member.userId !== newMember.userId),
      removedDevices: state.removedDevices.filter(device => !deviceIds.has(device.deviceId)),
      pendingKeyRotations: state.pendingKeyRotations.filter(userId => userId !== newMember.userId),
    }
  }
