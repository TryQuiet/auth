import { assert } from '@localfirst/shared'
import type { DeviceRecord, TeamState } from 'team/types.js'

/**
 * Devices live in their own namespace. Servers are *not* devices — they have their own ids and
 * their own keys — so a server can never be returned from a device lookup, and a server's id can
 * never shadow a device's.
 */
const getDevices = (
  state: TeamState,
  deviceId: string,
  options = { includeRemoved: false }
): DeviceRecord[] => {
  const members = state.members.concat(options.includeRemoved ? state.removedMembers : [])
  const memberDevices = members
    .flatMap(member => member.devices ?? [])
    .filter(device => device.deviceId === deviceId)
  const removedDevices = options.includeRemoved
    ? state.removedDevices.filter(device => device.deviceId === deviceId)
    : []
  return [...memberDevices, ...removedDevices]
}

/** Returns whether exactly one matching device exists; throws when the id is ambiguous. */
export const hasDevice = (
  state: TeamState,
  deviceId: string,
  options = { includeRemoved: false }
) => {
  const matchingDevices = getDevices(state, deviceId, options)
  assert(matchingDevices.length <= 1, `Device ID '${deviceId}' is ambiguous`)
  return matchingDevices.length === 1
}

/**
 * Returns the unique device with the given id. Removed devices are included only when asked for;
 * missing and ambiguous ids throw, rather than quietly resolving to the first match.
 */
export const device = (state: TeamState, deviceId: string, options = { includeRemoved: false }) => {
  const matchingDevices = getDevices(state, deviceId, options)
  assert(matchingDevices.length > 0, `Device ${deviceId} not found`)
  assert(matchingDevices.length === 1, `Device ID '${deviceId}' is ambiguous`)
  return matchingDevices[0]
}

/** All devices known to the team, active and removed. Used for global id-uniqueness checks. */
export const allDeviceIds = (state: TeamState): string[] => [
  ...[...state.members, ...state.removedMembers].flatMap(member =>
    (member.devices ?? []).map(device => device.deviceId)
  ),
  ...state.removedDevices.map(device => device.deviceId),
]
