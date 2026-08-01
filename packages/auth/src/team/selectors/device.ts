import { type TeamState } from 'team/types.js'
import { assert } from '@localfirst/shared'
import { server } from './server.js'
import { hasServer } from './hasServer.js'
import { castServer } from 'server/castServer.js'

/** Returns whether exactly one matching device exists; throws when the ID is ambiguous. */
export const hasDevice = (
  state: TeamState,
  deviceId: string,
  options = { includeRemoved: false }
) => {
  return getDevices(state, deviceId, options).length === 1
}

/**
 * Returns the unique member device or server projection for `deviceId`. Removed identities are
 * included only when requested; missing and ambiguous IDs throw.
 */
export const device = (state: TeamState, deviceId: string, options = { includeRemoved: false }) => {
  const matchingDevices = getDevices(state, deviceId, options)
  assert(matchingDevices.length > 0, `Device ${deviceId} not found`)
  assert(matchingDevices.length === 1, `Device ID '${deviceId}' is ambiguous`)
  return matchingDevices[0]
}

const getDevices = (state: TeamState, deviceId: string, options = { includeRemoved: false }) => {
  const matchingServers = hasServer(state, deviceId, options)
    ? [castServer.toDevice(server(state, deviceId, options))]
    : []
  const members = state.members.concat(options.includeRemoved ? state.removedMembers : [])
  const memberDevices = members
    .flatMap(member => member.devices ?? [])
    .filter(device => device.deviceId === deviceId)
  const removedDevices = options.includeRemoved
    ? state.removedDevices.filter(device => device.deviceId === deviceId)
    : []
  const matchingDevices = [...matchingServers, ...memberDevices, ...removedDevices]
  if (matchingDevices.length > 1) {
    throw new Error(`Device ID '${deviceId}' is ambiguous`)
  }
  return matchingDevices
}
