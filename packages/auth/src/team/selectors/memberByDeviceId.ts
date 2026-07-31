import { castServer } from 'server/castServer.js'
import type { TeamState } from '../index.js'
import { member, device, server, hasServer } from './index.js'

/**
 * Resolves a unique device ID to its member, or projects a uniquely matching server as a member.
 * Missing or ambiguous identities throw.
 */
export const memberByDeviceId = (
  state: TeamState,
  deviceId: string,
  options = { includeRemoved: false }
) => {
  const { userId } = device(state, deviceId, options)
  if (hasServer(state, deviceId, options)) {
    return castServer.toMember(server(state, deviceId, options))
  }
  return member(state, userId, options)
}
