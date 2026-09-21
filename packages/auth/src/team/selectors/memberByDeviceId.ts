import type { TeamState } from '../index.js'
import { device, member } from './index.js'

/** Finds the member that owns the given device. Devices only — servers aren't devices. */
export const memberByDeviceId = (
  state: TeamState,
  deviceId: string,
  options = { includeRemoved: false }
) => {
  const { userId } = device(state, deviceId, options)
  return member(state, userId, options)
}
