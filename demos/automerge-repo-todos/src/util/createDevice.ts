import * as Auth from '@localfirst/auth'
import { getDeviceNameFromUa } from './getDeviceNameFromUa'

export const createDevice = (userId: string) => {
  const deviceName = getDeviceNameFromUa()
  const device = Auth.createDevice({ userId, deviceName })
  return device
}

/** Creates a self-certifying founding device and derives its owner's id from it. */
export const createUserAndDevice = (userName: string) => {
  const deviceName = getDeviceNameFromUa()
  const firstUseDevice = Auth.createFirstUseDevice({ deviceName })
  const userId = Auth.deriveUserId(firstUseDevice.deviceId)
  const user = Auth.createUser(userName, userId)
  const device = { ...firstUseDevice, userId }
  return { user, device }
}
