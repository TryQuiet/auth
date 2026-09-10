import { redactKeys } from '@localfirst/crdx'
import type {
  Device,
  DeviceWithSecrets,
  FirstUseDevice,
  FirstUseDeviceWithSecrets,
} from './types.js'

/** Drops a device's owner, giving the form an invitee presents before it knows its `userId`. */
export const toFirstUseDevice = (device: Device): FirstUseDevice => {
  const { userId: _userId, ...firstUseDevice } = device
  return firstUseDevice
}

/**
 * Assigns an owner to a first-use device. The `userId` must come from the authenticated invitation
 * record — never from the invitee — since that is what binds a new device to the right user.
 */
export const toOwnedDevice = (device: FirstUseDevice, userId: string): Device => ({
  ...device,
  userId,
})

/** Redacts a device's secret keys and drops its owner, in one step. */
export const redactFirstUseDevice = (
  device: DeviceWithSecrets | FirstUseDeviceWithSecrets
): FirstUseDevice => {
  const { userId: _userId, ...rest } = device as DeviceWithSecrets
  return { ...rest, keys: redactKeys(rest.keys) }
}
