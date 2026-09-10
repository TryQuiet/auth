import type { Keyset, KeysetWithSecrets, UnixTimestamp } from '@localfirst/crdx'

export type DeviceInfo = {
  /** The user this device belongs to. A device invitation supplies this from the invitation record
   * on the team graph, not from the device itself. */
  userId: string

  /** Self-certifying identifier: the fingerprint of the device's public signature key
   * (`signerIdFromKeys(keys)`), and also `keys.name`. Every validator recomputes it, so a device
   * can't claim an id that doesn't belong to its keys. Device keys never rotate, so this id is
   * permanent. */
  deviceId: string

  /** Human-readable label. Never used for lookups or authorization. */
  deviceName: string

  deviceInfo?: any
  created?: UnixTimestamp
}

export type DeviceWithSecrets = {
  keys: KeysetWithSecrets
} & DeviceInfo

export type Device = {
  keys: Keyset
} & DeviceInfo

/** A device that has been created but not yet linked to a user — see `createFirstUseDevice`. */
export type FirstUseDeviceWithSecrets = Omit<DeviceWithSecrets, 'userId'>
export type FirstUseDevice = Omit<Device, 'userId'>
