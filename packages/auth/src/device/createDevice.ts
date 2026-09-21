import { createKeyset, type UnixTimestamp } from '@localfirst/crdx'
import { randomKey } from '@localfirst/crypto'
import type { DeviceWithSecrets, FirstUseDeviceWithSecrets } from './types.js'
import { KeyType, signerIdFromKeys } from 'util/index.js'

/**
 * Fixed derivation label for device keysets. The label must never depend on the device's id or
 * name: the id is derived *from* the keys, so anything that fed the id back into the derivation
 * would be circular.
 */
const DEVICE_KEY_SCOPE = { type: KeyType.DEVICE, name: KeyType.DEVICE } as const

/**
 * Creates a device that doesn't yet know which user it belongs to. A device invitation only tells
 * the invitee the invitation seed; the owning `userId` comes from the invitation record on the team
 * graph, so an invitee's device keys have to exist before its owner is known.
 */
export const createFirstUseDevice = ({
  deviceName,
  deviceInfo = {},
  created = Date.now() as UnixTimestamp,
  seed = randomKey(),
}: FirstUseParams): FirstUseDeviceWithSecrets => {
  const derivedKeys = createKeyset(DEVICE_KEY_SCOPE, seed)

  // The device's id is the fingerprint of its own public signature key, which makes it
  // self-certifying: a validator recomputes it from the registered keyset rather than trusting the
  // claimed id. The keyset is then renamed to that id so the keys and the id commit to each other.
  const deviceId = signerIdFromKeys(derivedKeys)
  const keys = { ...derivedKeys, name: deviceId }

  return { deviceId, deviceName, keys, created, deviceInfo }
}

/**
 * Creates a device belonging to a known user. Devices created from the same seed are the same
 * device: the seed determines the keys, and the keys determine the id.
 */
export const createDevice = ({ userId, ...params }: Params): DeviceWithSecrets => ({
  userId,
  ...createFirstUseDevice(params),
})

type FirstUseParams = {
  deviceName: string
  deviceInfo?: any
  created?: UnixTimestamp
  seed?: string
}

type Params = FirstUseParams & {
  userId: string
}
