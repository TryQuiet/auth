import type { Signer } from '@localfirst/crdx'
import type { DeviceWithSecrets } from 'device/index.js'
import { SignerKind } from './types.js'

/**
 * The signer a member's device authors links with.
 *
 * Members author as devices, not as users: a user's keys rotate, so a signature made with them
 * can't be verified against a permanent identity, and a user isn't a thing that holds keys anyway —
 * its devices are. `device.keys` never rotate, and `deviceId` is their fingerprint, so a link's
 * signature is checkable against the device's registration for the life of the team.
 */
export const deviceSigner = (device: DeviceWithSecrets): Signer => ({
  info: { kind: SignerKind.DEVICE, id: device.deviceId },
  keys: device.keys,
})
