// ignore file coverage
import type { DeviceWithSecrets, FirstUseDeviceWithSecrets } from 'device/index.js'
import { deriveId, generateProof } from 'invitation/index.js'
import {
  deviceClaim,
  devicePossessionProof,
  invitationNonces,
  memberClaim,
  memberPossessionProof,
  type UserStuff,
} from 'util/testing/index.js'

/**
 * Everything an invitee hands over to be admitted: proof that they know the invitation seed, the
 * identity that proof was signed over, and the new device's own signature over that identity.
 *
 * Spread these straight into `team.admitMember(...)` / `team.admitDevice(...)`.
 */
export const memberAdmission = (seed: string, user: UserStuff) => {
  const claim = memberClaim(user.user, user.device)
  return [
    generateProof({ seed, claim, ...invitationNonces() }),
    claim,
    memberPossessionProof(deriveId(seed), user.user, user.device),
  ] as const
}

export const deviceAdmission = (
  seed: string,
  device: DeviceWithSecrets | FirstUseDeviceWithSecrets
) => {
  const claim = deviceClaim(device)
  return [
    generateProof({ seed, claim, ...invitationNonces() }),
    claim,
    devicePossessionProof(deriveId(seed), device),
  ] as const
}
