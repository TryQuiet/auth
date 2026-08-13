import { redactKeys, type UserWithSecrets } from '@localfirst/crdx'
import { randomKey, type Base58 } from '@localfirst/crypto'
import {
  redactDevice,
  redactFirstUseDevice,
  type DeviceWithSecrets,
  type FirstUseDeviceWithSecrets,
} from 'device/index.js'
import {
  createPossessionProof,
  generateProof,
  type DeviceInvitationClaim,
  type MemberInvitationClaim,
} from 'invitation/index.js'

type InvitationNonces = {
  acceptorNonce: Base58
  inviteeNonce: Base58
}

export const invitationNonces = (): InvitationNonces => ({
  acceptorNonce: randomKey() as Base58,
  inviteeNonce: randomKey() as Base58,
})

export const memberClaim = (
  user: Pick<UserWithSecrets, 'userName' | 'keys'>,
  device: DeviceWithSecrets
): MemberInvitationClaim => ({
  invitationKind: 'member',
  userName: user.userName,
  memberKeys: redactKeys(user.keys),
  device: redactDevice(device),
})

export const deviceClaim = (
  device: DeviceWithSecrets | FirstUseDeviceWithSecrets
): DeviceInvitationClaim => ({
  invitationKind: 'device',
  device: redactFirstUseDevice(device),
})

export const memberInvitationProof = (
  seed: string,
  user: Pick<UserWithSecrets, 'userName' | 'keys'>,
  device: DeviceWithSecrets,
  nonces = invitationNonces()
) => generateProof({ seed, claim: memberClaim(user, device), ...nonces })

export const deviceInvitationProof = (
  seed: string,
  device: DeviceWithSecrets | FirstUseDeviceWithSecrets,
  nonces = invitationNonces()
) => generateProof({ seed, claim: deviceClaim(device), ...nonces })

export const memberPossessionProof = (
  invitationId: Base58,
  user: Pick<UserWithSecrets, 'userName' | 'keys'>,
  device: DeviceWithSecrets
) => createPossessionProof({ invitationId, claim: memberClaim(user, device), device })

export const devicePossessionProof = (
  invitationId: Base58,
  device: DeviceWithSecrets | FirstUseDeviceWithSecrets
) => createPossessionProof({ invitationId, claim: deviceClaim(device), device })
