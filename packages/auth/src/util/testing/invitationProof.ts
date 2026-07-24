import { redactKeys, type UserWithSecrets } from '@localfirst/crdx'
import { randomKey, type Base58 } from '@localfirst/crypto'
import {
  redactDevice,
  type FirstUseDevice,
  type DeviceWithSecrets,
} from 'device/index.js'
import {
  generateProof,
  type DeviceInvitationClaim,
  type MemberInvitationClaim,
} from 'invitation/index.js'

export const memberInvitationProof = (
  seed: string,
  user: Pick<UserWithSecrets, 'userName' | 'keys'>,
  device: DeviceWithSecrets,
  nonces = invitationNonces()
) => {
  const claim: MemberInvitationClaim = {
    invitationKind: 'member',
    userName: user.userName,
    userKeys: redactKeys(user.keys),
    device: redactDevice(device),
  }
  return generateProof({ seed, claim, ...nonces })
}

export const deviceInvitationProof = (
  seed: string,
  userName: string,
  device: DeviceWithSecrets,
  nonces = invitationNonces()
) => {
  const firstUseDevice = redactFirstUseDevice(device)
  const claim: DeviceInvitationClaim = {
    invitationKind: 'device',
    userName,
    device: firstUseDevice,
  }
  return generateProof({ seed, claim, ...nonces })
}

export const redactFirstUseDevice = (device: DeviceWithSecrets): FirstUseDevice => {
  const { userId: _userId, ...firstUseDevice } = redactDevice(device)
  return firstUseDevice
}

export const invitationNonces = (): {
  acceptorNonce: Base58
  inviteeNonce: Base58
} => ({
  acceptorNonce: randomKey(),
  inviteeNonce: randomKey(),
})
