import * as auth from '@localfirst/auth'
import { arrayToMap } from './util/arrayToMap.js'

export const devices = {
  laptop: { name: 'laptop', emoji: '💻' },
  phone: { name: 'phone', emoji: '📱' },
} as Record<string, DeviceInfo>

export function deviceSeed(userName: string, deviceName: string) {
  return `${userName}:${deviceName}`
}

export const users = {
  Alice: createUserInfo('Alice', '👩🏾'),
  Bob: createUserInfo('Bob', '👨🏻‍🦲'),
  Charlie: createUserInfo('Charlie', '👳🏽‍♂️'),
  Dwight: createUserInfo('Dwight', '👴'),
  Eve: createUserInfo('Eve', '🦹‍♀️'),
} as Record<string, UserInfo>

/** Derives each demo user's stable id from the stable laptop that founds that identity. */
function createUserInfo(userName: string, emoji: string): UserInfo {
  const foundingDevice = auth.createFirstUseDevice({
    deviceName: devices.laptop.name,
    seed: deviceSeed(userName, devices.laptop.name),
  })

  return { userName, userId: auth.deriveUserId(foundingDevice.deviceId), emoji }
}

const peerArray = Object.values(users).flatMap(user =>
  Object.values(devices).map(
    device =>
      ({
        user,
        device,
        id: `${user.userName}:${device.name}`,
        show: false,
      }) as PeerInfo
  )
)

export const peers = peerArray.reduce(arrayToMap('id'), {}) as PeerMap

export type PeerInfo = {
  id: string
  user: UserInfo
  device: DeviceInfo
  show: boolean
}

export type PeerMap = Record<string, PeerInfo>

export type DeviceInfo = {
  name: string
  emoji: string
}

export type UserInfo = {
  userId: string
  userName: string
  emoji: string
}
