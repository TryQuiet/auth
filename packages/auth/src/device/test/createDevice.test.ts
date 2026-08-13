import { createKeyset } from '@localfirst/crdx'
import { randomKey } from '@localfirst/crypto'
import { describe, expect, test } from 'vitest'
import {
  createDevice,
  createFirstUseDevice,
  deviceIdentityIsValid,
  redactDevice,
  redactFirstUseDevice,
  toFirstUseDevice,
  toOwnedDevice,
} from 'device/index.js'
import { KeyType, signerIdFromKeys } from 'util/index.js'

const alice = { userId: 'alice', deviceName: 'laptop' }

describe('createDevice', () => {
  test('the deviceId is the fingerprint of the public signature key', () => {
    const device = createDevice(alice)
    expect(device.deviceId).toBe(signerIdFromKeys(device.keys))
    expect(redactDevice(device).deviceId).toBe(signerIdFromKeys(device.keys))
  })

  test('the keyset is named for the deviceId', () => {
    const device = createDevice(alice)
    expect(device.keys.name).toBe(device.deviceId)
    expect(device.keys.type).toBe(KeyType.DEVICE)
    expect(device.keys.generation).toBe(0)
  })

  test('a device passes its own identity check', () => {
    expect(deviceIdentityIsValid(createDevice(alice))).toBe(true)
    expect(deviceIdentityIsValid(redactDevice(createDevice(alice)))).toBe(true)
  })

  test('the identity depends only on the seed', () => {
    const seed = randomKey()
    const laptop = createDevice({ userId: 'alice', deviceName: 'laptop', seed })

    // Nothing but the seed feeds the derivation — not the device name, not the user, not the id.
    const sameKeys = createDevice({ userId: 'bob', deviceName: 'phone', seed })
    expect(sameKeys.deviceId).toBe(laptop.deviceId)
    expect(sameKeys.keys).toEqual(laptop.keys)

    const otherKeys = createDevice({ ...alice, seed: randomKey() })
    expect(otherKeys.deviceId).not.toBe(laptop.deviceId)
  })

  test('a first-use device has an id but no owner', () => {
    const device = createFirstUseDevice({ deviceName: 'laptop' })
    expect(device).not.toHaveProperty('userId')
    expect(deviceIdentityIsValid(device)).toBe(true)

    const owned = toOwnedDevice(redactFirstUseDevice(device), 'alice')
    expect(owned.userId).toBe('alice')
    expect(owned.deviceId).toBe(device.deviceId)
    expect(toFirstUseDevice(owned)).toEqual(redactFirstUseDevice(device))
  })
})

describe('deviceIdentityIsValid', () => {
  const device = redactDevice(createDevice(alice))

  test('rejects an id that is not the fingerprint of the signature key', () => {
    const impostor = redactDevice(createDevice({ userId: 'eve', deviceName: 'laptop' }))

    // Eve claims Alice's deviceId while keeping her own keys...
    expect(deviceIdentityIsValid({ ...impostor, deviceId: device.deviceId })).toBe(false)

    // ...and renaming her keyset to match doesn't help, because the id commits to the key itself.
    expect(
      deviceIdentityIsValid({
        deviceId: device.deviceId,
        keys: { ...impostor.keys, name: device.deviceId },
      })
    ).toBe(false)
  })

  test('rejects a keyset that is not a device keyset', () => {
    const userKeys = createKeyset({ type: KeyType.USER, name: 'alice' })
    expect(
      deviceIdentityIsValid({ deviceId: signerIdFromKeys(userKeys), keys: userKeys })
    ).toBe(false)
  })

  test('rejects a keyset past generation 0', () => {
    expect(deviceIdentityIsValid({ ...device, keys: { ...device.keys, generation: 1 } })).toBe(false)
  })

  test('rejects a keyset whose name is not the deviceId', () => {
    expect(deviceIdentityIsValid({ ...device, keys: { ...device.keys, name: 'laptop' } })).toBe(
      false
    )
  })
})
