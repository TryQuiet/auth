import { createFirstUseDevice } from 'device/index.js'
import { describe, expect, it } from 'vitest'
import { deriveUserId } from '../userId.js'

describe('deriveUserId', () => {
  it('is deterministic — the same device always derives the same userId', () => {
    const { deviceId } = createFirstUseDevice({ deviceName: 'laptop', seed: 'a-device' })
    expect(deriveUserId(deviceId)).toBe(deriveUserId(deviceId))
  })

  it('never equals the deviceId it is derived from (domain separation)', () => {
    // A deviceId is a fingerprint under one hash domain; a userId is a hash of that id under a
    // different domain, so the two can never collide — which is what keeps member ids and device
    // ids in one namespace without a global uniqueness scan.
    const { deviceId } = createFirstUseDevice({ deviceName: 'laptop', seed: 'b-device' })
    expect(deriveUserId(deviceId)).not.toBe(deviceId)
  })

  it('derives distinct userIds for distinct devices', () => {
    const a = createFirstUseDevice({ deviceName: 'laptop', seed: 'device-a' })
    const b = createFirstUseDevice({ deviceName: 'laptop', seed: 'device-b' })
    expect(a.deviceId).not.toBe(b.deviceId)
    expect(deriveUserId(a.deviceId)).not.toBe(deriveUserId(b.deviceId))
  })
})
