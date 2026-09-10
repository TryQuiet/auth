import { createKeyset } from '@localfirst/crdx'
import { asymmetric } from '@localfirst/crypto'
import { cloneDeep } from 'lodash-es'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { create, keysetCommitment } from 'lockbox/index.js'
import { initialState } from 'team/constants.js'
import { keyMap } from '../keyMap.js'

const fixture = () => {
  const deviceKeys = createKeyset({ type: 'DEVICE', name: 'device' })
  const roleKeys = createKeyset({ type: 'ROLE', name: 'member' })
  const box = create(roleKeys, deviceKeys)
  return { deviceKeys, roleKeys, box, state: { ...initialState, lockboxes: [box] } }
}

afterEach(() => {
  vi.restoreAllMocks()
})

describe('key map caching', () => {
  it('reuses resolved keys without opening lockboxes again, including copied device keys', () => {
    const { deviceKeys, roleKeys, state } = fixture()
    const decrypt = vi.spyOn(asymmetric, 'decryptBytes')
    expect(keyMap(state, deviceKeys).ROLE.member[0]).toEqual(roleKeys)
    expect(decrypt).toHaveBeenCalled()
    decrypt.mockClear()
    const second = keyMap(state, cloneDeep(deviceKeys))
    expect(second.ROLE.member[0]).toEqual(roleKeys)
    expect(decrypt).not.toHaveBeenCalled()
    expect(Object.getPrototypeOf(second)).toBeNull()
    expect(Object.getPrototypeOf(second.ROLE)).toBeNull()
  })

  it('does not let callers poison cached maps or nested keysets', () => {
    const { deviceKeys, roleKeys, state } = fixture()
    const first = keyMap(state, deviceKeys)
    first.ROLE.member[0].encryption.secretKey = deviceKeys.encryption.secretKey
    first.ROLE.member.length = 0
    const second = keyMap(state, deviceKeys)
    expect(second.ROLE.member).toEqual([roleKeys])
    second.ROLE.member[0].signature.publicKey = deviceKeys.signature.publicKey
    expect(keyMap(state, deviceKeys).ROLE.member).toEqual([roleKeys])
  })

  it.each(['manifest', 'recipient', 'ciphertext', 'extra field'])(
    'rechecks an in-place %s mutation after a successful lookup',
    kind => {
      const { deviceKeys, roleKeys, box, state } = fixture()
      expect(keyMap(state, deviceKeys).ROLE.member).toEqual([roleKeys])
      if (kind === 'manifest') box.contents.commitment = keysetCommitment(deviceKeys)
      if (kind === 'recipient') box.recipient.name = 'different-device'
      if (kind === 'ciphertext') box.encryptedPayload[0] ^= 1
      if (kind === 'extra field') Object.assign(box.contents, { unexpected: undefined })
      expect(keyMap(state, deviceKeys).ROLE).toBeUndefined()
    }
  )

  it('copies Buffer ciphertext rather than retaining a shared byte view', () => {
    const { deviceKeys, roleKeys, box, state } = fixture()
    box.encryptedPayload = Buffer.from(box.encryptedPayload)
    expect(keyMap(state, deviceKeys).ROLE.member).toEqual([roleKeys])
    box.encryptedPayload[0] ^= 1
    expect(keyMap(state, deviceKeys).ROLE).toBeUndefined()
  })

  it('invalidates for changed decryption keys and never shares another device access', () => {
    const { deviceKeys, roleKeys, state } = fixture()
    expect(keyMap(state, deviceKeys).ROLE.member).toEqual([roleKeys])
    const other = createKeyset({ type: 'DEVICE', name: 'other' })
    expect(keyMap(state, other).ROLE).toBeUndefined()
    expect(keyMap(state, deviceKeys).ROLE.member).toEqual([roleKeys])
    deviceKeys.encryption.secretKey = other.encryption.secretKey
    expect(() => keyMap(state, deviceKeys)).toThrow()
  })

  it('rebuilds after lockbox addition, removal and generation rotation', () => {
    const { deviceKeys, roleKeys, state } = fixture()
    keyMap(state, deviceKeys)
    const rotated = { ...createKeyset({ type: 'ROLE', name: 'member' }), generation: 1 }
    state.lockboxes.push(create(rotated, deviceKeys))
    expect(keyMap(state, deviceKeys).ROLE.member).toEqual([roleKeys, rotated])
    state.lockboxes = []
    expect(keyMap(state, deviceKeys).ROLE).toBeUndefined()
    const nextState = { ...state, lockboxes: [create(roleKeys, deviceKeys)] }
    expect(keyMap(nextState, deviceKeys).ROLE.member).toEqual([roleKeys])
  })
})
