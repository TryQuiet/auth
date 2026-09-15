import { createKeyset } from '@localfirst/crdx'
import { isValidKeyset } from 'lockbox/validateKeyset.js'
import { keysetCommitment } from 'lockbox/keysetCommitment.js'
import { describe, expect, it } from 'vitest'

describe('complete keyset validation cache identity', () => {
  it.each([
    'signature secret',
    'signature public',
    'symmetric secret',
    'generation',
    'name',
    'type',
    'extra field',
  ])('rejects invalid %s mutation after successful cached validation', field => {
    const keys = createKeyset({ type: 'DEVICE', name: 'phone' })
    const other = createKeyset({ type: 'DEVICE', name: 'other' })
    expect(isValidKeyset(keys)).toBe(true)
    expect(isValidKeyset(keys)).toBe(true)
    switch (field) {
      case 'signature secret': {
        keys.signature.secretKey = other.signature.secretKey
        break
      }
      case 'signature public': {
        keys.signature.publicKey = other.signature.publicKey
        break
      }
      case 'symmetric secret': {
        keys.secretKey = ''
        break
      }
      case 'generation': {
        keys.generation = -1
        break
      }
      case 'name': {
        keys.name = ''
        break
      }
      case 'type': {
        keys.type = ''
        break
      }
      case 'extra field': {
        Object.assign(keys, { unexpected: true })
        break
      }
    }
    expect(isValidKeyset(keys)).toBe(false)
  })

  it('rechecks accessor replacements on every call', () => {
    const keys = createKeyset({ type: 'DEVICE', name: 'phone' })
    expect(isValidKeyset(keys)).toBe(true)
    let secret = keys.secretKey
    Object.defineProperty(keys, 'secretKey', { enumerable: true, get: () => secret })
    expect(isValidKeyset(keys)).toBe(true)
    secret = ''
    expect(isValidKeyset(keys)).toBe(false)
  })

  it('validates legitimate changed material but commits to the changed value', () => {
    const keys = createKeyset({ type: 'DEVICE', name: 'phone' })
    const before = keysetCommitment(keys)
    keys.secretKey = createKeyset({ type: 'DEVICE', name: 'other' }).secretKey
    expect(isValidKeyset(keys)).toBe(true)
    const changedSecret = keysetCommitment(keys)
    expect(changedSecret).not.toBe(before)
    keys.generation = 1
    expect(isValidKeyset(keys)).toBe(true)
    expect(keysetCommitment(keys)).not.toBe(changedSecret)
  })
})
