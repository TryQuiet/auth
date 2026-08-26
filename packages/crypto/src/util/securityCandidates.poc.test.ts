import { describe, expect, it, vi } from 'vitest'
import { base58 } from './base58.js'
import { isBase58KeyOfLength } from '../keypairValidation.js'

describe('security candidate PoCs: base58 validation', () => {
  it('decodes an oversized Base58 value before rejecting its decoded length', () => {
    const decode = vi.spyOn(base58, 'decode')
    const oversized = '1'.repeat(100_000)

    try {
      expect(isBase58KeyOfLength(oversized, 32)).toBe(false)
      expect(decode).toHaveBeenCalledWith(oversized)
    } finally {
      decode.mockRestore()
    }
  })
})
