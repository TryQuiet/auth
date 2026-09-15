import { createKeyset } from '@localfirst/crdx'
import { base58 } from '@localfirst/crypto'
import { create, isKeyManifest } from 'lockbox/index.js'
import { snapshotLockbox, snapshotLockboxes } from 'lockbox/snapshot.js'
import { lockboxesInScope } from 'team/selectors/lockboxesInScope.js'
import { type TeamState } from 'team/types.js'
import { describe, expect, it, vi } from 'vitest'

const box = () =>
  create(
    createKeyset({ type: 'ROLE', name: 'member' }),
    createKeyset({ type: 'DEVICE', name: 'phone' })
  )

describe('owned manifest structural validation', () => {
  it('decodes each immutable manifest once while still selecting the requested scope', () => {
    const member = box()
    const other = create(
      createKeyset({ type: 'ROLE', name: 'other' }),
      createKeyset({ type: 'DEVICE', name: 'phone' })
    )
    const state = { lockboxes: snapshotLockboxes([member, other]) } as TeamState
    const decode = vi.spyOn(base58, 'decode')
    try {
      for (let i = 0; i < 1000; i++) {
        expect(lockboxesInScope(state, { type: 'ROLE', name: 'member' })).toEqual([
          state.lockboxes[0],
        ])
        expect(lockboxesInScope(state, { type: 'ROLE', name: 'other' })).toEqual([
          state.lockboxes[1],
        ])
        expect(lockboxesInScope(state, { type: 'ROLE', name: 'unknown' })).toEqual([])
      }
      expect(decode).toHaveBeenCalledTimes(4)
    } finally {
      decode.mockRestore()
    }
  })

  it.each([
    ['type', ''],
    ['name', ''],
    ['generation', -1],
    ['version', 0],
    ['publicKey', 'invalid'],
    ['commitment', 'invalid'],
    ['extra', true],
  ])('rechecks changed caller-owned %s after a successful validation', (field, value) => {
    const manifest = box().contents
    expect(isKeyManifest(manifest)).toBe(true)
    Object.assign(manifest, { [field]: value })
    expect(isKeyManifest(manifest)).toBe(false)
  })

  it('does not trust frozen caller-owned accessors after an earlier successful check', () => {
    const original = box().contents
    let { publicKey } = original
    const manifest = Object.freeze({
      ...original,
      get publicKey() {
        return publicKey
      },
    })
    expect(isKeyManifest(manifest)).toBe(true)
    publicKey = '' as typeof publicKey
    expect(isKeyManifest(manifest)).toBe(false)
  })

  it('does not extend cache eligibility to arbitrary frozen clones', () => {
    const manifest = Object.freeze({ ...box().contents })
    const decode = vi.spyOn(base58, 'decode')
    try {
      expect(isKeyManifest(manifest)).toBe(true)
      expect(isKeyManifest(manifest)).toBe(true)
      expect(decode).toHaveBeenCalledTimes(4)
    } finally {
      decode.mockRestore()
    }
  })

  it('protects owned snapshots against aliases and never promotes invalid snapshots', () => {
    const original = box()
    const snapshot = snapshotLockbox(original)
    expect(isKeyManifest(snapshot.contents)).toBe(true)
    original.contents.name = ''
    expect(isKeyManifest(original.contents)).toBe(false)
    expect(isKeyManifest(snapshot.contents)).toBe(true)
    expect(() => {
      snapshot.contents.name = ''
    }).toThrow()
    const invalid = snapshotLockbox(original)
    expect(isKeyManifest(invalid.contents)).toBe(false)
    expect(isKeyManifest(invalid.contents)).toBe(false)
  })
})
