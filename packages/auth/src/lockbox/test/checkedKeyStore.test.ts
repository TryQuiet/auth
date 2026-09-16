import { createKeyset } from '@localfirst/crdx'
import * as crypto from '@localfirst/crypto'
import { pack, unpack } from 'msgpackr'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { CheckedKeyStore } from 'lockbox/CheckedKeyStore.js'
import { create, open, type Lockbox } from 'lockbox/index.js'
import { snapshotLockboxes } from 'lockbox/snapshot.js'

afterEach(() => {
  vi.restoreAllMocks()
  vi.unstubAllGlobals()
})

const fixture = () => {
  const store = new CheckedKeyStore()
  const recipient = createKeyset({ type: 'DEVICE', name: 'phone' })
  const role = createKeyset({ type: 'ROLE', name: 'private' })
  return { store, recipient, role, box: create(role, recipient) }
}
const copy = <T>(value: T): T => unpack(pack(value)) as T

describe('checked key material owned by a team', () => {
  it('preserves standalone open as a caller-owned result', () => {
    const { box, recipient, role } = fixture()
    const opened = open(box, recipient)
    opened.name = 'changed'
    opened.encryption.secretKey = recipient.encryption.secretKey
    expect(open(box, recipient)).toEqual(role)
  })

  it('checks imported material once and owns every returned field', () => {
    const { store, recipient } = fixture()
    const signature = vi.spyOn(crypto, 'isValidSignatureKeypair')
    const encryption = vi.spyOn(crypto, 'isValidEncryptionKeypair')
    const owned = store.import(recipient)
    expect(owned).toEqual(recipient)
    expect(owned).not.toBe(recipient)
    expect(owned.encryption).not.toBe(recipient.encryption)
    expect(owned.signature).not.toBe(recipient.signature)
    for (let n = 0; n < 1000; n++) expect(store.import(owned)).toBe(owned)
    expect(signature).toHaveBeenCalledTimes(1)
    expect(encryption).toHaveBeenCalledTimes(1)
    expect(() => {
      owned.signature.secretKey = recipient.encryption.secretKey
    }).toThrow()
    recipient.signature.secretKey = recipient.encryption.secretKey
    expect(() => store.import(recipient)).toThrow()
    expect(store.import(owned)).toBe(owned)
  })

  it('snapshots accessor inputs and rechecks later imports of the caller object', () => {
    const { store, recipient } = fixture()
    let { name } = recipient
    Object.defineProperty(recipient, 'name', { enumerable: true, get: () => name })
    Object.freeze(recipient)
    const owned = store.import(recipient)
    name = ''
    expect(owned.name).toBe('phone')
    expect(() => store.import(recipient)).toThrow()
    expect(store.import(owned)).toBe(owned)
  })

  it('retains a checked delivery across reconstructed collections without WeakRef', () => {
    const { store, recipient, role, box } = fixture()
    const owned = store.import(recipient)
    vi.stubGlobal('WeakRef', undefined)
    const decrypt = vi.spyOn(crypto.asymmetric, 'decryptBytes')
    const signature = vi.spyOn(crypto, 'isValidSignatureKeypair')
    const encryption = vi.spyOn(crypto, 'isValidEncryptionKeypair')
    for (let n = 0; n < 100; n++) {
      const lockboxes = snapshotLockboxes([copy(box)])
      expect(store.keyMap(lockboxes, owned).ROLE.private[0]).toEqual(role)
    }
    expect(decrypt).toHaveBeenCalledTimes(1)
    expect(signature).toHaveBeenCalledTimes(1)
    expect(encryption).toHaveBeenCalledTimes(1)
  })

  it.each([
    'ciphertext',
    'sender',
    'recipient name',
    'recipient public key',
    'contents name',
    'contents generation',
    'contents commitment',
    'contents extra field',
  ])('rejects changed %s after warming the delivery', field => {
    const { store, recipient, box } = fixture()
    const owned = store.import(recipient)
    const expected = store.open(box, owned)
    const changed = copy(box)
    const other = createKeyset({ type: 'ROLE', name: 'other' })
    switch (field) {
      case 'ciphertext': {
        changed.encryptedPayload[0] ^= 1 // eslint-disable-line no-bitwise
        break
      }
      case 'sender': {
        changed.encryptionKey.publicKey = other.encryption.publicKey
        break
      }
      case 'recipient name': {
        changed.recipient.name = 'other'
        break
      }
      case 'recipient public key': {
        changed.recipient.publicKey = other.encryption.publicKey
        break
      }
      case 'contents name': {
        changed.contents.name = 'other'
        break
      }
      case 'contents generation': {
        changed.contents.generation++
        break
      }
      case 'contents commitment': {
        changed.contents.commitment = create(other, recipient).contents.commitment
        break
      }
      case 'contents extra field': {
        Object.assign(changed.contents, { extra: true })
        break
      }
    }
    expect(() => store.open(changed, owned)).toThrow()
    expect(store.open(box, owned)).toBe(expected)
  })

  it('checks different ciphertext even when it advertises an already checked commitment', () => {
    const { store, recipient, role, box } = fixture()
    const owned = store.import(recipient)
    const expected = store.open(box, owned)
    const other = createKeyset({ type: role.type, name: role.name })
    const forged = create({ ...role, secretKey: other.secretKey }, recipient)
    forged.contents = { ...box.contents }
    expect(() => store.open(forged, owned)).toThrow('do not match its manifest')
    expect(store.keyMap(snapshotLockboxes([forged]), owned).ROLE).toBeUndefined()
    // A previously rejected delivery can be repaired and must be evaluated again.
    forged.contents = create({ ...role, secretKey: other.secretKey }, recipient).contents
    expect(store.open(forged, owned).secretKey).toBe(other.secretKey)
    expect(store.open(box, owned)).toBe(expected)
  })

  it('binds recipient imports to the full keyset and isolates separate stores', () => {
    const { store, recipient, box } = fixture()
    const expected = store.open(box, recipient)
    const other = createKeyset({ type: recipient.type, name: recipient.name })
    const corrupt = copy(recipient)
    corrupt.signature.secretKey = other.signature.secretKey
    expect(() => store.open(box, corrupt)).toThrow()
    expect(() => store.open(box, other)).toThrow()
    const decrypt = vi.spyOn(crypto.asymmetric, 'decryptBytes')
    expect(store.open(box, { ...recipient, secretKey: other.secretKey })).toEqual(expected)
    expect(decrypt).toHaveBeenCalledTimes(1)
    expect(new CheckedKeyStore().open(box, recipient)).toEqual(expected)
    expect(decrypt).toHaveBeenCalledTimes(2)
  })

  it('selects each branch independently despite retained keys, cycles, and conflicting generations', () => {
    const { store, recipient, role, box } = fixture()
    const owned = store.import(recipient)
    const rotated = { ...createKeyset({ type: role.type, name: role.name }), generation: 1 }
    const conflict = createKeyset({ type: role.type, name: role.name })
    const base = snapshotLockboxes([box, create(role, role)])
    const left = snapshotLockboxes([...base, create(rotated, recipient)])
    const right = snapshotLockboxes([create(conflict, recipient)])
    expect(store.keyMap(left, owned).ROLE.private).toEqual([role, rotated])
    expect(store.keyMap(right, owned).ROLE.private).toEqual([conflict])
    expect(store.keyMap(snapshotLockboxes([]), owned).ROLE).toBeUndefined()
    expect(store.keyMap(base, owned).ROLE.private).toEqual([role])
    const duplicates: Lockbox[] = [...base, create(conflict, recipient), copy(box)]
    expect(store.keyMap(snapshotLockboxes(duplicates), owned).ROLE.private).toEqual([role])
  })
})
