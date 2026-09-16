import * as crypto from '@localfirst/crypto'
import { decryptGraph } from '@localfirst/crdx'
import { unpack } from 'msgpackr'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { removeMemberRole } from 'team/transforms/removeMemberRole.js'
import { type TeamAction, type TeamContext } from 'team/types.js'
import { setup } from 'util/testing/index.js'

afterEach(() => {
  vi.restoreAllMocks()
})

const privateTeam = () => {
  const { alice, bob } = setup('alice', { user: 'bob', admin: false })
  alice.team.addRole('private')
  alice.team.addMemberRole(bob.userId, 'private')
  bob.team.merge(alice.team.graph)
  return { alice, bob }
}

describe('messages using team-owned checked keys', () => {
  it('decrypts 1,000 messages without reopening or rechecking keys, and verifies every signature', () => {
    const { alice, bob } = privateTeam()
    const messages = Array.from({ length: 1000 }, (_, n) => {
      const signed = alice.team.sign(`message ${n}`)
      return { signed, encrypted: alice.team.encrypt(signed.contents, 'private') }
    })
    bob.team.roleKeys('private')
    const decrypt = vi.spyOn(crypto.asymmetric, 'decryptBytes')
    const signatureKeys = vi.spyOn(crypto, 'isValidSignatureKeypair')
    const encryptionKeys = vi.spyOn(crypto, 'isValidEncryptionKeypair')
    const hash = vi.spyOn(crypto, 'hash')
    const verify = vi.spyOn(crypto.signatures, 'verify')
    for (const { signed, encrypted } of messages) {
      const contents = bob.team.decrypt(encrypted)
      expect(contents).toEqual(signed.contents)
      expect(bob.team.verify({ ...signed, contents })).toBe(true)
    }
    expect(decrypt).not.toHaveBeenCalled()
    expect(signatureKeys).not.toHaveBeenCalled()
    expect(encryptionKeys).not.toHaveBeenCalled()
    expect(hash).not.toHaveBeenCalled()
    expect(verify).toHaveBeenCalledTimes(1000)
    expect(bob.team.verify({ ...messages[0].signed, contents: 'forged' })).toBe(false)
    const tampered = {
      ...messages[0].encrypted,
      contents: new Uint8Array(messages[0].encrypted.contents),
    }
    tampered.contents[0] ^= 1 // eslint-disable-line no-bitwise
    expect(() => bob.team.decrypt(tampered)).toThrow()
  })

  it('retains keys across a serialized edition but removes selection when role access is removed', () => {
    const { alice, bob } = privateTeam()
    const message = alice.team.encrypt('private message', 'private')
    expect(bob.team.decrypt(message)).toBe('private message')
    const original = bob.team.roleKeys('private')
    alice.team.addMessage({ text: 'new edition' })
    const edition = decryptGraph<TeamAction, TeamContext>({
      encryptedGraph: unpack(alice.team.save()),
      keys: bob.team.teamKeyring(),
    })
    bob.team.merge(edition)
    expect(bob.team.roleKeys('private')).toBe(original)
    expect(bob.team.decrypt(message)).toBe('private message')
    // Protocol 4 gates removal dispatch; exercise its actual retained transform on the same Team.
    bob.team.state = removeMemberRole(bob.userId, 'private')(bob.team.state)
    expect(() => bob.team.roleKeys('private')).toThrow()
    expect(() => bob.team.decrypt(message)).toThrow()
  })

  it('owns its default recipient and rejects a mutated explicit recipient', () => {
    const { alice, bob } = privateTeam()
    const message = alice.team.encrypt('private message', 'private')
    expect(bob.team.decrypt(message)).toBe('private message')
    const raw = bob.localContext.device.keys
    const saved = raw.encryption.secretKey
    try {
      raw.encryption.secretKey = alice.localContext.device.keys.encryption.secretKey
      expect(bob.team.decrypt(message)).toBe('private message')
      expect(() => bob.team.roleKeys('private', undefined, raw)).toThrow()
    } finally {
      raw.encryption.secretKey = saved
    }
  })
})
