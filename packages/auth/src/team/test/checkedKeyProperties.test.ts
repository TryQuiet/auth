import { Buffer } from 'node:buffer'
import { createKeyring } from '@localfirst/crdx'
import * as crypto from '@localfirst/crypto'
import { pack, unpack } from 'msgpackr'
import { afterEach, describe, expect, it, vi } from 'vitest'
import * as teams from 'team/index.js'
import { setup } from 'util/testing/index.js'
import { forge } from './forgeHelpers.js'

afterEach(() => {
  vi.restoreAllMocks()
})

/** Every secret key held by the given keysets, as strings we can search for. */
const secretsOf = (...keysets: Array<Record<string, any>>) =>
  keysets.flatMap(keys => [keys.secretKey, keys.encryption.secretKey, keys.signature.secretKey])

const privateTeam = () => {
  const { alice, bob } = setup('alice', { user: 'bob', admin: false })
  const beforeGrant = alice.team.save()
  alice.team.addRole('private')
  alice.team.addMemberRole(bob.userId, 'private')
  bob.team.merge(alice.team.graph)
  return { alice, bob, beforeGrant }
}

describe('security properties of team-owned checked keys', () => {
  it('cannot select a retained role key from a real branch whose lockboxes never delivered it', () => {
    const { alice, bob, beforeGrant } = privateTeam()
    const message = alice.team.encrypt('private message', 'private')
    expect(bob.team.decrypt(message)).toBe('private message')
    const retained = bob.team.roleKeys('private')

    // A concurrent branch of the same team, forked from before the grant, that never contains the
    // role delivery. Bob's Team keeps the store that already opened the role key.
    const fork = teams.load(beforeGrant, alice.localContext, createKeyring(alice.team.teamKeys()))
    fork.addMessage({ text: 'concurrent edit without the role grant' })
    const branchState = teams.load(fork.save(), bob.localContext, bob.team.teamKeyring()).state
    expect(branchState.lockboxes.some(box => box.contents.name === 'private')).toBe(false)

    const merged = bob.team.state
    bob.team.state = branchState
    try {
      expect(() => bob.team.roleKeys('private')).toThrow('Requested key scope is unavailable')
      expect(() => bob.team.decrypt(message)).toThrow()
      expect(bob.team.allKeys().ROLE?.private).toBeUndefined()
    } finally {
      bob.team.state = merged
    }
    // Back on the state that delivers it, the same retained record is selected again.
    expect(bob.team.roleKeys('private')).toBe(retained)
    expect(bob.team.decrypt(message)).toBe('private message')
  })

  it('cannot reuse a cached opening for a different recipient device or a re-addressed delivery', () => {
    const { alice, bob } = privateTeam()
    const { charlie } = setup({ user: 'charlie', member: false })
    bob.team.roleKeys('private') // Warm Bob's delivery record.
    const delivery = bob.team.state.lockboxes.find(box => box.contents.name === 'private')!

    // Charlie's device keys cannot open the delivery even though its contents are already known.
    expect(() =>
      bob.team.roleKeys('private', undefined, charlie.localContext.device.keys)
    ).toThrow()

    // Re-addressing the known delivery to Charlie's public key is a different delivery: it is
    // re-evaluated and fails because the ciphertext was never encrypted to Charlie.
    const readdressed = unpack(pack(delivery)) as typeof delivery
    const charlieKeys = charlie.localContext.device.keys
    readdressed.recipient = {
      type: charlieKeys.type,
      name: charlieKeys.name,
      generation: charlieKeys.generation,
      publicKey: charlieKeys.encryption.publicKey,
    }
    const state = { ...bob.team.state, lockboxes: [...bob.team.state.lockboxes, readdressed] }
    const decrypt = vi.spyOn(crypto.asymmetric, 'decryptBytes')
    const merged = bob.team.state
    bob.team.state = state
    try {
      expect(() =>
        bob.team.roleKeys('private', undefined, charlie.localContext.device.keys)
      ).toThrow()
      expect(bob.team.allKeys(charlie.localContext.device.keys).ROLE?.private).toBeUndefined()
      expect(
        decrypt.mock.calls.some(([{ cipher }]) =>
          Buffer.from(cipher).equals(Buffer.from(delivery.encryptedPayload))
        )
      ).toBe(true)
    } finally {
      bob.team.state = merged
    }
    expect(bob.team.roleKeys('private')).toEqual(alice.team.roleKeys('private'))
  })

  it('leaves no selectable or rechecked material from the prefix of a rejected merge', () => {
    const { alice, bob } = setup('alice', 'bob')
    alice.team.addRole('pending')
    alice.team.addMemberRole(bob.userId, 'pending')
    const rejected = forge({
      graph: alice.team.graph,
      action: {
        type: 'ADD_ROLE',
        payload: { roleName: '__proto__', createdBy: alice.userId, lockboxes: [] },
      },
      signer: alice.signer,
      teamKeys: alice.team.teamKeys(),
    })
    expect(() => bob.team.merge(rejected)).toThrow(/reserved/)
    expect(() => bob.team.roleKeys('pending')).toThrow()
    expect(bob.team.allKeys().ROLE?.pending).toBeUndefined()

    // After the reset, the Team's own device keys are still an owned record: ordinary key use
    // does not re-run keypair validation on every call.
    const signature = vi.spyOn(crypto, 'isValidSignatureKeypair')
    const encryption = vi.spyOn(crypto, 'isValidEncryptionKeypair')
    for (let n = 0; n < 100; n++) bob.team.teamKeys()
    expect(signature).not.toHaveBeenCalled()
    expect(encryption).not.toHaveBeenCalled()

    bob.team.merge(alice.team.graph)
    expect(bob.team.roleKeys('pending')).toEqual(alice.team.roleKeys('pending'))
  })

  it('never serializes retained secrets with the team or its state', () => {
    const { alice, bob } = privateTeam()
    bob.team.roleKeys('private')
    const secrets = secretsOf(
      bob.team.roleKeys('private'),
      bob.team.teamKeys(),
      bob.localContext.device.keys,
      alice.localContext.device.keys
    )
    expect(secrets.length).toBe(12)
    const saved = Buffer.from(bob.team.save()).toString('latin1')
    const state = JSON.stringify(bob.team.state)
    for (const secret of secrets) {
      expect(saved).not.toContain(secret)
      expect(state).not.toContain(secret)
    }
    // The store is a true private field: no enumerable property of the Team can reach it.
    const exposed = Object.keys(bob.team as unknown as Record<string, unknown>)
    expect(exposed.some(key => /checked/i.test(key))).toBe(false)
    expect(
      Object.values(bob.team as unknown as Record<string, unknown>).some(
        value => value?.constructor?.name === 'CheckedKeyStore'
      )
    ).toBe(false)
    // Loading the saved graph again yields the same keys only by opening the lockboxes afresh.
    const decrypt = vi.spyOn(crypto.asymmetric, 'decryptBytes')
    const reloaded = teams.load(bob.team.save(), bob.localContext, bob.team.teamKeyring())
    expect(reloaded.roleKeys('private')).toEqual(alice.team.roleKeys('private'))
    expect(decrypt).toHaveBeenCalled()
  })

  it('keeps one retained record per delivery no matter how many graph copies replay it', () => {
    const { alice, bob } = privateTeam()
    const decrypt = vi.spyOn(crypto.asymmetric, 'decryptBytes')
    const encryption = vi.spyOn(crypto, 'isValidEncryptionKeypair')
    const before = decrypt.mock.calls.length
    for (let n = 0; n < 50; n++) {
      // Each merge reconstructs every link body and lockbox from ciphertext.
      bob.team.merge(unpack(pack(alice.team.graph)))
      bob.team.roleKeys('private')
    }
    // No lockbox is opened again and no keyset is re-validated: retained records are reused, so
    // the store's size is bounded by the distinct deliveries in the accepted graph.
    const lockboxOpens = decrypt.mock.calls
      .slice(before)
      .filter(([{ cipher }]) =>
        bob.team.state.lockboxes.some(box =>
          Buffer.from(cipher).equals(Buffer.from(box.encryptedPayload))
        )
      )
    expect(lockboxOpens).toHaveLength(0)
    expect(encryption).not.toHaveBeenCalled()
  })
})
