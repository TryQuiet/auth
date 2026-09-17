import { createKeyset, getSequence } from '@localfirst/crdx'
import {
  signatures,
  INVITATION_PROOF,
  DEVICE_POSSESSION,
  type SignedMessage,
} from '@localfirst/crypto'
import { verifyGraphProof } from 'invitation/verifiedGraphProof.js'
import { setup } from 'util/testing/index.js'
import { describe, expect, it, vi } from 'vitest'

const { alice } = setup('alice')
const owner = alice.team.graph.links[alice.team.graph.root]

describe('owned graph proof signatures', () => {
  it('keeps proof facts with retained graph inputs rather than temporary sequence copies', () => {
    const keys = createKeyset({ type: 'DEVICE', name: 'retained-proof' })
    const input = {
      payload: 'owned proof',
      context: INVITATION_PROOF,
      signature: signatures.sign('owned proof', keys.signature.secretKey, INVITATION_PROOF),
      publicKey: keys.signature.publicKey,
    }
    const sequenced = getSequence(alice.team.graph).find(link => link.hash === owner.hash)!
    const verify = vi.spyOn(signatures, 'verify')
    vi.stubGlobal('WeakRef', undefined)
    try {
      expect(verifyGraphProof(input, sequenced)).toBe(true)
      expect(verifyGraphProof(input, owner)).toBe(true)
      expect(verify).toHaveBeenCalledTimes(1)
      expect(verifyGraphProof({ ...input, payload: 'changed' }, owner)).toBe(false)
      expect(verify).toHaveBeenCalledTimes(2)
    } finally {
      vi.unstubAllGlobals()
      verify.mockRestore()
    }
  })
  it('reuses only the complete context/payload/signature/resolved-key fact', () => {
    const keys = createKeyset({ type: 'DEVICE', name: 'proof-signer' })
    const other = createKeyset({ type: 'DEVICE', name: 'other-proof-signer' })
    const payload = ['invitation', { identity: 'alice', bytes: Uint8Array.from([1, 2, 3]) }]
    const input: SignedMessage = {
      payload,
      context: INVITATION_PROOF,
      signature: signatures.sign(payload, keys.signature.secretKey, INVITATION_PROOF),
      publicKey: keys.signature.publicKey,
    }
    const verify = vi.spyOn(signatures, 'verify')
    try {
      expect(verifyGraphProof(input, owner)).toBe(true)
      for (let n = 0; n < 1000; n++) expect(verifyGraphProof(input, { ...owner })).toBe(true)
      expect(verify).toHaveBeenCalledTimes(1)
      expect(verifyGraphProof({ ...input, context: DEVICE_POSSESSION }, owner)).toBe(false)
      expect(verifyGraphProof({ ...input, publicKey: other.signature.publicKey }, owner)).toBe(
        false
      )
      expect(
        verifyGraphProof(
          {
            ...input,
            signature: signatures.sign('different', keys.signature.secretKey, INVITATION_PROOF),
          },
          owner
        )
      ).toBe(false)
      ;(payload[1] as { bytes: Uint8Array }).bytes[0] = 9
      expect(verifyGraphProof(input, owner)).toBe(false)
      expect(verifyGraphProof(input, owner)).toBe(false) // Failed checks are never cached.
      expect(verify).toHaveBeenCalledTimes(6)
    } finally {
      verify.mockRestore()
    }
  })

  it('remains correct without WeakRef support', () => {
    const keys = createKeyset({ type: 'DEVICE', name: 'no-weakref-proof' })
    const input = {
      payload: 'no WeakRef',
      context: INVITATION_PROOF,
      signature: signatures.sign('no WeakRef', keys.signature.secretKey, INVITATION_PROOF),
      publicKey: keys.signature.publicKey,
    }
    vi.stubGlobal('WeakRef', undefined)
    try {
      expect(verifyGraphProof(input, owner)).toBe(true)
      expect(verifyGraphProof(input, { ...owner })).toBe(true)
      expect(verifyGraphProof({ ...input, payload: 'tampered' }, owner)).toBe(false)
    } finally {
      vi.unstubAllGlobals()
    }
  })

  it('keeps non-graph handshake signature checks uncached', () => {
    const keys = createKeyset({ type: 'DEVICE', name: 'handshake-signer' })
    const input = {
      payload: 'proof',
      context: INVITATION_PROOF,
      signature: signatures.sign('proof', keys.signature.secretKey, INVITATION_PROOF),
      publicKey: keys.signature.publicKey,
    }
    const verify = vi.spyOn(signatures, 'verify')
    try {
      expect(verifyGraphProof(input)).toBe(true)
      expect(verifyGraphProof(input)).toBe(true)
      expect(verify).toHaveBeenCalledTimes(2)
    } finally {
      verify.mockRestore()
    }
  })
})
