import { randomKey, randomKeyBytes } from '@localfirst/crypto'
import { describe, expect, it, vi } from 'vitest'
import { Connection } from 'connection/Connection.js'
import { deriveSharedKey } from 'connection/deriveSharedKey.js'
import { invitationProofPayload, generateProof } from 'invitation/index.js'
import { memberClaim, invitationNonces, setup } from 'util/testing/index.js'
import { MessageQueue } from '../MessageQueue.js'
import { pack } from 'msgpackr'

describe('security candidate PoCs: connection protocol', () => {
  it('produces the same invitation proof payload without a protocol-version binding', () => {
    const { alice, bob } = setup('alice', { user: 'bob', member: false })
    const { seed } = alice.team.inviteMember({ seed: 'version-binding-poc' })
    const claim = memberClaim(bob.user, bob.device)
    const proof = generateProof({
      seed,
      claim,
      ...invitationNonces(),
    })

    const signedPayload = invitationProofPayload(proof, claim) as unknown[]
    expect(signedPayload.slice(0, 4)).toEqual([
      'localfirst-auth/invitation-claim',
      proof.id,
      proof.identityNonce,
      proof.inviteeNonce,
    ])

    // A v2 and v3 relay would present the same signed transcript to the invitation verifier: the
    // proof API has no protocol-version input, and the version is not part of the signed payload.
    expect(invitationProofPayload(proof, claim)).toEqual(signedPayload)
  })

  it('derives an identical session key for different channel contexts', () => {
    const firstSeed = randomKeyBytes(32)
    const secondSeed = randomKeyBytes(32)
    const v2Context = {
      version: 2,
      teamId: randomKey(),
      alice: randomKey(),
      bob: randomKey(),
      identityNonce: randomKey(),
      inviteeNonce: randomKey(),
    }
    const v3Context = {
      version: 3,
      teamId: randomKey(),
      alice: randomKey(),
      bob: randomKey(),
      identityNonce: randomKey(),
      inviteeNonce: randomKey(),
    }

    expect(v2Context).not.toEqual(v3Context)
    expect(deriveSharedKey(firstSeed, secondSeed)).toEqual(deriveSharedKey(firstSeed, secondSeed))
  })

  it('throws on malformed MsgPack before the protocol can reject the message', () => {
    const { alice } = setup('alice')
    const connection = new Connection({
      context: alice.connectionContext,
      sendMessage: vi.fn(),
    })
    connection.start()

    expect(() => connection.deliver(Uint8Array.of(0xd9, 0x05, 0x61))).toThrow()
    connection.stop(false)
  })

  it('throws when an unauthenticated resend request reaches queue handling', () => {
    const { alice } = setup('alice')
    const connection = new Connection({
      context: alice.connectionContext,
      sendMessage: vi.fn(),
    })
    connection.start()

    expect(() =>
      connection.deliver(
        Uint8Array.from(
          pack({ index: 0, type: 'REQUEST_RESEND', payload: { index: Number.MAX_SAFE_INTEGER } })
        )
      )
    ).toThrow(/doesn't exist/)
    connection.stop(false)
  })

  it('schedules work linearly in an unauthenticated inbound message index', () => {
    const setTimeout = vi
      .spyOn(globalThis, 'setTimeout')
      .mockImplementation(() => 0 as unknown as ReturnType<typeof globalThis.setTimeout>)
    try {
      const queue = new MessageQueue<{ type: 'NOOP' }>({
        sendMessage: vi.fn(),
        timeout: 1,
      })
      queue.start()
      queue.receive({ type: 'NOOP', index: 10_000 })

      expect(setTimeout).toHaveBeenCalledTimes(10_000)
    } finally {
      setTimeout.mockRestore()
    }
  })
})
