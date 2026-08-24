import {
  asymmetric,
  IDENTITY_CHALLENGE,
  randomKey,
  signatures,
  type Base58,
} from '@localfirst/crypto'
import { eventPromise } from '@localfirst/shared'
import { Connection } from 'connection/Connection.js'
import { IDENTITY_PROOF_INVALID, PROTOCOL_VERSION_UNSUPPORTED } from 'connection/errors.js'
import {
  CONNECTION_PROTOCOL_VERSION,
  isReadyMessage,
  type ConnectionMessage,
} from 'connection/message.js'
import type { InviteeMemberContext } from 'connection/types.js'
import { generateStarterKeys } from 'invitation/index.js'
import { pack, unpack } from 'msgpackr'
import { connect, joinTestChannel, setup, TestChannel } from 'util/testing/index.js'
import { describe, expect, it, vi } from 'vitest'
import type { NumberedMessage } from '../MessageQueue.js'

describe('connection protocol messages', () => {
  it('accepts only the exact v3 REQUEST_IDENTITY payload', () => {
    const identityNonce = randomKey()
    expect(
      isReadyMessage({
        type: 'REQUEST_IDENTITY',
        payload: { protocolVersion: CONNECTION_PROTOCOL_VERSION, identityNonce },
      })
    ).toBe(true)
    expect(isReadyMessage({ type: 'REQUEST_IDENTITY' })).toBe(false)
    expect(isReadyMessage({ type: 'REQUEST_IDENTITY', payload: {} })).toBe(false)
    expect(
      isReadyMessage({
        type: 'REQUEST_IDENTITY',
        payload: {
          protocolVersion: CONNECTION_PROTOCOL_VERSION,
          identityNonce: 'not base58!',
        },
      })
    ).toBe(false)
    expect(
      isReadyMessage({
        type: 'REQUEST_IDENTITY',
        payload: { protocolVersion: CONNECTION_PROTOCOL_VERSION, identityNonce, extra: true },
      })
    ).toBe(false)
    expect(
      isReadyMessage({
        type: 'REQUEST_IDENTITY',
        payload: { protocolVersion: CONNECTION_PROTOCOL_VERSION, identityNonce },
        extra: true,
      })
    ).toBe(false)
  })

  it('connects peers that both negotiate v3', async () => {
    const { alice, bob } = setup('alice', 'bob')
    await expect(connect(alice, bob)).resolves.toBe(true)
  })

  it('rejects a translated legacy identity proof before synchronization', async () => {
    const { alice, bob } = setup('alice', 'bob')
    const channel = new LegacyRequestBridgeChannel(
      bob.device.deviceId,
      bob.device.keys.signature.secretKey
    )
    const join = joinTestChannel(channel)
    const aliceConnection = join(alice.connectionContext)
    const bobConnection = join(bob.connectionContext)
    const localError = eventPromise(aliceConnection, 'localError')

    aliceConnection.start()
    bobConnection.start()

    await expect(localError).resolves.toMatchObject({ type: IDENTITY_PROOF_INVALID })
    expect(channel.translatedRequests).toBe(2)
    expect(channel.sawSync).toBe(false)

    aliceConnection.stop(false)
    bobConnection.stop(false)
  })

  it.each([
    ['payload-less legacy request', undefined],
    ['old nonce shape', { acceptorNonce: randomKey() }],
    ['missing version', { identityNonce: randomKey() }],
    ['missing identity nonce', { protocolVersion: CONNECTION_PROTOCOL_VERSION }],
    ['old version', { protocolVersion: 2, identityNonce: randomKey() }],
    ['future version', { protocolVersion: 4, identityNonce: randomKey() }],
    ['unknown version', { protocolVersion: '3', identityNonce: randomKey() }],
    [
      'extra field',
      { protocolVersion: CONNECTION_PROTOCOL_VERSION, identityNonce: randomKey(), extra: true },
    ],
  ])('rejects a %s before graph exchange', (_label, payload) => {
    const { alice } = setup('alice')
    const sent: Uint8Array[] = []
    const localError = vi.fn()
    const connection = new Connection({
      context: alice.connectionContext,
      sendMessage: message => sent.push(message),
    }).on('localError', localError)

    connection.start()
    connection.deliver(
      pack(
        payload === undefined
          ? { index: 0, type: 'REQUEST_IDENTITY' }
          : { index: 0, type: 'REQUEST_IDENTITY', payload }
      )
    )

    expect(connection.state).toBe('disconnected')
    expect(localError).toHaveBeenCalledWith(
      expect.objectContaining({ type: PROTOCOL_VERSION_UNSUPPORTED })
    )
    expect(unpack(sent.at(-1)!)).toMatchObject({
      type: 'ERROR',
      payload: { type: PROTOCOL_VERSION_UNSUPPORTED },
    })
    expect(sent.map(message => unpack(message).type)).not.toContain('CLAIM_IDENTITY')
    expect(sent.map(message => unpack(message).type)).not.toContain('SYNC')
  })

  it.each([
    ['legacy plaintext shape', () => ({ serializedGraph: new Uint8Array(), teamKeyring: {} })],
    [
      'missing version',
      (payload: Record<string, unknown>) => {
        const { version: _version, ...rest } = payload
        return rest
      },
    ],
    ['old version', (payload: Record<string, unknown>) => ({ ...payload, version: 2 })],
    ['future version', (payload: Record<string, unknown>) => ({ ...payload, version: 4 })],
    ['extra field', (payload: Record<string, unknown>) => ({ ...payload, extra: true })],
  ])('rejects an invitation acceptance with a %s before sync', async (_label, rewrite) => {
    const { alice, bob } = setup('alice', { user: 'bob', member: false })
    const { seed, teamId } = alice.team.inviteMember()
    const inviteeContext: InviteeMemberContext = {
      user: bob.user,
      device: bob.device,
      invitationSeed: seed,
      expectedTeamId: teamId,
    }
    const channel = new RewriteAcceptanceChannel(rewrite)
    const join = joinTestChannel(channel)
    const acceptor = join(alice.connectionContext)
    const invitee = join(inviteeContext)
    const localError = eventPromise(invitee, 'localError')

    acceptor.start()
    invitee.start()

    await expect(localError).resolves.toMatchObject({ type: PROTOCOL_VERSION_UNSUPPORTED })
    expect(invitee.state).toBe('disconnected')
    expect(channel.sawSync).toBe(false)

    acceptor.stop(false)
    invitee.stop(false)
  })

  it.each([
    [
      'legacy plaintext shape',
      (envelope: Record<string, unknown>) => ({
        serializedGraph: envelope.serializedGraph,
        teamKeyring: envelope.teamKeyring,
      }),
    ],
    [
      'missing version',
      (envelope: Record<string, unknown>) => {
        const { version: _version, ...rest } = envelope
        return rest
      },
    ],
    ['old version', (envelope: Record<string, unknown>) => ({ ...envelope, version: 2 })],
    ['future version', (envelope: Record<string, unknown>) => ({ ...envelope, version: 4 })],
    ['extra field', (envelope: Record<string, unknown>) => ({ ...envelope, extra: true })],
  ])('rejects an encrypted invitation envelope with a %s before sync', async (_label, mutate) => {
    const { alice, bob } = setup('alice', { user: 'bob', member: false })
    const { seed, teamId } = alice.team.inviteMember()
    const inviteeContext: InviteeMemberContext = {
      user: bob.user,
      device: bob.device,
      invitationSeed: seed,
      expectedTeamId: teamId,
    }
    const channel = new RewriteAcceptanceChannel(payload =>
      rewriteAcceptanceEnvelope({
        payload,
        invitationSeed: seed,
        senderSecretKey: alice.device.keys.encryption.secretKey,
        mutate,
      })
    )
    const join = joinTestChannel(channel)
    const acceptor = join(alice.connectionContext)
    const invitee = join(inviteeContext)
    const localError = eventPromise(invitee, 'localError')

    acceptor.start()
    invitee.start()

    await expect(localError).resolves.toMatchObject({ type: PROTOCOL_VERSION_UNSUPPORTED })
    expect(invitee.state).toBe('disconnected')
    expect(channel.sawSync).toBe(false)

    acceptor.stop(false)
    invitee.stop(false)
  })
})

class RewriteAcceptanceChannel extends TestChannel {
  sawSync = false

  constructor(private readonly rewrite: (payload: Record<string, unknown>) => unknown) {
    super()
  }

  override write(senderId: string, message: Uint8Array) {
    const numbered = unpack(message) as NumberedMessage<ConnectionMessage>
    if (numbered.type === 'SYNC') this.sawSync = true
    if (numbered.type !== 'ACCEPT_INVITATION') {
      super.write(senderId, message)
      return
    }

    const rewritten = {
      ...numbered,
      payload: this.rewrite(numbered.payload as unknown as Record<string, unknown>),
    }
    super.write(senderId, Uint8Array.from(pack(rewritten)))
  }
}

/**
 * Models a relay translating the legacy and v3 REQUEST_IDENTITY field names in both directions,
 * while one peer still produces the pre-v3 identity signature over the bare challenge. Syntax
 * translation gets both requests through, but the authenticated v3 identity payload must not.
 */
class LegacyRequestBridgeChannel extends TestChannel {
  sawSync = false
  translatedRequests = 0

  constructor(
    private readonly legacySenderId: string,
    private readonly legacySigningSecretKey: Base58
  ) {
    super()
  }

  override write(senderId: string, message: Uint8Array) {
    const numbered = unpack(message) as NumberedMessage<ConnectionMessage>
    if (numbered.type === 'SYNC') this.sawSync = true

    if (numbered.type === 'REQUEST_IDENTITY') {
      // The intermediate legacy representation is intentionally not delivered: the relay maps it
      // straight back to the exact v3 payload understood by the current endpoint.
      const legacyRequest = { acceptorNonce: numbered.payload.identityNonce }
      const translated = {
        ...numbered,
        payload: {
          protocolVersion: CONNECTION_PROTOCOL_VERSION,
          identityNonce: legacyRequest.acceptorNonce,
        },
      }
      this.translatedRequests += 1
      super.write(senderId, Uint8Array.from(pack(translated)))
      return
    }

    if (senderId === this.legacySenderId && numbered.type === 'PROVE_IDENTITY') {
      const legacyProof = signatures.sign(
        numbered.payload.challenge,
        this.legacySigningSecretKey,
        IDENTITY_CHALLENGE
      )
      const translated = {
        ...numbered,
        payload: { ...numbered.payload, proof: legacyProof },
      }
      super.write(senderId, Uint8Array.from(pack(translated)))
      return
    }

    super.write(senderId, message)
  }
}

const rewriteAcceptanceEnvelope = ({
  payload,
  invitationSeed,
  senderSecretKey,
  mutate,
}: {
  payload: Record<string, unknown>
  invitationSeed: string
  senderSecretKey: Base58
  mutate: (envelope: Record<string, unknown>) => unknown
}): unknown => {
  const senderPublicKey = payload.senderPublicKey as Base58
  const starterKeys = generateStarterKeys(invitationSeed)
  const envelope = asymmetric.decryptBytes({
    cipher: payload.encryptedAcceptance as Uint8Array,
    recipientSecretKey: starterKeys.encryption.secretKey,
    senderPublicKey,
  }) as Record<string, unknown>

  return {
    ...payload,
    encryptedAcceptance: asymmetric.encryptBytes({
      secret: mutate(envelope),
      recipientPublicKey: starterKeys.encryption.publicKey,
      senderSecretKey,
    }),
  }
}
