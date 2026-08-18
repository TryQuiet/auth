import { eventPromise } from '@localfirst/shared'
import { pack, unpack } from 'msgpackr'
import { joinTestChannel, setup, TestChannel } from 'util/testing/index.js'
import { describe, expect, it, vi } from 'vitest'
import { ENCRYPTION_FAILURE } from '../errors.js'
import type { ConnectionMessage } from '../message.js'
import type { NumberedMessage } from '../MessageQueue.js'
import type { InviteeMemberContext } from '../types.js'

describe('connection session events', () => {
  it('commits the session key before emitting connectionSecured', async () => {
    const { alice, bob } = setup('alice', 'bob')
    const join = joinTestChannel(new TestChannel())
    const aliceConnection = join(alice.connectionContext)
    const bobConnection = join(bob.connectionContext)

    let sessionKeyAtEvent: Uint8Array | undefined
    let sendError: unknown
    aliceConnection.on('connectionSecured', () => {
      sessionKeyAtEvent = aliceConnection._sessionKey
      try {
        aliceConnection.send('sent immediately')
      } catch (error) {
        sendError = error
      }
    })

    const connected = Promise.all([
      eventPromise(aliceConnection, 'connected'),
      eventPromise(bobConnection, 'connected'),
    ])
    aliceConnection.start()
    bobConnection.start()
    await connected

    expect(sessionKeyAtEvent).toBeInstanceOf(Uint8Array)
    expect(sendError).toBeUndefined()
  })

  it('emits joined only after the invitation connection is secured', async () => {
    const { alice, bob } = setup('alice', { user: 'bob', member: false })
    const { seed, teamId } = alice.team.inviteMember()
    const inviteeContext: InviteeMemberContext = {
      user: bob.user,
      device: bob.device,
      invitationSeed: seed,
      expectedTeamId: teamId,
    }
    const join = joinTestChannel(new TestChannel())
    const aliceConnection = join(alice.connectionContext)
    const inviteeConnection = join(inviteeContext)

    const events: string[] = []
    let sessionKeyAtJoined: Uint8Array | undefined
    inviteeConnection.on('connectionSecured', () => events.push('connectionSecured'))
    inviteeConnection.on('joined', () => {
      sessionKeyAtJoined = inviteeConnection._sessionKey
      events.push('joined')
    })

    const connected = Promise.all([
      eventPromise(aliceConnection, 'connected'),
      eventPromise(inviteeConnection, 'connected'),
    ])
    aliceConnection.start()
    inviteeConnection.start()
    await connected

    expect(events).toEqual(['connectionSecured', 'joined'])
    expect(sessionKeyAtJoined).toBeInstanceOf(Uint8Array)
  })

  it('does not emit joined when session negotiation fails after admission', async () => {
    const { alice, bob } = setup('alice', { user: 'bob', member: false })
    const { seed, teamId } = alice.team.inviteMember()
    const inviteeContext: InviteeMemberContext = {
      user: bob.user,
      device: bob.device,
      invitationSeed: seed,
      expectedTeamId: teamId,
    }
    const join = joinTestChannel(new TamperedSeedChannel(alice.device.deviceId))
    const aliceConnection = join(alice.connectionContext)
    const inviteeConnection = join(inviteeContext)

    const joined = vi.fn()
    inviteeConnection.on('joined', joined)
    const error = eventPromise(inviteeConnection, 'localError')

    aliceConnection.start()
    inviteeConnection.start()

    // The invitee validated the graph and joined the team internally, but the peer that handed it
    // over never proved it holds the keys that graph names, so nothing is handed to the app.
    await expect(error).resolves.toMatchObject({ type: ENCRYPTION_FAILURE })
    expect(inviteeConnection.team).toBeDefined()
    expect(joined).not.toHaveBeenCalled()
  })
})

/** Corrupts the SEED message from one particular sender, so key agreement fails. */
class TamperedSeedChannel extends TestChannel {
  constructor(private readonly senderToTamper: string) {
    super()
  }

  override write(senderId: string, message: Uint8Array) {
    const numberedMessage = unpack(message) as NumberedMessage<ConnectionMessage>
    if (senderId === this.senderToTamper && numberedMessage.type === 'SEED') {
      const encryptedSeed = numberedMessage.payload.encryptedSeed.slice()
      encryptedSeed[Math.floor(encryptedSeed.length / 2)] ^= 1
      const tampered = pack({ ...numberedMessage, payload: { encryptedSeed } })
      super.write(
        senderId,
        new Uint8Array(tampered.buffer, tampered.byteOffset, tampered.byteLength)
      )
      return
    }

    super.write(senderId, message)
  }
}
