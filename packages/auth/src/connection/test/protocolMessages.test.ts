import { randomKey } from '@localfirst/crypto'
import { Connection } from 'connection/Connection.js'
import { PROTOCOL_VERSION_UNSUPPORTED } from 'connection/errors.js'
import { isReadyMessage } from 'connection/message.js'
import { pack, unpack } from 'msgpackr'
import { setup } from 'util/testing/index.js'
import { describe, expect, it, vi } from 'vitest'

describe('connection protocol messages', () => {
  it('validates REQUEST_IDENTITY payloads at runtime', () => {
    expect(
      isReadyMessage({ type: 'REQUEST_IDENTITY', payload: { acceptorNonce: randomKey() } })
    ).toBe(true)
    expect(isReadyMessage({ type: 'REQUEST_IDENTITY' })).toBe(false)
    expect(isReadyMessage({ type: 'REQUEST_IDENTITY', payload: {} })).toBe(false)
    expect(
      isReadyMessage({ type: 'REQUEST_IDENTITY', payload: { acceptorNonce: 'not base58!' } })
    ).toBe(false)
  })

  it('rejects a payload-less legacy REQUEST_IDENTITY as a protocol error', () => {
    const { alice } = setup('alice')
    const sent: Uint8Array[] = []
    const localError = vi.fn()
    const connection = new Connection({
      context: alice.connectionContext,
      sendMessage: message => sent.push(message),
    }).on('localError', localError)

    connection.start()
    connection.deliver(pack({ index: 0, type: 'REQUEST_IDENTITY' }))

    expect(connection.state).toBe('disconnected')
    expect(localError).toHaveBeenCalledWith(
      expect.objectContaining({ type: PROTOCOL_VERSION_UNSUPPORTED })
    )
    expect(unpack(sent.at(-1)!)).toMatchObject({
      type: 'ERROR',
      payload: { type: PROTOCOL_VERSION_UNSUPPORTED },
    })
  })
})
