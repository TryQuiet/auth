import { randomKey } from '@localfirst/crypto'
import { describe, expect, test } from 'vitest'
import { castServer, createServer, redactServer, serverIdentityIsValid } from 'server/index.js'
import { KeyType, signerIdFromKeys } from 'util/index.js'

describe('createServer', () => {
  test('the serverId is the fingerprint of the identity signature key', () => {
    const server = createServer({ host: 'localhost:3000' })
    expect(server.serverId).toBe(signerIdFromKeys(server.identityKeys))
    expect(serverIdentityIsValid(server)).toBe(true)
  })

  test('identity keys and member keys are distinct keysets', () => {
    const server = createServer({ host: 'localhost:3000' })
    expect(server.identityKeys.type).toBe(KeyType.SERVER_IDENTITY)
    expect(server.keys.type).toBe(KeyType.SERVER)
    expect(server.keys.signature.publicKey).not.toBe(server.identityKeys.signature.publicKey)
    expect(server.keys.encryption.publicKey).not.toBe(server.identityKeys.encryption.publicKey)

    // Both are named for the identity, so a validator can tie them together
    expect(server.identityKeys.name).toBe(server.serverId)
    expect(server.keys.name).toBe(server.serverId)
  })

  test('the identity survives a key rotation but does not survive an identity swap', () => {
    const server = createServer({ host: 'localhost:3000' })
    const other = createServer({ host: 'localhost:3001' })

    // Rotating the member keys leaves the identity intact
    const rotated = { ...server, keys: { ...server.keys, generation: 1 } }
    expect(serverIdentityIsValid(rotated)).toBe(true)

    // Rotating them into someone else's name does not
    expect(
      serverIdentityIsValid({ ...server, keys: { ...server.keys, name: other.serverId } })
    ).toBe(false)

    // Nor does presenting another server's identity keys under this serverId
    expect(serverIdentityIsValid({ ...server, identityKeys: other.identityKeys })).toBe(false)
    expect(
      serverIdentityIsValid({
        ...server,
        identityKeys: { ...other.identityKeys, name: server.serverId },
      })
    ).toBe(false)

    // Nor does an identity keyset claiming to have rotated
    expect(
      serverIdentityIsValid({
        ...server,
        identityKeys: { ...server.identityKeys, generation: 1 },
      })
    ).toBe(false)
  })

  test('the host is a label, not an identity', () => {
    const seed = randomKey()
    const server = createServer({ host: 'localhost:3000', seed })
    const renamed = createServer({ host: 'example.com', seed })
    expect(renamed.serverId).toBe(server.serverId)
    expect(serverIdentityIsValid(renamed)).toBe(true)
  })
})

describe('castServer', () => {
  const server = createServer({ host: 'localhost:3000' })

  test('a server acts as a member under its serverId, with its rotatable keys', () => {
    const publicServer = redactServer(server)
    expect(castServer.toMember(publicServer)).toEqual({
      userId: server.serverId,
      userName: server.host,
      keys: publicServer.keys,
      roles: [],
    })
    expect(castServer.toUser(server).userId).toBe(server.serverId)
    expect(serverIdentityIsValid(publicServer)).toBe(true)
  })

  test('a server signs with its identity keys', () => {
    expect(castServer.toSigner(server)).toEqual({
      info: { kind: 'server', id: server.serverId },
      keys: server.identityKeys,
    })
  })
})
