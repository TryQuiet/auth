import { createKeyset } from '@localfirst/crdx'
import { createServer as makeServer, redactServer } from 'server/index.js'
import type { Host, Server, ServerWithSecrets } from 'server/index.js'
import { KeyType } from 'util/index.js'
import { eventPromise } from '@localfirst/shared'
import {
  TestChannel,
  all,
  invitationNonces,
  joinTestChannel,
  memberClaim,
  memberPossessionProof,
  setup as setupHumans,
  type SetupConfig,
  type UserStuff,
} from 'util/testing/index.js'
import { describe, expect, it } from 'vitest'
import {
  createTeam,
  invitation,
  loadTeam,
  type Connection,
  type Context,
  type InviteeDeviceContext,
  type MemberContext,
  type Team,
} from 'index.js'

describe('Team', () => {
  describe('a server', () => {
    it('can be added and removed by an admin', () => {
      const { alice } = setupHumans('alice')

      // Add server
      const { server } = createServer(host)
      alice.team.addServer(server)
      expect(alice.team.servers().length).toBe(1)

      // Look up server by its id
      const serverFromTeam = alice.team.servers(server.serverId)
      expect(serverFromTeam.host).toBe(host)

      // The host is a label, not an identity, so looking one up by host gives a list
      expect(alice.team.serversByHost(host)).toHaveLength(1)

      // Remove server
      alice.team.removeServer(server.serverId)
      expect(alice.team.servers().length).toBe(0)
      expect(alice.team.serverWasRemoved(server.serverId)).toBe(true)
    })

    it("throws if a named server doesn't exist on the team", () => {
      const { alice } = setupHumans('alice')
      expect(() => alice.team.servers('foo.com')).toThrow()
    })

    it("can't be re-added after being removed", () => {
      const { alice } = setupHumans('alice')

      // Add server
      const { server } = createServer(host)
      alice.team.addServer(server)
      expect(alice.team.servers().length).toBe(1)

      // Remove server
      alice.team.removeServer(server.serverId)
      expect(alice.team.servers().length).toBe(0)
      expect(alice.team.serverWasRemoved(server.serverId)).toBe(true)

      // A removed id is tombstoned for good: bringing it back would undo the removal for anyone
      // still holding the server's keys.
      expect(() => alice.team.addServer(server)).toThrow()
      expect(alice.team.servers().length).toBe(0)

      // A fresh server at the same host is a different identity, and that's fine
      const { server: replacement } = createServer(host, 'a-different-seed')
      alice.team.addServer(replacement)
      expect(alice.team.servers().length).toBe(1)
    })

    it("can't be added by a non-admin member", () => {
      const { bob } = setupHumans('alice', { user: 'bob', admin: false })

      const { server } = createServer(host)
      const tryToAddServer = () => {
        bob.team.addServer(server)
      }

      expect(tryToAddServer).toThrowError()
      expect(bob.team.servers().length).toBe(0)
    })

    it("can't be removed by a non-admin member", () => {
      const { alice, bob } = setupHumans('alice', { user: 'bob', admin: false })

      // Add server
      const { server } = createServer(host)
      alice.team.addServer(server)
      expect(alice.team.servers().length).toBe(1)

      const tryToRemoveServer = () => {
        bob.team.removeServer(server.serverId)
      }

      expect(tryToRemoveServer).toThrowError()
    })

    it('can decrypt a team graph', () => {
      const { alice } = setupHumans('alice', 'bob', {
        user: 'charlie',
        admin: false,
      })
      const { server, serverWithSecrets } = createServer(host)
      alice.team.addServer(server)

      // Add some stuff to the team graph
      alice.team.addRole('MANAGER')
      const { id: memberInviteId } = alice.team.inviteMember()
      const { id: deviceInviteId } = alice.team.inviteDevice()

      const savedGraph = alice.team.save()
      const teamKeys = alice.team.teamKeys()

      // The server instantiates the team
      const serverTeam = loadTeam(savedGraph, { server: serverWithSecrets }, teamKeys)

      // All the stuff that should be on the graph is there
      expect(serverTeam.members().length).toBe(3)
      expect(serverTeam.roles('MANAGER')).toBeDefined()
      expect(serverTeam.getInvitation(memberInviteId)).toBeDefined()
      expect(serverTeam.getInvitation(deviceInviteId)).toBeDefined()
    })

    it('syncs with a user - changes made before connecting', async () => {
      const { server, alice } = setup('alice')

      // Alice makes a change
      alice.team.addRole('MANAGER')

      // Alice connects to the server
      await connectWithServer(alice, server)

      // The server gets the change
      expect(server.team.roles('MANAGER')).toBeDefined()
    })

    it('syncs with a user - changes made after connecting', async () => {
      const { server, alice } = setup('alice')

      // Alice connects to the server
      await connectWithServer(alice, server)

      // Alice makes a change
      alice.team.addRole('MANAGER')

      // The server gets the change
      await eventPromise(server.team, 'updated')
      expect(server.team.roles('MANAGER')).toBeDefined()
    })

    it("can't create a team", () => {
      const { serverWithSecrets } = createServer(host)
      expect(() => {
        createTeam('team server', {
          server: serverWithSecrets,
        })
      }).toThrow()
    })

    it("can't invite a member", () => {
      const { server } = setup('alice')

      expect(() => server.team.inviteMember()).toThrow()
    })

    it('can admit an invitee', async () => {
      const { server, alice, bob } = setup('alice', {
        user: 'bob',
        member: false,
      })
      const { seed: bobInvite } = alice.team.inviteMember()

      // The server learns about the invitation by connecting with Alice
      await connectWithServer(alice, server)

      // Now if Bob connects to the server, the server can admit him
      const claim = memberClaim(bob.user, bob.device)
      server.team.admitMember(
        invitation.generateProof({ seed: bobInvite, claim, ...invitationNonces() }),
        claim,
        memberPossessionProof(invitation.deriveId(bobInvite), bob.user, bob.device)
      )
      expect(server.team.members().length).toBe(2)
    })

    it("can't invite a device", () => {
      const { server } = setup('alice')
      expect(() => server.team.inviteDevice()).toThrow()
    })

    it("can't remove a member", () => {
      const { server, bob } = setup('alice', 'bob')
      expect(() => {
        server.team.remove(bob.userId)
      }).toThrow()
    })

    it('can relay changes from one member to another asynchronously', async () => {
      const { server, alice, bob } = setup('alice', 'bob')

      // Alice makes a change
      alice.team.addRole('MANAGER')

      // Alice connects to the server
      await connectWithServer(alice, server)

      // Server learned of the change
      expect(server.team.roles('MANAGER')).toBeDefined()

      // Alice disconnects from the server
      alice.connection[host].stop()
      server.connection[alice.userId].stop()

      // Bob connects to the server
      await connectWithServer(bob, server)

      // Server told bob about new role
      expect(bob.team.roles('MANAGER')).toBeDefined()
    })

    it('can admit a device invited by a member', async () => {
      const { server, alice, bob } = setup('alice', 'bob')
      const { seed } = bob.team.inviteDevice()

      // Bob's laptop connects to the server, so now it knows about the invitation
      await connectWithServer(bob, server)

      // Bob's laptop disconnects from the server
      bob.connection[host].stop()
      server.connection[bob.userId].stop()

      // Bob's phone connects to the server
      const phoneContext: InviteeDeviceContext = {
        userName: bob.userName,
        device: bob.phone!,
        invitationSeed: seed,
      }
      const join = joinTestChannel(new TestChannel())
      const serverConnection = join(server.connectionContext).start()
      const phoneConnection = join(phoneContext).start()
      await all([serverConnection, phoneConnection], 'connected')

      // const phoneTeam = phoneConnection.team!

      // Bob reconnects to the server
      await connectWithServer(bob, server)

      // 👨🏻‍🦲👍📱 Bob's phone is added to his list of devices
      expect(bob.team.members(bob.userId).devices).toHaveLength(2)

      // ✅ 👩🏾👍📱 Alice knows about Bob's phone
      await connectWithServer(alice, server)
      expect(alice.team.members(bob.userId).devices).toHaveLength(2)
    })

    it('has its keys rotated by an admin', () => {
      const { alice } = setupHumans('alice', 'bob')
      const { server, serverWithSecrets } = createServer(host)
      alice.team.addServer(server)

      expect(alice.team.teamKeys().generation).toBe(0)

      // An admin rotates the server's keys
      alice.team.changeKeys(createKeyset({ type: KeyType.SERVER, name: server.serverId }))
      expect(alice.team.servers(server.serverId).keys.generation).toBe(1)

      // The server's *identity* is untouched by the rotation — that's what its id commits to, and
      // what every link it has ever signed was signed with
      expect(alice.team.servers(server.serverId).serverId).toBe(server.serverId)
      expect(alice.team.servers(server.serverId).identityKeys).toEqual(server.identityKeys)

      // The rotation reaches the team keys, since the old server keys could see them
      const teamKeys1 = alice.team.teamKeys()
      expect(teamKeys1.generation).toBe(1)

      // The server can still read the graph after the rotation, because it signs and decrypts with
      // its identity keys
      const serverTeam = loadTeam(
        alice.team.save(),
        { server: serverWithSecrets },
        alice.team.teamKeyring()
      )
      expect(serverTeam.servers(server.serverId).keys.generation).toBe(1)
    })

    it(`can't change anyone's keys, including its own`, () => {
      const { alice } = setupHumans('alice', 'bob')
      const { server, serverWithSecrets } = createServer(host)
      alice.team.addServer(server)

      const { server: server2 } = createServer('foo.com', 'foo-seed')
      alice.team.addServer(server2)

      const savedGraph = alice.team.save()
      const serverTeam = loadTeam(savedGraph, { server: serverWithSecrets }, alice.team.teamKeys())

      // A server may only author admissions. Anything else it posts — including a re-key of itself
      // — is rejected by every replica, so it can't quietly grant itself anything.
      expect(() => {
        serverTeam.changeKeys(createKeyset({ type: KeyType.SERVER, name: server.serverId }))
      }).toThrow()

      expect(() => {
        serverTeam.changeKeys(createKeyset({ type: KeyType.SERVER, name: server2.serverId }))
      }).toThrow()

      // No keys have been rotated
      expect(serverTeam.teamKeys().generation).toBe(0)
      expect(serverTeam.servers(server2.serverId).keys.generation).toBe(0)
    })
  })
})

const connectionPromise = async (a: Connection, b: Connection) => {
  const connections = [a, b]

  // ✅ They're both connected
  await all(connections, 'connected')

  const sharedKey = connections[0]._sessionKey
  for (const connection of connections) {
    expect(connection.state).toEqual('connected')
    // ✅ They've converged on a shared secret key
    expect(connection._sessionKey).toEqual(sharedKey)
  }
}

const connectWithServer = async (user: UserStuff, server: ServerStuff) => {
  const join = joinTestChannel(new TestChannel())

  user.connection[host] = join(user.connectionContext).start()
  server.connection[user.userId] = join(server.connectionContext).start()

  return connectionPromise(user.connection[host], server.connection[user.userId])
}

const createServer = (host: Host, seed = host) => {
  const serverWithSecrets = makeServer({ host, seed })
  return { server: redactServer(serverWithSecrets), serverWithSecrets }
}

const host = 'example.com'

const setup = (...humanUsers: SetupConfig) => {
  const { server, serverWithSecrets } = createServer(host)

  const users = setupHumans(...humanUsers)

  const founder = users[humanUsers[0] as string]
  const teamKeys = founder.team.teamKeys()

  // Add the server to one team
  founder.team.addServer(server)
  const savedGraph = founder.team.save()

  // Set everybody's team to the one containing the server
  for (const userStuff of Object.values(users)) {
    const { userId, user, device, team } = userStuff
    if (userId === founder.userId) continue

    if (team) {
      const newTeam = loadTeam(savedGraph, { user, device }, teamKeys)
      userStuff.team = newTeam
      const connectionContext = userStuff.connectionContext as MemberContext
      connectionContext.team = newTeam
    }
  }

  const serverTeam = loadTeam(savedGraph, { server: serverWithSecrets }, teamKeys)

  const serverStuff = {
    server,
    serverWithSecrets,
    team: serverTeam,

    connectionContext: {
      server: serverWithSecrets,
      team: serverTeam,
    },
    connection: {},
  } as ServerStuff
  return {
    ...users,
    server: serverStuff,
  } as Record<string, UserStuff> & { server: ServerStuff }
}

type ServerStuff = {
  server: Server
  serverWithSecrets: ServerWithSecrets
  team: Team
  connectionContext: Context
  connection: Record<string, Connection>
}
