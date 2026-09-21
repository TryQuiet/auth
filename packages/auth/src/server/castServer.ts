import type { User, UserWithSecrets } from '@localfirst/crdx'
import type { Server, ServerWithSecrets } from './types.js'
import type { Member } from 'team/index.js'

/**
 * A server participates in the team's key hierarchy as if it were a member: team and role keys are
 * shipped to it in lockboxes addressed to its rotatable `keys`. That member identity is its
 * `serverId` — its `host` is only a display name, and authorizing anything by host would let a
 * server rename its way into someone else's permissions.
 */
const toMember = (server: Server): Member => ({
  userId: server.serverId,
  userName: server.host,
  keys: server.keys,
  roles: [],
})

const toUser = <T extends Server | ServerWithSecrets>(server: T) =>
  ({
    userId: server.serverId,
    userName: server.host,
    keys: server.keys,
  }) as T extends Server ? User : UserWithSecrets

/**
 * The signer a server authors links with. Note that this is the *identity* keyset, not the member
 * keyset above: links are signed and encrypted with keys that never rotate, so a link's signature
 * can still be verified against the server's registered identity after a re-key.
 */
const toSigner = (server: ServerWithSecrets) => ({
  info: { kind: 'server' as const, id: server.serverId },
  keys: server.identityKeys,
})

export const castServer = { toMember, toUser, toSigner }
