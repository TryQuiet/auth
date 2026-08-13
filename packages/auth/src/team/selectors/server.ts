import { assert } from '@localfirst/shared'
import { type Host } from 'server/index.js'
import { type ServerRecord, type TeamState } from 'team/types.js'

const getServers = (
  state: TeamState,
  serverId: string,
  options = { includeRemoved: false }
): ServerRecord[] =>
  [...state.servers, ...(options.includeRemoved ? state.removedServers : [])].filter(
    server => server.serverId === serverId
  )

/**
 * Returns the unique server with the given `serverId`; missing and ambiguous ids throw.
 *
 * Servers are looked up by `serverId` — the fingerprint of their immutable identity key — and never
 * by host. A host is a routing label a server can change, so authorizing by host would let one
 * server rename its way into another's permissions.
 */
export const server = (state: TeamState, serverId: string, options = { includeRemoved: false }) => {
  const matchingServers = getServers(state, serverId, options)
  assert(matchingServers.length > 0, `A server with id '${serverId}' was not found`)
  assert(matchingServers.length === 1, `Server ID '${serverId}' is ambiguous`)
  return matchingServers[0]
}

export const hasServer = (
  state: TeamState,
  serverId: string,
  options = { includeRemoved: false }
) => {
  const matchingServers = getServers(state, serverId, options)
  assert(matchingServers.length <= 1, `Server ID '${serverId}' is ambiguous`)
  return matchingServers.length === 1
}

/**
 * Finds a server by its host. For display and routing only — hosts aren't unique and aren't
 * identities, so this deliberately returns every match instead of pretending to resolve one.
 */
export const serversByHost = (
  state: TeamState,
  host: Host,
  options = { includeRemoved: false }
): ServerRecord[] =>
  [...state.servers, ...(options.includeRemoved ? state.removedServers : [])].filter(
    server => server.host === host
  )

/** All server ids known to the team, active and removed. Used for global id-uniqueness checks. */
export const allServerIds = (state: TeamState): string[] =>
  [...state.servers, ...state.removedServers].map(server => server.serverId)
