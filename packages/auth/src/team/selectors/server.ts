import { type Host } from 'server/index.js'
import { type TeamState } from 'team/types.js'

export const server = (state: TeamState, host: Host, options = { includeRemoved: false }) => {
  const serversToSearch = [
    ...state.servers,
    ...(options.includeRemoved ? state.removedServers : []),
  ]
  const matchingServers = serversToSearch.filter(server => server.host === host)

  if (matchingServers.length === 0) {
    throw new Error(`A server with host '${host}' was not found`)
  }
  if (matchingServers.length > 1) {
    throw new Error(`Server host '${host}' is ambiguous`)
  }

  return matchingServers[0]
}
