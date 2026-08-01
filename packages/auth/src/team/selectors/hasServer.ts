import { type Host } from 'server/index.js'
import { type TeamState } from 'team/types.js'

/**
 * Returns whether exactly one server has `host`; optionally includes removed servers and throws when
 * the host is ambiguous.
 */
export const hasServer = (state: TeamState, host: Host, options = { includeRemoved: false }) => {
  const matchingServers = [
    ...state.servers,
    ...(options.includeRemoved ? state.removedServers : []),
  ].filter(server => server.host === host)
  if (matchingServers.length > 1) {
    throw new Error(`Server host '${host}' is ambiguous`)
  }
  return matchingServers.length === 1
}
