import type { UnixTimestamp } from '@localfirst/crdx'
import { type Transform } from 'team/types.js'

export const removeServer =
  (serverId: string, removedAt: UnixTimestamp): Transform =>
  state => {
    const removedServer = state.servers.find(s => s.serverId === serverId)

    return {
      ...state,
      servers: state.servers.filter(s => s.serverId !== serverId),
      removedServers: removedServer
        ? [...state.removedServers, { ...removedServer, removedAt }]
        : state.removedServers,
    }
  }
