import type { UnixTimestamp } from '@localfirst/crdx'
import type { Server } from 'server/index.js'
import type { Transform } from 'team/types.js'

/** Registers a server. As with devices, a removed `serverId` is never registered again. */
export const addServer =
  (newServer: Server, admittedAt: UnixTimestamp): Transform =>
  state => ({
    ...state,
    servers: [...state.servers, { ...newServer, admittedAt }],
  })
