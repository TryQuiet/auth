import { type Keyset } from '@localfirst/crdx'
import { type Transform } from 'team/types.js'

/**
 * Replaces a server's rotatable keys. Only those: `identityKeys` and `serverId` are immutable, so
 * that links the server signed before a rotation still verify afterwards.
 */
export const changeServerKeys =
  (keys: Keyset): Transform =>
  state => ({
    ...state,
    servers: state.servers.map(server =>
      server.serverId === keys.name ? { ...server, keys } : server
    ),
  })
