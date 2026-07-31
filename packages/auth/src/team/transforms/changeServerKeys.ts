import { type Hash, type Keyset } from '@localfirst/crdx'
import { type Transform } from 'team/types.js'

export const changeServerKeys =
  (keys: Keyset, retiredAt: Hash): Transform =>
  state => {
    const previousKeys = state.servers.find(server => server.host === keys.name)?.keys
    return {
      ...state,
      servers: state.servers.map(server =>
        server.host === keys.name
          ? {
              ...server,
              keys, // 🡐 replace keys with new ones
            }
          : server
      ),
      retiredAuthorKeys:
        previousKeys === undefined
          ? state.retiredAuthorKeys
          : [
              ...state.retiredAuthorKeys,
              {
                identityId: keys.name,
                encryptionPublicKey: previousKeys.encryption,
                retiredAt,
              },
            ],
    }
  }
