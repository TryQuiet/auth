import { type Hash, type Keyset } from '@localfirst/crdx'
import { type Transform } from 'team/types.js'

export const changeMemberKeys =
  (keys: Keyset, retiredAt: Hash): Transform =>
  state => {
    const previousKeys = state.members.find(member => member.userId === keys.name)?.keys
    return {
      ...state,
      members: state.members.map(member =>
        member.userId === keys.name
          ? {
              ...member,
              keys, // 🡐 replace keys with new ones
            }
          : member
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
