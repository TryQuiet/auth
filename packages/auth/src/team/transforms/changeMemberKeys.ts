import { type Keyset } from '@localfirst/crdx'
import { type Transform } from 'team/types.js'

export const changeMemberKeys =
  (keys: Keyset): Transform =>
  state => ({
    ...state,
    members: state.members.map(member =>
      member.userId === keys.name
        ? {
            ...member,
            keys, // 🡐 replace keys with new ones
            keysHistory: !member.keysHistory.find(k => k.generation === keys.generation && k.encryption === keys.encryption) ? [keys, ...member.keysHistory] : member.keysHistory,
          }
        : member
    ),
  })
