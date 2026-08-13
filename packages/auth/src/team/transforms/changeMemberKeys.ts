import { type Keyset } from '@localfirst/crdx'
import { type Transform } from 'team/types.js'

export const changeMemberKeys =
  (keys: Keyset): Transform =>
  state => ({
    ...state,
    members: state.members.map(member => {
      if (member.userId !== keys.name) return member

      // Graphs persisted before keysHistory was added only contain the current keyset.
      const keysHistory = member.keysHistory ?? [member.keys]

      return {
        ...member,
        keys, // 🡐 replace keys with new ones
        keysHistory: !keysHistory.find(k => k.generation === keys.generation && k.encryption === keys.encryption)
          ? [keys, ...keysHistory]
          : keysHistory,
      }
    }),
  })
