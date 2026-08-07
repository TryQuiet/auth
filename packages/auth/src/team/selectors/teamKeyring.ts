import { type KeysetWithSecrets, createKeyring } from '@localfirst/crdx'
import { type TeamState } from 'team/types.js'
import { KeyType } from 'util/types.js'
import { keyMap } from './keyMap.js'

const { TEAM } = KeyType

export const teamKeyring = (state: TeamState, keys: KeysetWithSecrets) => {
  const resolvedKeyMap = keyMap(state, keys)
  const allTeamKeys = resolvedKeyMap[TEAM][TEAM]
  return createKeyring(allTeamKeys)
}
