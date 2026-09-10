import { type KeysetWithSecrets } from '@localfirst/crdx'
import { type TeamState } from 'team/types.js'

export type KeyMap = Record<string, Record<string, KeysetWithSecrets[]>>

export type CachedKeyMap = {
  lockboxes: TeamState['lockboxes']
  deviceKeys: KeysetWithSecrets
  result: KeyMap
}
