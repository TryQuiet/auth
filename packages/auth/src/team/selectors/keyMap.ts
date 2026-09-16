import { type KeysetWithSecrets } from '@localfirst/crdx'
import { CheckedKeyStore } from 'lockbox/CheckedKeyStore.js'
import { type TeamState } from 'team/types.js'

export type { KeyMap } from 'lockbox/CheckedKeyStore.js'

/** Select reachable keysets by scope and generation from the current state's deliveries. */
export const keyMap = (
  state: TeamState,
  deviceKeys: KeysetWithSecrets,
  checkedKeys = new CheckedKeyStore()
) => checkedKeys.keyMap(state.lockboxes, deviceKeys)
