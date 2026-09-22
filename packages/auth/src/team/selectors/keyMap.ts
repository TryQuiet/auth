import { type KeysetWithSecrets } from '@localfirst/crdx'
import { CheckedKeyStore, type KeyMap } from '../../lockbox/CheckedKeyStore.js'
import { type TeamState } from 'team/types.js'

/** Select reachable keysets by scope and generation from the current state's deliveries. */
export const keyMap = (
  state: TeamState,
  deviceKeys: KeysetWithSecrets,
  checkedKeys = new CheckedKeyStore()
): KeyMap => checkedKeys.keyMap(state.lockboxes, deviceKeys)

export { type KeyMap } from '../../lockbox/CheckedKeyStore.js'
