import { type KeysetWithSecrets } from '@localfirst/crdx'
import { CheckedKeyStore } from '../../lockbox/CheckedKeyStore.js'
import { type TeamState } from 'team/types.js'

/** Keysets reachable through the supplied state's lockboxes, excluding the starting keyset. */
export const visibleKeys = (
  state: TeamState,
  keyset: KeysetWithSecrets,
  checkedKeys = new CheckedKeyStore()
) => checkedKeys.visibleKeys(state.lockboxes, keyset)
