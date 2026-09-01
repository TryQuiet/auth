import { type KeysetWithSecrets } from '@localfirst/crdx'
import { visibleKeys } from './visibleKeys.js'
import { type TeamState } from 'team/types.js'

/** Returns all keysets from the current device's lockboxes in a structure that looks like this:
 * ```js
 * {
 *    TEAM: {
 *      TEAM: [ gen0, gen1, gen2, ... ], // <- all keys starting with generation 0
 *    ROLE: {
 *      admin: [ gen0, ... ]
 *      managers: [ gen0, ...]
 *    },
 *   USER: {
 *    alice: [ gen0, ... ]
 *   }
 * }
 * ```
 */
export const keyMap = (state: TeamState, deviceKeys: KeysetWithSecrets): KeyMap => {
  // Get all the keys those keys can access
  const allVisibleKeys = visibleKeys(state, deviceKeys)

  // Structure these keys as described above
  return allVisibleKeys.reduce(organizeKeysIntoMap, Object.create(null) as KeyMap)
}

const organizeKeysIntoMap = (result: KeyMap, keys: KeysetWithSecrets) => {
  const { type, name, generation } = keys
  const keysetsForScope = Object.hasOwn(result, type)
    ? result[type]
    : (result[type] = Object.create(null) as Record<string, KeysetWithSecrets[]>)
  const keysetHistory = Object.hasOwn(keysetsForScope, name)
    ? keysetsForScope[name]
    : (keysetsForScope[name] = [])

  // An established generation is immutable. `authorizedLockboxes` ensures duplicates carry the
  // same committed keyset, but first-write-wins here keeps selection stable if a caller supplies a
  // state that bypassed collection or contains hostile legacy lockboxes.
  if (Object.hasOwn(keysetHistory, generation)) return result

  keysetHistory[generation] = keys
  return result
}

export type KeyMap = Record<string, Record<string, KeysetWithSecrets[]>>
