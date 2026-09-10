import { type KeysetWithSecrets } from '@localfirst/crdx'
import { visibleKeys } from './visibleKeys.js'
import { type TeamState } from 'team/types.js'
import { isUnsafeScopeName } from 'team/unsafeScopeName.js'
import { cloneDeep, cloneDeepWith, isEqual } from 'lodash-es'
import { type CachedKeyMap, type KeyMap } from './keyMap.types.js'

export type { KeyMap } from './keyMap.types.js'

// Keep one lookup per state, allowing superseded states and their secrets to be collected.
const cache = new WeakMap<TeamState, CachedKeyMap>()

const snapshot = <T>(value: T): T =>
  cloneDeepWith(value, item =>
    // Buffer.slice() shares memory; explicitly copy bytes for both Buffers and Uint8Arrays.
    item instanceof Uint8Array ? item.map((byte: number) => byte) : undefined
  )

const copyKeyMap = (value: KeyMap): KeyMap => {
  const copy: KeyMap = Object.create(null)
  for (const [type, scopes] of Object.entries(value)) {
    copy[type] = Object.assign(Object.create(null), cloneDeep(scopes))
  }
  return copy
}

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
  const previous = cache.get(state)
  // State, lockboxes and keysets are mutable public inputs. Reference equality or a graph head
  // alone cannot detect manifest, ciphertext, or key mutations after a successful lookup.
  if (
    previous &&
    isEqual(previous.lockboxes, state.lockboxes) &&
    isEqual(previous.deviceKeys, deviceKeys)
  ) {
    return copyKeyMap(previous.result)
  }
  cache.delete(state)

  // Get all the keys those keys can access
  const allVisibleKeys = visibleKeys(state, deviceKeys)

  // Structure these keys as described above
  const result = allVisibleKeys.reduce<KeyMap>(organizeKeysIntoMap, Object.create(null))
  cache.set(state, {
    lockboxes: snapshot(state.lockboxes),
    deviceKeys: snapshot(deviceKeys),
    result,
  })
  // Do not expose the cached map or its secret keysets to mutation by callers.
  return copyKeyMap(result)
}

const organizeKeysIntoMap = (result: KeyMap, keys: KeysetWithSecrets) => {
  const { type, name, generation } = keys
  // Scope names are ultimately action-controlled. Keep the map safe even if a
  // legacy graph contains a JavaScript meta-property name.
  if (isUnsafeScopeName(type) || isUnsafeScopeName(name)) return result
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
