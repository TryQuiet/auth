import { keysetCacheIdentity } from 'lockbox/keysetCacheIdentity.js'
import { type KeysetWithSecrets } from '@localfirst/crdx'
import { isLockboxCollection } from 'lockbox/snapshot.js'
import { visibleKeys } from './visibleKeys.js'
import { type TeamState } from 'team/types.js'
import { isUnsafeScopeName } from 'team/unsafeScopeName.js'

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
  // Only immutable reducer snapshots are eligible. Device keys remain caller-owned: include all
  // fields (including both secret keys) in the cache key, so mutation never aliases a valid key.
  const cacheable = isLockboxCollection(state.lockboxes)
  const identity = cacheable ? keysetCacheIdentity(deviceKeys) : undefined
  const previous = cacheable ? keyMaps.get(state.lockboxes) : undefined
  if (previous !== undefined && previous.identity === identity && identity !== undefined)
    return previous.keys

  const allVisibleKeys = visibleKeys(state, deviceKeys)
  const keys = allVisibleKeys.reduce<KeyMap>(organizeKeysIntoMap, Object.create(null))
  if (cacheable && identity !== undefined) {
    // Callers must not be able to poison the next lookup by altering returned decrypted keys.
    for (const scopes of Object.values(keys)) {
      for (const generations of Object.values(scopes)) {
        for (const keyset of generations) {
          freezeKeyset(keyset)
        }
        Object.freeze(generations)
      }
      Object.freeze(scopes)
    }
    Object.freeze(keys)
    keyMaps.set(state.lockboxes, { identity, keys })
  }
  return keys
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

export type KeyMap = Record<string, Record<string, KeysetWithSecrets[]>>

// One device/context per immutable state; no unbounded process-wide secret-key cache.
const keyMaps = new WeakMap<TeamState['lockboxes'], { identity: string; keys: KeyMap }>()

const freezeKeyset = (keys: KeysetWithSecrets | undefined) => {
  if (keys === undefined) return
  Object.freeze(keys.encryption)
  Object.freeze(keys.signature)
  Object.freeze(keys)
}
