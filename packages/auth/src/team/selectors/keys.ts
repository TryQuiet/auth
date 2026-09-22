import { type KeyMetadata, type KeyScope, type KeysetWithSecrets } from '@localfirst/crdx'
import { keyMap } from './keyMap.js'
import { type CheckedKeyStore } from 'lockbox/CheckedKeyStore.js'
import { type TeamState } from 'team/types.js'
import { assert } from '@localfirst/shared'

/** Returns the keys for the given scope, if they are in a lockbox that the current device has access to */
export const keys = (
  state: TeamState,
  deviceKeys: KeysetWithSecrets,
  scope: KeyScope | KeyMetadata,
  checkedKeys?: CheckedKeyStore
) => {
  const keys = keysAllGen(state, deviceKeys, scope, checkedKeys)

  const generation =
    'generation' in scope && scope.generation !== undefined
      ? // Return specific generation if requested
        scope.generation
      : // Use latest generation by default
        keys.length - 1

  return keys[generation]
}

export const keysAllGen = (
  state: TeamState,
  deviceKeys: KeysetWithSecrets,
  scope: KeyScope | KeyMetadata,
  checkedKeys?: CheckedKeyStore
) => {
  const { type, name } = scope

  const keysFromLockboxes = keyMap(state, deviceKeys, checkedKeys)
  const keys = keysFromLockboxes[type] ? keysFromLockboxes[type][name] : undefined

  assert(keys, 'Requested key scope is unavailable')

  return keys
}

export { keyMap as allKeys } from './keyMap.js'
