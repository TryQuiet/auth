import { type KeyMetadata, type KeyScope, type KeysetWithSecrets } from '@localfirst/crdx'
import { keyMap, type KeyMap } from './keyMap.js'
import { type TeamState } from 'team/types.js'
import { assert } from '@localfirst/shared'

/** Returns the keys for the given scope, if they are in a lockbox that the current device has access to */
export const keys = (
  state: TeamState,
  deviceKeys: KeysetWithSecrets,
  scope: KeyScope | KeyMetadata
) => {
  const { type, name } = scope

  const keysFromLockboxes = keyMap(state, deviceKeys)
  const keys = keysFromLockboxes[type] ? keysFromLockboxes[type][name] : undefined

  assert(keys, 'Requested key scope is unavailable')

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
  scope: KeyScope | KeyMetadata
) => {
  const { type, name } = scope

  const keysFromLockboxes = keyMap(state, deviceKeys)
  const keys = keysFromLockboxes[type] ? keysFromLockboxes[type][name] : undefined

  assert(keys, 'Requested key scope is unavailable')

  return keys
}

export const allKeys = (state: TeamState, deviceKeys: KeysetWithSecrets): KeyMap => {
  const keysFromLockboxes = keyMap(state, deviceKeys)

  assert(keysFromLockboxes, 'Key material is unavailable')

  return keysFromLockboxes
}
