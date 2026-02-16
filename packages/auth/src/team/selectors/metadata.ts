import { type Base58 } from '@localfirst/crdx'
import { type TeamState } from 'team/types.js'
import { assert } from '@localfirst/shared'

export function hasMetadata(state: TeamState): boolean {
  return !!state.metadata
}

export function getMetadata(state: TeamState) {
  assert(hasMetadata(state), `No metadata found`)
  return state.metadata
}
