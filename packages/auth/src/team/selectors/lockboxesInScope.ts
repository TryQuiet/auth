import { type KeyScope } from '@localfirst/crdx'
import { isKeyManifest, type Lockbox } from 'lockbox/index.js'
import { type TeamState } from 'team/types.js'

/** Returns all lockboxes *containing* keys for the given scope */
export const lockboxesInScope = (state: TeamState, scope: KeyScope): Lockbox[] => {
  const lockboxes = state.lockboxes.filter(
    ({ contents }) =>
      isKeyManifest(contents) && contents.type === scope.type && contents.name === scope.name
  )
  const latestGeneration = lockboxes.reduce(maxGeneration, 0)
  const latestLockboxes = lockboxes.filter(
    ({ contents }) => contents.generation === latestGeneration
  )

  // Collection establishes the first commitment for each scope/generation. Keep the selector
  // stable even if it is handed a state assembled outside the reducer (or from hostile legacy
  // data): a later conflicting lockbox must not expand the holder set or become rotation input.
  const establishedCommitment = latestLockboxes[0]?.contents.commitment
  return latestLockboxes.filter(({ contents }) => contents.commitment === establishedCommitment)
}

const maxGeneration = (max: number, lockbox: Lockbox) => {
  const { generation } = lockbox.contents
  if (generation > max) {
    return generation
  }

  return max
}
