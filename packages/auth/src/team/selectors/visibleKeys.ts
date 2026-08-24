import { type KeysetWithSecrets } from '@localfirst/crdx'
import { keysetCommitment, open } from 'lockbox/index.js'
import { type TeamState } from 'team/types.js'

/**
 * Returns all keys that can be accessed directly or indirectly (via lockboxes) by the given keyset
 * @param state
 * @param keyset
 */
export const visibleKeys = (state: TeamState, keyset: KeysetWithSecrets): KeysetWithSecrets[] => {
  // Exact redistributions can form cycles (including a keyset boxed to itself). Track the complete
  // committed keyset identity so those valid lockboxes cannot recurse forever or amplify duplicate
  // paths. The starting keyset is deliberately excluded from the result.
  const visited = new Set([keysetCommitment(keyset)])
  return collectVisibleKeys(state, keyset, visited)
}

const collectVisibleKeys = (
  state: TeamState,
  keyset: KeysetWithSecrets,
  visited: Set<string>
): KeysetWithSecrets[] => {
  const { lockboxes } = state
  const { publicKey } = keyset.encryption

  // What lockboxes can I open with these keys?
  const lockboxesICanOpen = lockboxes.filter(({ recipient }) => recipient.publicKey === publicKey)

  // Collect all the keys from those lockboxes
  // A peer can publish a malformed lockbox whose manifest names us as its recipient. Treat it as
  // unusable instead of allowing one bad lockbox to make every key lookup fail.
  const keysets = lockboxesICanOpen
    .flatMap(lockbox => {
      try {
        return [open(lockbox, keyset)]
      } catch {
        return []
      }
    })
    .filter(keys => {
      const commitment = keysetCommitment(keys)
      if (visited.has(commitment)) return false

      visited.add(commitment)
      return true
    })

  // Recursively get all the keys *those* keys can access
  const keys = keysets.flatMap(keyset => collectVisibleKeys(state, keyset, visited))

  return [...keysets, ...keys]
}
