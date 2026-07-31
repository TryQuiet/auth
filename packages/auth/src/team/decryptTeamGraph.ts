import type { Keyring, KeysetWithSecrets, MaybePartlyDecryptedGraph } from '@localfirst/crdx'
import type { Logger } from '@localfirst/shared'
import { decryptTeamGraphCore } from './decryptTeamGraphCore.js'
import type { TeamAction, TeamContext, TeamGraph } from './types.js'

/**
 * Decrypts a graph.
 *
 * This is a team-specific version of `decryptGraph` from crdx. When we're communicating with a
 * peer, we can't just use a single set of team keys to decrypt everything, because there might be
 * key rotations in links that we receive that we will need to decrypt subsequent links. When that
 * happens, each team member gets the new keys in a lockbox that's stored on the chain. So we need
 * to recurse through the chain, updating the keys if necessary before continuing to decrypt
 * further.
 */
export const decryptTeamGraph = ({
  encryptedGraph,
  teamKeys,
  deviceKeys,
  extendableLogger,
}: {
  encryptedGraph: MaybePartlyDecryptedGraph<TeamAction, TeamContext>

  /** First-generation or retained team keys used to begin decryption. */
  teamKeys: KeysetWithSecrets | KeysetWithSecrets[] | Keyring

  /** Device keys used to open rotated team keys found in graph lockboxes. */
  deviceKeys: KeysetWithSecrets

  extendableLogger?: Logger
}): TeamGraph => decryptTeamGraphCore({ encryptedGraph, teamKeys, deviceKeys, extendableLogger })
