import { decryptTeamGraphCore } from './decryptTeamGraphCore.js'
import type { TeamGraph } from './types.js'

type Options = Parameters<typeof decryptTeamGraphCore>[0]

/** Internal sync-only path for reusing plaintext from the live, locally accepted Team graph. */
export const decryptTrustedTeamGraph = (
  options: Omit<Options, 'trustedGraph'> & { trustedGraph: TeamGraph }
): TeamGraph => decryptTeamGraphCore(options)
