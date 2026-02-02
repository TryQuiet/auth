import { createKeyset } from '@localfirst/crdx'
import { TEAM_SCOPE } from './constants.js'
import { type LocalContext } from 'team/context.js'
import { Team } from 'team/Team.js'
import { TeamMetadata } from './index.js'

export function createTeam(teamName: string, context: LocalContext, seed?: string, metadata?: TeamMetadata) {
  const teamKeys = createKeyset(TEAM_SCOPE, seed)

  return new Team({ teamName, context, teamKeys, metadata: metadata ?? { selfAssignableRoles: [] } })
}
