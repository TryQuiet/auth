import { createKeyset } from '@localfirst/crdx'
import { TEAM_SCOPE } from './constants.js'
import { type LocalContext } from 'team/context.js'
import { Team } from 'team/Team.js'
import { TeamMetadata } from './index.js'
import { SharedLogger } from '@localfirst/shared'

export function createTeam(teamName: string, context: LocalContext, seed?: string, metadata?: TeamMetadata, sharedLogger?: SharedLogger) {
  const teamKeys = createKeyset(TEAM_SCOPE, seed)
  const defaultMetadata: TeamMetadata = {
    selfAssignableRoles: []
  }
  return new Team({ teamName, context, teamKeys, metadata: metadata ?? defaultMetadata, sharedLogger })
}
