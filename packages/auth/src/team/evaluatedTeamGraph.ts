import type { MachineResult } from '@localfirst/crdx'
import type { ExistingTeamOptions, TeamAction, TeamContext, TeamState } from './types.js'

const EVALUATED_TEAM_GRAPH = Symbol('evaluated-team-graph')

type EvaluatedTeamOptions = ExistingTeamOptions & {
  [EVALUATED_TEAM_GRAPH]?: MachineResult<TeamState, TeamAction, TeamContext>
}

/** Internal capability for reusing a graph result that already passed the exact team machine. */
export const withEvaluatedTeamGraph = <T extends ExistingTeamOptions>(
  options: T,
  machineResult: MachineResult<TeamState, TeamAction, TeamContext>
): T => {
  Object.defineProperty(options, EVALUATED_TEAM_GRAPH, { value: machineResult })
  return options
}

export const getEvaluatedTeamGraph = (options: ExistingTeamOptions) =>
  (options as EvaluatedTeamOptions)[EVALUATED_TEAM_GRAPH]
