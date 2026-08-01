import type { TeamGraph } from './types.js'

const authenticatedGraphs = new WeakSet<TeamGraph>()

/** Internal one-shot capability for a graph authenticated during the current sync pass. */
export const markTeamGraphAuthenticated = (graph: TeamGraph): TeamGraph => {
  authenticatedGraphs.add(graph)
  return graph
}

/** Consumes the capability so it cannot be retained and reused after the graph changes. */
export const consumeAuthenticatedTeamGraph = (graph: TeamGraph): boolean => {
  const isAuthenticated = authenticatedGraphs.has(graph)
  authenticatedGraphs.delete(graph)
  return isAuthenticated
}
