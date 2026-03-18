import type { Keyring } from '@localfirst/crdx'
import { deserializeTeamGraph } from './serialize.js'
import { teamMachine } from './teamMachine.js'

export const getTeamState = (serializedGraph: Uint8Array, keyring: Keyring, sharedLogger?: any) => {
  const graph = deserializeTeamGraph(serializedGraph, keyring)
  return teamMachine(graph, sharedLogger)
}
