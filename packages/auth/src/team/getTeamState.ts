import type { Keyring } from '@localfirst/crdx'
import { deserializeTeamGraph } from './serialize.js'
import { teamMachine } from './teamMachine.js'
import { Logger } from '@localfirst/shared'

export const getTeamState = (serializedGraph: Uint8Array, keyring: Keyring, extendableLogger?: Logger) => {
  const graph = deserializeTeamGraph(serializedGraph, keyring)
  return teamMachine(graph, extendableLogger)
}
