import { type Logger } from '@localfirst/shared'
import { type Action, type Graph, type Link } from 'graph/index.js'

export type Reducer<S, A extends Action, C = Record<string, unknown>> = (
  state: S,
  link: Link<A, C>,
  extendableLogger?: Logger,

  /** The graph the link belongs to, for reducers that need to look beyond the link in hand — e.g.
   * to resolve the link's signer against registrations elsewhere in the graph. */
  graph?: Graph<A, C>
) => S
