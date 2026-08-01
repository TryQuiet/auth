import { Logger } from '@localfirst/shared'
import { type Action, type Graph, type Link } from 'graph/index.js'

/**
 * Redux-style state reducer for graph links.
 *
 * Store and machine evaluation supply the complete graph being evaluated—including the candidate
 * link during dispatch—as the optional fourth argument. It remains optional for compatibility with
 * existing reducers.
 */
export type Reducer<S, A extends Action, C = Record<string, unknown>> = (
  state: S,
  link: Link<A, C>,
  extendableLogger?: Logger,
  graph?: Graph<A, C>
) => S
