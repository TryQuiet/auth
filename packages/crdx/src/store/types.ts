import { Logger } from '@localfirst/shared'
import { type Action, type Link } from 'graph/index.js'

export type Reducer<S, A extends Action, C = Record<string, unknown>> = (
  state: S,
  link: Link<A, C>,
  extendableLogger?: Logger
) => S
