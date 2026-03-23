import { Logger } from '@localfirst/shared'
import { type Reducer } from './types.js'
import { type Action, getSequence, type Graph, Link, type Resolver } from 'graph/index.js'
import { validate, type ValidatorSet } from 'validator/index.js'

export const makeMachine = <S, A extends Action, C>({
  initialState,
  reducer,
  resolver,
  validators,
}: MachineParams<S, A, C>) => {
  return (graph: Graph<A, C>, extendableLogger?: Logger) => {
    // extend the logger or generate a new one if none was passed in
    const logger = extendableLogger != null ? extendableLogger.extend('makeMachine') : new Logger({ moduleName: 'auth:makeMachine' })

    // Validate the graph's integrity.
    validate(graph, validators, logger)

    // Use the filter & sequencer to turn the graph into an ordered sequence
    const sequence = getSequence(graph, resolver)
    const wrappedReducer = (state: S, link: Link<A, C>) => reducer(state, link, logger)

    // Run the sequence through the reducer to calculate the current team state
    return sequence.reduce(wrappedReducer, initialState)
  }
}

type MachineParams<S, A extends Action, C> = {
  initialState: S
  reducer: Reducer<S, A, C>
  resolver: Resolver<A, C>
  validators?: ValidatorSet
}
