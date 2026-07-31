import { type Reducer } from './types.js'
import { type Action } from 'graph/index.js'

export const compose =
  <S, A extends Action, C>(reducers: Array<Reducer<S, A, C>>): Reducer<S, A, C> =>
  (state, action, logger, graph) =>
    reducers.reduce(
      (nextState, reducer) => reducer(nextState, action, logger, graph),
      state
    )
