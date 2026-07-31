import { hash } from '@localfirst/crypto'
import { Logger } from '@localfirst/shared'
import { isEqual } from 'lodash-es'
import { type Reducer } from './types.js'
import { type Action, getSequence, type Graph, type Link, type Resolver } from 'graph/index.js'
import { validate, type ValidatorSet } from 'validator/index.js'

const MACHINE_RESULT = Symbol('crdx-machine-result')
const MACHINE_RESULT_HASH_PURPOSE = 'CRDX_MACHINE_RESULT'

type MachineResultMetadata = {
  readonly definition: {
    readonly initialState: unknown
    readonly reducer: unknown
    readonly resolver: unknown
    readonly validators: unknown
  }
  readonly fingerprint: string
  readonly initialStateSnapshot: unknown
  readonly stateSnapshot: unknown
  readonly validatorEntries: ReadonlyArray<readonly [string, unknown]>
}

type MachineResultKey = { readonly [MACHINE_RESULT]: true }

const machineResults = new WeakMap<MachineResultKey, MachineResultMetadata>()

export type MachineResult<S, A extends Action, C> = {
  readonly graph: Graph<A, C>
  readonly state: S
  readonly sequence: ReadonlyArray<Link<A, C>>
  readonly [MACHINE_RESULT]: true
}

export const makeMachine = <S, A extends Action, C>({
  initialState,
  reducer,
  resolver,
  validators,
}: MachineParams<S, A, C>) => {
  const definition = Object.freeze({ initialState, reducer, resolver, validators })

  const evaluate = (graph: Graph<A, C>, extendableLogger?: Logger) => {
    // extend the logger or generate a new one if none was passed in
    const logger =
      extendableLogger !== undefined
        ? extendableLogger.extend('makeMachine')
        : new Logger({ moduleName: 'auth:makeMachine' })

    // Validate the graph's integrity.
    const validation = validate(graph, validators, logger)
    if (!validation.isValid) {
      throw validation.error
    }

    // Use the filter & sequencer to turn the graph into an ordered sequence
    const sequence = getSequence(graph, resolver)
    const wrappedReducer = (state: S, link: Link<A, C>) => reducer(state, link, logger, graph)

    // Run the sequence through the reducer to calculate the current team state
    const state = sequence.reduce(wrappedReducer, initialState)
    return { sequence, state }
  }

  const derive = (graph: Graph<A, C>, extendableLogger?: Logger): MachineResult<S, A, C> => {
    const { sequence, state } = evaluate(graph, extendableLogger)
    const metadata = Object.freeze({
      definition,
      fingerprint: fingerprint(graph),
      initialStateSnapshot: cloneForReuse(initialState),
      stateSnapshot: cloneForReuse(state),
      validatorEntries: snapshotValidators(validators),
    })
    const result = Object.freeze({
      graph,
      state,
      sequence: Object.freeze(sequence),
      [MACHINE_RESULT]: true as const,
    })
    machineResults.set(result, metadata)
    return result
  }

  return Object.assign(
    (graph: Graph<A, C>, extendableLogger?: Logger) => evaluate(graph, extendableLogger).state,
    { derive }
  )
}

export const consumeMachineResult = <S, A extends Action, C>(
  result: MachineResult<S, A, C>,
  graph: Graph<A, C>,
  definition: MachineParams<S, A, C>
): boolean => {
  const metadata = machineResults.get(result)
  machineResults.delete(result)
  const matches =
    metadata !== undefined &&
    result.graph === graph &&
    metadata.definition.initialState === definition.initialState &&
    metadata.definition.reducer === definition.reducer &&
    metadata.definition.resolver === definition.resolver &&
    metadata.definition.validators === definition.validators &&
    metadata.fingerprint === fingerprint(result.graph) &&
    isEqual(metadata.initialStateSnapshot, definition.initialState) &&
    isEqual(metadata.stateSnapshot, result.state) &&
    validatorsMatch(metadata.validatorEntries, definition.validators)
  return matches
}

const fingerprint = <A extends Action, C>(graph: Graph<A, C>) =>
  hash(MACHINE_RESULT_HASH_PURPOSE, graph)

const cloneForReuse = <T>(value: T): T => {
  try {
    return structuredClone(value)
  } catch (error) {
    throw new Error('Reusable machine state must be structured-cloneable.', { cause: error })
  }
}

const snapshotValidators = (validators?: ValidatorSet): ReadonlyArray<readonly [string, unknown]> =>
  Object.freeze(
    Object.entries(validators ?? {})
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([name, validator]) => Object.freeze([name, validator] as const))
  )

const validatorsMatch = (
  snapshot: ReadonlyArray<readonly [string, unknown]>,
  validators?: ValidatorSet
): boolean => {
  const current = snapshotValidators(validators)
  return (
    snapshot.length === current.length &&
    snapshot.every(
      ([name, validator], index) => name === current[index][0] && validator === current[index][1]
    )
  )
}

export type MachineParams<S, A extends Action, C> = {
  initialState: S
  reducer: Reducer<S, A, C>
  resolver: Resolver<A, C>
  validators?: ValidatorSet
}
