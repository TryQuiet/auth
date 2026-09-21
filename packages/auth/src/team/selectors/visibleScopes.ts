import { type KeyScope } from '@localfirst/crdx'
import { type TeamState } from 'team/types.js'

export const visibleScopes = (state: TeamState, { type, name }: KeyScope): KeyScope[] => {
  // Scope traversal mirrors visibleKeys but does not have secret material available. Seed the
  // visited set with the starting scope so valid self/cyclic redistributions terminate and the
  // caller's own scope stays excluded from the result.
  const visited = new Set([scopeId({ type, name })])
  return collectVisibleScopes(state, { type, name }, visited)
}

const collectVisibleScopes = (
  state: TeamState,
  { type, name }: KeyScope,
  visited: Set<string>
): KeyScope[] => {
  // Find the keys that the given key can see
  const scopes = state.lockboxes
    .filter(({ recipient }) => recipient.type === type && recipient.name === name)
    .map(({ contents: { type, name } }) => ({ type, name }) as KeyScope)
    .filter(scope => {
      const id = scopeId(scope)
      if (visited.has(id)) return false

      visited.add(id)
      return true
    })

  // Recursively find all the keys that _those_ keys can see
  const derivedScopes = scopes.flatMap(scope => collectVisibleScopes(state, scope, visited))

  return [...scopes, ...derivedScopes]
}

const scopeId = ({ type, name }: KeyScope) => JSON.stringify([type, name])
