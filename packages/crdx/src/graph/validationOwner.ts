import { type Hash } from 'util/types.js'

type Owner = { hash: Hash }

// Sequencing decorates links with context-dependent isInvalid flags. Those temporary copies
// must not become the sole owners of immutable crypto facts: the graph retains the input links.
const owners = new WeakMap<Owner, Owner>()

export const setLinkValidationOwner = (copy: Owner, original: Owner): void => {
  owners.set(copy, getLinkValidationOwner(original))
}

/** Selects a lifetime owner only. Callers must still bind every verification input to their fact. */
export const getLinkValidationOwner = (link: Owner): Owner => owners.get(link) ?? link
