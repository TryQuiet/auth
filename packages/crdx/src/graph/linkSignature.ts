import { signatures, LINK_AUTHORSHIP } from '@localfirst/crypto'
import type { Base58, Hash } from 'util/types.js'
import { getLinkValidationOwner } from './validationOwner.js'

/**
 * Checks a link's signature against a public signing key.
 *
 * This is a pure function over material the caller has already resolved: the link's hash, the
 * signature carried alongside it, and the key the application has registered for the identity named
 * in `link.body.signer`. crdx deliberately doesn't do that resolution — knowing which key belongs
 * to a signer requires application state that crdx has no view of.
 */
export const verifyLinkSignature = ({
  hash,
  signature,
  publicKey,
  owner: inputOwner,
}: {
  /** The link's hash, which is what was signed. */
  hash: Hash

  /** The signature carried on the link. */
  signature: Base58 | undefined

  /** The public signature key registered for the link's claimed signer. */
  publicKey: Base58 | undefined

  /** Owned graph link keeping a reusable cryptographic fact alive across replay. */
  owner?: { hash: Hash }
}): boolean => {
  if (!signature || !publicKey) return false
  const owner = inputOwner === undefined ? undefined : getLinkValidationOwner(inputOwner)
  const cacheable =
    owner !== undefined &&
    typeof hash === 'string' &&
    typeof signature === 'string' &&
    typeof publicKey === 'string'
  if (cacheable) {
    const fact = validated.get(owner) ?? recentFacts.get(hash)?.deref()
    if (fact?.hash === hash && fact.signature === signature && fact.publicKey === publicKey) {
      remember(owner, fact)
      return true
    }
  }
  try {
    const valid = signatures.verify({
      payload: hash,
      signature,
      publicKey,
      context: LINK_AUTHORSHIP,
    })
    if (valid && cacheable) remember(owner, { hash, signature, publicKey })
    return valid
  } catch {
    // malformed base58 in either the signature or the key throws rather than returning false
    return false
  }
}

type SignatureFact = { hash: Hash; signature: Base58; publicKey: Base58 }
const validated = new WeakMap<{ hash: Hash }, SignatureFact>()
// Index the shared fact, not its latest (possibly temporary) owner. Any live graph owner keeps
// its fact available; once all owners are gone this bounded weak index cannot retain it.
const recentFacts = new Map<Hash, WeakRef<SignatureFact>>()
const MAX_RECENT_LINKS = 4096
const remember = (owner: { hash: Hash }, fact: SignatureFact) => {
  validated.set(owner, fact)
  if (typeof WeakRef !== 'function') return
  recentFacts.delete(fact.hash)
  recentFacts.set(fact.hash, new WeakRef(fact))
  if (recentFacts.size > MAX_RECENT_LINKS) recentFacts.delete(recentFacts.keys().next().value)
}
