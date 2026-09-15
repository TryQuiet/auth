import { signatures, LINK_AUTHORSHIP } from '@localfirst/crypto'
import type { Base58, Hash } from 'util/types.js'

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
  owner,
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
  const cacheable =
    owner !== undefined &&
    typeof hash === 'string' &&
    typeof signature === 'string' &&
    typeof publicKey === 'string'
  if (cacheable) {
    const previousOwner = recentOwners.get(hash)?.deref()
    const fact =
      validated.get(owner) ??
      (previousOwner === undefined ? undefined : validated.get(previousOwner))
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
// The index is bounded and holds no link strongly. Facts expire with the graphs owning links.
const recentOwners = new Map<Hash, WeakRef<{ hash: Hash }>>()
const MAX_RECENT_LINKS = 4096
const remember = (owner: { hash: Hash }, fact: SignatureFact) => {
  validated.set(owner, fact)
  recentOwners.delete(fact.hash)
  recentOwners.set(fact.hash, new WeakRef(owner))
  if (recentOwners.size > MAX_RECENT_LINKS) recentOwners.delete(recentOwners.keys().next().value)
}
