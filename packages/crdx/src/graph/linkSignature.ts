import { signatures } from '@localfirst/crypto'
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
}: {
  /** The link's hash, which is what was signed. */
  hash: Hash

  /** The signature carried on the link. */
  signature: Base58 | undefined

  /** The public signature key registered for the link's claimed signer. */
  publicKey: Base58 | undefined
}): boolean => {
  if (!signature || !publicKey) return false
  try {
    return signatures.verify({ payload: hash, signature, publicKey })
  } catch {
    // malformed base58 in either the signature or the key throws rather than returning false
    return false
  }
}
