import { hash, signatures, type SignedMessage, type Payload } from '@localfirst/crypto'
import { type TeamLink } from '../team/types.js'
import { pack, unpack } from 'msgpackr'
import { getLinkValidationOwner } from '@localfirst/crdx'

/** Cache only the signature fact, never invitation validity, identity, expiry or authorization.
 * The owning graph link keeps facts alive. Replayed links can find a still-owned identical proof
 * through a bounded weak index. Handshake callers without an owned graph link do not use it.
 */
export const verifyGraphProof = (input: SignedMessage, inputOwner?: TeamLink): boolean => {
  if (inputOwner === undefined) return signatures.verify(input)
  const owner = getLinkValidationOwner(inputOwner)
  // Snapshot the exact complete input so caller-controlled nested values cannot alias the fact.
  const signed = unpack(pack(input)) as SignedMessage
  const identity = hash('localfirst-auth/verified-graph-proof', [
    signed.context,
    signed.payload,
    signed.signature,
    signed.publicKey,
  ] as Payload)
  const previous = facts.get(owner)?.get(identity) ?? recentFacts.get(identity)?.deref()
  if (previous !== undefined) {
    remember(owner, previous)
    return true
  }
  const valid = signatures.verify(signed)
  if (valid) remember(owner, { identity })
  return valid
}

type ProofFact = { identity: string }
const facts = new WeakMap<Record<string, unknown>, Map<string, ProofFact>>()
const recentFacts = new Map<string, WeakRef<ProofFact>>()
const remember = (owner: Record<string, unknown>, fact: ProofFact) => {
  const { identity } = fact
  const owned = facts.get(owner) ?? new Map<string, ProofFact>()
  owned.set(identity, fact)
  if (owned.size > 8) owned.delete(owned.keys().next().value)
  facts.set(owner, owned)
  if (typeof WeakRef !== 'function') return
  recentFacts.delete(identity)
  recentFacts.set(identity, new WeakRef(fact))
  if (recentFacts.size > 4096) recentFacts.delete(recentFacts.keys().next().value)
}
