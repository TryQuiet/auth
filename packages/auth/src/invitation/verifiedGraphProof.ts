import { hash, signatures, type SignedMessage, type Payload } from '@localfirst/crypto'
import { type TeamLink } from 'team/types.js'
import { pack, unpack } from 'msgpackr'

/** Cache only the signature fact, never invitation validity, identity, expiry or authorization.
 * The owning graph link keeps facts alive. Replayed links can find a still-owned identical proof
 * through a bounded weak index. Handshake callers without an owned graph link do not use it.
 */
export const verifyGraphProof = (input: SignedMessage, owner?: TeamLink): boolean => {
  if (owner === undefined) return signatures.verify(input)
  // Snapshot the exact complete input so caller-controlled nested values cannot alias the fact.
  const signed = unpack(pack(input)) as SignedMessage
  const identity = hash('localfirst-auth/verified-graph-proof', [
    signed.context,
    signed.payload,
    signed.signature,
    signed.publicKey,
  ] as Payload)
  const previousOwner = recentOwners.get(identity)?.deref()
  if (
    facts.get(owner)?.has(identity) === true ||
    (previousOwner !== undefined && facts.get(previousOwner)?.has(identity) === true)
  ) {
    remember(owner, identity)
    return true
  }
  const valid = signatures.verify(signed)
  if (valid) remember(owner, identity)
  return valid
}

const facts = new WeakMap<TeamLink, Set<string>>()
const recentOwners = new Map<string, WeakRef<TeamLink>>()
const remember = (owner: TeamLink, identity: string) => {
  const owned = facts.get(owner) ?? new Set<string>()
  owned.add(identity)
  if (owned.size > 8) owned.delete(owned.values().next().value)
  facts.set(owner, owned)
  if (typeof WeakRef !== 'function') return
  recentOwners.delete(identity)
  recentOwners.set(identity, new WeakRef(owner))
  if (recentOwners.size > 4096) recentOwners.delete(recentOwners.keys().next().value)
}
