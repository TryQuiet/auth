// ignore file coverage
import {
  append,
  createKeyring,
  hashEncryptedLink,
  type EncryptedLink,
  type Hash,
  type Keyring,
  type KeysetWithSecrets,
  type Signer,
} from '@localfirst/crdx'
import { asymmetric, signatures, LINK_AUTHORSHIP } from '@localfirst/crypto'
import * as teams from 'team/index.js'
import { serializeTeamGraph } from 'team/serialize.js'
import {
  SignerKind,
  type TeamAction,
  type TeamGraph,
  type TeamLink,
  type TeamLinkBody,
} from 'team/types.js'
import type { UserStuff } from 'util/testing/index.js'
import { expect } from 'vitest'

/**
 * The forging kit for the attack suite.
 *
 * Every forgery in these tests is some variation on one move: write somebody else's identity into
 * `body.signer` and sign with your own keys. That used to be enough, because authorization read the
 * author out of the link body. Now a validator recomputes the fingerprint of the key registered for
 * `signer.id` and checks the link's signature against *that*, so the lie and the signature can no
 * longer both be true at once.
 */

/**
 * A signer that claims someone else's id.
 *
 * This is the whole attack in one function: `info.id` is the victim's, `keys` are the attacker's.
 * The link that comes out is well-formed, correctly encrypted to the team, and names the victim as
 * its author — it just isn't signed by the victim's key.
 */
export const forgedSigner = (
  victimId: string,
  attackerKeys: KeysetWithSecrets,
  kind: SignerKind = SignerKind.DEVICE
): Signer => ({ info: { kind, id: victimId }, keys: attackerKeys })

/** `attacker` signs a link that says it came from `victim`'s device. */
export const impersonate = (victim: UserStuff, attacker: UserStuff): Signer =>
  forgedSigner(victim.deviceId, attacker.device.keys)

/** Appends a link to a copy of `graph`, with whatever signer the caller wants to claim to be. */
export const forge = ({
  graph,
  action,
  signer,
  teamKeys,
}: {
  graph: TeamGraph
  action: TeamAction
  signer: Signer
  teamKeys: KeysetWithSecrets
}): TeamGraph => append({ graph, action, signer, keys: teamKeys }) as TeamGraph

/**
 * Builds an encrypted link by hand, without going through `append`.
 *
 * `append` always signs the hash of what it just encrypted, which is exactly what an attacker
 * wants to avoid doing. This lets a test drive the three parts apart — encrypt one body, sign a
 * different hash, publish a third set of bytes — which is what the tampering tests need.
 */
export const buildEncryptedLink = ({
  body,
  teamKeys,
  senderKeys,
  signWith,
}: {
  body: TeamLinkBody
  teamKeys: KeysetWithSecrets

  /** The crypto_box sender. Any keypair will do — the recipient derives the same shared secret. */
  senderKeys: KeysetWithSecrets

  /** The keys the signature is made with. */
  signWith: KeysetWithSecrets
}) => {
  const encryptedBody = asymmetric.encryptBytes({
    secret: body,
    recipientPublicKey: teamKeys.encryption.publicKey,
    senderSecretKey: senderKeys.encryption.secretKey,
  })
  const hash = hashEncryptedLink(encryptedBody)
  const encryptedLink: EncryptedLink = {
    encryptedBody,
    signature: signatures.sign(hash, signWith.signature.secretKey, LINK_AUTHORSHIP),
    senderPublicKey: senderKeys.encryption.publicKey,
    recipientPublicKey: teamKeys.encryption.publicKey,
  }
  return { hash, body, encryptedLink }
}

/**
 * Puts a hand-built link on a graph as its new head, in both the encrypted and the plaintext maps.
 *
 * The plaintext entry is the attacker's to write — that's the point of supplying it — and honest
 * code is supposed to throw it away and re-derive the body from the ciphertext.
 */
export const withInjectedLink = (
  graph: TeamGraph,
  { hash, body, encryptedLink }: { hash: Hash; body: TeamLinkBody; encryptedLink: EncryptedLink }
): TeamGraph => ({
  ...graph,
  head: [hash],
  encryptedLinks: { ...graph.encryptedLinks, [hash]: encryptedLink },
  links: {
    ...graph.links,
    [hash]: { hash, signature: encryptedLink.signature, body } as TeamLink,
  },
})

/** The link body `append` would have written, for tests that then build the envelope themselves. */
export const linkBody = (
  graph: TeamGraph,
  action: TeamAction,
  signer: Signer['info']
): TeamLinkBody =>
  ({
    ...action,
    signer,
    timestamp: Date.now(),
    prev: graph.head,
  }) as TeamLinkBody

/**
 * Asserts that a forged graph is refused on every path a peer could accept it by, and that nothing
 * it contains leaks into a replica that refused it.
 *
 * A forgery caught on live dispatch but waved through on load is still a working attack — an
 * attacker who can get the graph persisted and reloaded (a relay, a restart, a fresh peer syncing
 * from bytes) doesn't need the live path at all. So all of these have to hold:
 *
 *   - a third party merging it live,
 *   - the impersonated victim merging it live (they of all people know it's false),
 *   - a cold `load()` of the serialized bytes,
 *   - a `load()` of the object form, where the attacker also supplies the plaintext links.
 */
export const expectRejectedEverywhere = ({
  forged,
  teamKeys,
  peers,
  message,
}: {
  forged: TeamGraph

  /** Enough keys to decrypt the whole graph — pass a keyring if the team has re-keyed. */
  teamKeys: KeysetWithSecrets | Keyring

  /** Replicas that should reject a live merge. Include the impersonated victim. */
  peers: UserStuff[]

  /** The rejection we mean to be testing — not just "it threw something". */
  message: RegExp
}) => {
  for (const peer of peers) {
    const headBefore = peer.team.graph.head
    expect(() => peer.team.merge(forged)).toThrow(message)

    // A rejected merge is a non-event: the replica is exactly where it was.
    expect(peer.team.graph.head).toEqual(headBefore)
  }

  const [loader] = peers
  const keyring = createKeyring(teamKeys)
  expect(() => teams.load(serializeTeamGraph(forged), loader.localContext, keyring)).toThrow(
    message
  )
  expect(() => teams.load(forged, loader.localContext, keyring)).toThrow(message)
}
