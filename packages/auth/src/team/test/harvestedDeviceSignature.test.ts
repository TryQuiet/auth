import {
  hashEncryptedLink,
  redactKeys,
  verifyLinkSignature,
  type EncryptedLink,
  type KeysetWithSecrets,
} from '@localfirst/crdx'
import { asymmetric } from '@localfirst/crypto'
import { pack, unpack } from 'msgpackr'
import { challenge, prove } from 'connection/identity.js'
import { ADMIN } from 'role/index.js'
import { SignerKind, type TeamAction, type TeamGraph } from 'team/types.js'
import { KeyType } from 'util/index.js'
import type { UserStuff } from 'util/testing/index.js'
import { setup } from 'util/testing/index.js'
import { describe, expect, it } from 'vitest'
import { expectRejectedEverywhere, forge, impersonate, linkBody, withInjectedLink } from './forgeHelpers.js'

/**
 * SECURITY PoC (post-fix) — a harvested device-key signature can no longer defeat the
 * device-signed-links fix.
 *
 * `signatures.sign(payload, secretKey)` used to be `crypto_sign_detached(msgpack(payload), secretKey)`
 * with NO domain/purpose tag. The device-signed-links fix (#46) authenticates a link's author by
 * verifying the link's signature against the signer's registered DEVICE key, over the base58 link
 * hash STRING (`crdx/linkSignature.ts` -> `team/validate.ts`). So a valid link signature was exactly
 * `signatures.sign(<a base58 string>, deviceSecretKey)`.
 *
 * The SAME device key signed, unseparated, the connection handshake's identity proof:
 *
 *     prove(challenge, keys) => signatures.sign(challenge, keys.signature.secretKey)  // connection/identity.ts
 *     // Connection.proveIdentity signs event.payload.challenge with no runtime shape check
 *
 * so an attacker acting as the identity CHALLENGER could send a `CHALLENGE_IDENTITY` whose
 * `challenge` is a bare base58 string equal to a link hash they chose, and the victim's device would
 * sign it — producing a signature byte-identical to one `crdx.append` makes for that link (#68 / PoC #70).
 *
 * The fix binds the purpose OUTSIDE the payload via mandatory domain-separation contexts:
 * `prove` now signs under `IDENTITY_CHALLENGE` and link authorship verifies under `LINK_AUTHORSHIP`,
 * so a signature harvested from the identity challenge no longer verifies as link authorship.
 *
 * BEFORE the fix (branch 185b650) the SECURITY assertions below were the opposite: the harvested
 * signature verified, and the forged link was ACCEPTED on a third party's live merge, on the
 * impersonated victim's own replica, and on a cold load from bytes and object form (including a
 * non-admin escalating to admin). This test now asserts the fix holds.
 *
 * NB: production (origin/main) is NOT vulnerable to this mechanism — it does not verify link
 * authorship cryptographically at all (authorizes off plaintext `body.userId`; see #46). This
 * harvest is FIX-INTRODUCED: reachable only because the fix adds a device-key signature check a
 * harvested signature could satisfy.
 */

/**
 * Forges a link authored as `victim`'s device, signed with a signature HARVESTED from the victim's
 * `prove` oracle — never with the victim's secret key at the attacker's own hand.
 *
 * The attacker only supplies `hash` and reads back `signature`; the `prove(hash, victim.device.keys)`
 * call here is the exact code that runs on the VICTIM's device inside `Connection.proveIdentity`,
 * fed the attacker's crafted string challenge.
 */
const forgeViaHarvestedSignature = ({
  graph,
  action,
  victim,
  attackerKeys,
  teamKeys,
}: {
  graph: TeamGraph
  action: TeamAction
  victim: UserStuff
  /** The attacker's own keypair — used only as the crypto_box sender; any keypair works. */
  attackerKeys: KeysetWithSecrets
  teamKeys: KeysetWithSecrets
}): TeamGraph => {
  const body = linkBody(graph, action, { kind: SignerKind.DEVICE, id: victim.deviceId })
  const encryptedBody = asymmetric.encryptBytes({
    secret: body,
    recipientPublicKey: teamKeys.encryption.publicKey,
    senderSecretKey: attackerKeys.encryption.secretKey,
  })
  const hash = hashEncryptedLink(encryptedBody)

  // HARVEST: the attacker sends `hash` as a bare-string CHALLENGE_IDENTITY over the wire. Model the
  // wire faithfully: the challenge survives the msgpackr codec unchanged, then the victim signs it.
  const challengeOffWire = unpack(pack(hash)) as typeof hash
  const signature = prove(challengeOffWire, victim.device.keys)

  const encryptedLink: EncryptedLink = {
    encryptedBody,
    signature,
    senderPublicKey: attackerKeys.encryption.publicKey,
    recipientPublicKey: teamKeys.encryption.publicKey,
  }
  return withInjectedLink(graph, { hash, body, encryptedLink })
}

describe('harvested device-key signature', () => {
  const ADD_MANAGERS = { type: 'ADD_ROLE', payload: { roleName: 'managers' } } as TeamAction

  it('SECURITY: prove() over an attacker-chosen string does NOT verify as a crdx link signature', () => {
    const { alice } = setup('alice')

    // An arbitrary base58 string the attacker would use as a link hash.
    const targetHash = '9nHq3xY2kV6pRtWfB8dLmNjQ4sZ7aC1eG5uH2iJ3kL' as any

    // The victim's device signs it through the identity oracle...
    const harvested = prove(targetHash, alice.device.keys)

    // ...but post-fix `prove` is bound to IDENTITY_CHALLENGE while link authorship is verified under
    // LINK_AUTHORSHIP, so the harvested signature is NOT a valid link signature. (Pre-fix this was true.)
    expect(
      verifyLinkSignature({
        hash: targetHash,
        signature: harvested,
        publicKey: redactKeys(alice.device.keys).signature,
      })
    ).toBe(false)
  })

  it('shape guard: a normal (object) identity challenge can NOT collide with a link hash', () => {
    // Independent of domain separation: msgpack tags an object with a map byte and a link hash is a
    // string, so their signed bytes can never be equal; and a bare string survives the wire codec.
    const objectChallenge = challenge({ type: KeyType.DEVICE, name: 'some-device-id' })
    const someHash = '9nHq3xY2kV6pRtWfB8dLmNjQ4sZ7aC1eG5uH2iJ3kL'
    expect(pack(objectChallenge)[0]).not.toEqual(pack(someHash)[0]) // map byte vs str byte
    expect(unpack(pack(someHash))).toEqual(someHash)
  })

  it('SECURITY: forged link rejected despite a harvested device-key signature', () => {
    const { alice, bob } = setup('alice', 'bob')

    // Bob forges a link that says it came from ALICE's device, using a signature harvested from
    // Alice's own `prove` oracle. Post-fix the harvested signature no longer verifies as authorship.
    const forged = forgeViaHarvestedSignature({
      graph: alice.team.graph,
      action: ADD_MANAGERS,
      victim: alice,
      attackerKeys: bob.device.keys,
      teamKeys: alice.team.teamKeys(),
    })

    expectRejectedEverywhere({
      forged,
      teamKeys: alice.team.teamKeys(),
      peers: [bob, alice],
      message: /does not verify against the keys registered/,
    })
    expect(bob.team.hasRole('managers')).toBe(false)
  })

  it('SECURITY: a non-admin can NOT escalate to admin via a harvested device-key signature', () => {
    const { alice, eve } = setup('alice', { user: 'eve', admin: false })
    expect(eve.team.memberIsAdmin(eve.userId)).toBe(false)

    // Eve authors an admin-only grant AS ALICE's device, using a signature harvested from Alice's oracle.
    const grantEveAdmin = {
      type: 'ADD_MEMBER_ROLE',
      payload: { userId: eve.userId, roleName: ADMIN, lockboxes: [] },
    } as TeamAction

    const forged = forgeViaHarvestedSignature({
      graph: alice.team.graph,
      action: grantEveAdmin,
      victim: alice,
      attackerKeys: eve.device.keys,
      teamKeys: alice.team.teamKeys(),
    })

    expectRejectedEverywhere({
      forged,
      teamKeys: alice.team.teamKeys(),
      peers: [eve, alice],
      message: /does not verify against the keys registered/,
    })
    expect(eve.team.memberIsAdmin(eve.userId)).toBe(false)
  })

  it('CONTROL: the same forgery WITHOUT a harvested signature is rejected by the fix', () => {
    const { alice, bob } = setup('alice', 'bob')

    // The naive forge the #46 fix is meant to stop: Bob signs with his OWN device key while claiming
    // Alice's device id. No harvest. The signature does not verify against Alice's registered key.
    const forged = forge({
      graph: alice.team.graph,
      action: ADD_MANAGERS,
      signer: impersonate(alice, bob),
      teamKeys: alice.team.teamKeys(),
    })

    expect(() => bob.team.merge(forged)).toThrow(/does not verify against the keys registered/)
    expect(bob.team.hasRole('managers')).toBe(false)
  })
})
