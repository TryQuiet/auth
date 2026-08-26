import {
  append,
  createKeyring,
  createKeyset,
  decryptLink,
  verifyLinkSignature,
  type KeysetWithSecrets,
} from '@localfirst/crdx'
import { ADMIN } from 'role/index.js'
import type { TeamAction, TeamGraph } from 'team/types.js'
import { KeyType } from 'util/index.js'
import { setup } from 'util/testing/index.js'
import { describe, expect, it } from 'vitest'
import { expectRejectedEverywhere, forgedSigner } from './forgeHelpers.js'

/**
 * Where the security boundary actually is.
 *
 * The other tests forge as a current member, holding the team keyring. This one sharpens the threat
 * model on one point: *constructing* a forged link needs no team secret at all. The team's public
 * encryption key is stored in plaintext on every `EncryptedLink` as `recipientPublicKey`, and
 * `asymmetric.encryptBytes` encrypts *to* that public key with an attacker-generated sender secret.
 * So anyone who has merely seen the serialized graph — an ex-member, an invitee who was handed it,
 * a relay — can produce a well-formed link that a member's replica decrypts cleanly.
 *
 * That refines the README's "a non-member is cryptographically excluded" line. A non-member is
 * excluded from *reading* the graph and from *landing* a link (delivery needs an authenticated sync
 * connection or a trusting relay), but not from *building* one. Construction was never the
 * boundary; acceptance is, and acceptance is now a signature check against a registered key.
 */
describe('forged authorship — the non-member construction bar', () => {
  it('can be constructed with only the team’s public key, and still cannot be accepted', () => {
    const { alice, bob, eve } = setup('alice', 'bob', { user: 'eve', admin: false })

    // The team's public encryption key is plaintext on every link. No secret is needed to read it.
    const [anyHash] = alice.team.graph.head
    const { recipientPublicKey } = alice.team.graph.encryptedLinks[anyHash]

    // The attacker's keypair is freshly minted and has never been near this team.
    const attackerKeys = createKeyset({ type: KeyType.DEVICE, name: 'outsider' }, 'outsider-seed')

    const forged = append({
      graph: alice.team.graph,
      action: {
        type: 'ADD_MEMBER_ROLE',
        payload: { userId: eve.userId, roleName: ADMIN },
      } as TeamAction,

      // Claim 👩🏾 Alice's device — its id is knowable to anyone who has ever held the decrypted
      // graph — and sign with keys that are nobody's.
      signer: forgedSigner(alice.deviceId, attackerKeys),

      // Only the *public* half is supplied as the team keyset, which is what proves no team secret
      // is required to build a link a member will decrypt.
      keys: { encryption: { publicKey: recipientPublicKey } } as unknown as KeysetWithSecrets,
    }) as TeamGraph

    const [forgedHash] = forged.head
    const forgedLink = forged.encryptedLinks[forgedHash]

    // A member who receives this decrypts it without complaint, and reads Alice's device id off it.
    const recovered = decryptLink(forgedLink, createKeyring(alice.team.teamKeys()))
    expect(recovered.body.signer.id).toBe(alice.deviceId)

    // The signature is real — it just belongs to the wrong key. This is the whole difference
    // between the two worlds: there is now something on the link that only Alice could have made.
    expect(
      verifyLinkSignature({
        hash: recovered.hash,
        signature: recovered.signature,
        publicKey: attackerKeys.signature.publicKey,
      })
    ).toBe(true)
    expect(
      verifyLinkSignature({
        hash: recovered.hash,
        signature: recovered.signature,
        publicKey: alice.device.keys.signature.publicKey,
      })
    ).toBe(false)

    expectRejectedEverywhere({
      forged,
      teamKeys: alice.team.teamKeys(),
      peers: [alice, bob],
      message: /signature does not verify/,
    })

    expect(alice.team.memberIsAdmin(eve.userId)).toBe(false)
  })

  it('cannot be accepted even when the attacker invents an identity of their own', () => {
    const { alice, bob } = setup('alice', 'bob')
    const [anyHash] = alice.team.graph.head
    const { recipientPublicKey } = alice.team.graph.encryptedLinks[anyHash]

    // Rather than impersonating anybody, the outsider signs as itself with a self-consistent id —
    // the fingerprint really is of the key it signs with. Being internally consistent is not the
    // same as being registered: a team's members are the ones its graph says they are.
    const attackerKeys = createKeyset({ type: KeyType.DEVICE, name: 'outsider' }, 'outsider-seed')

    const forged = append({
      graph: alice.team.graph,
      action: { type: 'ADD_ROLE', payload: { roleName: 'managers' } } as TeamAction,
      signer: forgedSigner('an-id-of-my-own-choosing', attackerKeys),
      keys: { encryption: { publicKey: recipientPublicKey } } as unknown as KeysetWithSecrets,
    }) as TeamGraph

    expectRejectedEverywhere({
      forged,
      teamKeys: alice.team.teamKeys(),
      peers: [alice, bob],
      message: /is not registered on this team/,
    })
  })

  it('CONTROL: the same link built the same way, but signed by a registered device, is accepted', () => {
    const { alice, bob } = setup('alice', 'bob')
    const [anyHash] = alice.team.graph.head
    const { recipientPublicKey } = alice.team.graph.encryptedLinks[anyHash]

    // Nothing about building a link outside the Team API is itself suspect — Alice's own device
    // does exactly this below and it lands. The signature is the only thing that ever mattered.
    const honest = append({
      graph: alice.team.graph,
      action: { type: 'ADD_ROLE', payload: { roleName: 'managers' } } as TeamAction,
      signer: alice.signer,
      keys: { encryption: { publicKey: recipientPublicKey } } as unknown as KeysetWithSecrets,
    }) as TeamGraph

    bob.team.merge(honest)
    expect(bob.team.hasRole('managers')).toBe(true)
  })
})
