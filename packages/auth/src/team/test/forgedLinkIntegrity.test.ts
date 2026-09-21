import { createKeyring, hashEncryptedLink } from '@localfirst/crdx'
import { asymmetric, signatures, LINK_AUTHORSHIP } from '@localfirst/crypto'
import * as teams from 'team/index.js'
import { serializeTeamGraph } from 'team/serialize.js'
import type { TeamAction } from 'team/types.js'
import { setup, type UserStuff } from 'util/testing/index.js'
import { describe, expect, it } from 'vitest'
import {
  buildEncryptedLink,
  expectRejectedEverywhere,
  forge,
  linkBody,
  withInjectedLink,
} from './forgeHelpers.js'

/**
 * The envelope itself: what happens when the three pieces of a link are pulled apart.
 *
 * A link is a body, a hash of the ciphertext of that body, and a signature over that hash. Honest
 * code makes all three in one breath, so an attacker's only opportunity is to mix and match — swap
 * the ciphertext under a hash, swap the signature under a hash, or reuse a real signature over a
 * hash it wasn't made for. Each has to fail, and none of them may be reachable by handing a peer
 * plaintext that disagrees with the bytes.
 */
describe('forged link integrity', () => {
  const ADD_MANAGERS = { type: 'ADD_ROLE', payload: { roleName: 'managers' } } as TeamAction

  /**
   * A link 👩🏾 Alice signed but hasn't published — it exists only in the copy of the graph handed
   * to the attacker, so no replica already holds the authentic version of it. That matters: a
   * tampered copy of a link you *already have* collides with it on hash and simply loses the merge,
   * which is correct but tests nothing. Interception in flight is the case with teeth.
   */
  const inFlight = (alice: UserStuff, action: TeamAction) =>
    forge({
      graph: alice.team.graph,
      action,
      signer: alice.signer,
      teamKeys: alice.team.teamKeys(),
    })

  it('rejects a link whose ciphertext was replaced under the same hash', () => {
    const { alice, bob, charlie } = setup('alice', 'bob', 'charlie')

    // 🦹‍♀️ In flight, the link's ciphertext is swapped for a new one saying something else. It's
    // encrypted correctly, to the right team, with a real member's sender key — it just isn't the
    // bytes this hash names.
    const tampered = inFlight(alice, ADD_MANAGERS)
    const [head] = tampered.head
    const body = { ...tampered.links[head].body } as any
    body.payload = { ...body.payload, roleName: 'attacker-chosen-role' }
    tampered.encryptedLinks[head].encryptedBody = asymmetric.encryptBytes({
      secret: body,
      recipientPublicKey: alice.team.teamKeys().encryption.publicKey,
      senderSecretKey: alice.device.keys.encryption.secretKey,
    })

    // A link *is* its hash. Rewriting what the hash points at doesn't rewrite the link.
    expectRejectedEverywhere({
      forged: tampered,
      teamKeys: alice.team.teamKeys(),
      peers: [bob, alice, charlie],
      message: /hash does not match/,
    })
    expect(bob.team.hasRole('attacker-chosen-role')).toBe(false)
    expect(bob.team.hasRole('managers')).toBe(false)
  })

  it('rejects a link whose ciphertext was corrupted in transit', () => {
    const { alice, bob, charlie } = setup('alice', 'bob', 'charlie')

    const tampered = inFlight(alice, ADD_MANAGERS)
    const [head] = tampered.head
    const bytes = new Uint8Array(tampered.encryptedLinks[head].encryptedBody)
    const byteIndex = bytes.length - 5
    bytes[byteIndex] = bytes[byteIndex] === 0 ? 1 : 0
    tampered.encryptedLinks[head].encryptedBody = bytes

    expectRejectedEverywhere({
      forged: tampered,
      teamKeys: alice.team.teamKeys(),
      peers: [bob, alice, charlie],
      message: /hash does not match/,
    })
  })

  it('rejects a link whose signature was replaced', () => {
    const { alice, bob, eve } = setup('alice', 'bob', { user: 'eve', admin: false })

    // The body and the hash are 👩🏾 Alice's, untouched. Only the signature is 🦹‍♀️ Eve's — made
    // over the correct hash, with the wrong key. Stripping a signature off a link you don't like
    // and putting your own on gets you nothing, because the key it's checked against is Alice's.
    const tampered = inFlight(alice, ADD_MANAGERS)
    const [head] = tampered.head
    const signature = signatures.sign(head, eve.device.keys.signature.secretKey, LINK_AUTHORSHIP)
    tampered.encryptedLinks[head].signature = signature
    tampered.links[head].signature = signature

    expectRejectedEverywhere({
      forged: tampered,
      teamKeys: alice.team.teamKeys(),
      peers: [bob, alice],
      message: /signature does not verify/,
    })
    expect(bob.team.hasRole('managers')).toBe(false)
  })

  it('keeps the authentic copy when a link a replica already holds arrives tampered', () => {
    const { alice, bob } = setup('alice', 'bob')
    alice.team.addRole('managers')

    // The other side of the same coin: 👩🏾 Alice has already accepted this link, and the tampered
    // copy carries the same hash — so it isn't a new link at all, it's a second claim about one she
    // has. Her own bytes win, and the attacker's contents never appear.
    const tampered = structuredClone(alice.team.graph)
    const [head] = tampered.head
    const body = { ...tampered.links[head].body } as any
    body.payload = { ...body.payload, roleName: 'attacker-chosen-role' }
    tampered.encryptedLinks[head].encryptedBody = asymmetric.encryptBytes({
      secret: body,
      recipientPublicKey: alice.team.teamKeys().encryption.publicKey,
      senderSecretKey: alice.device.keys.encryption.secretKey,
    })

    alice.team.merge(tampered)
    expect(alice.team.hasRole('managers')).toBe(true)
    expect(alice.team.hasRole('attacker-chosen-role')).toBe(false)

    // 👨🏻‍🦲 Bob, who has never seen the honest version, has no authentic copy to fall back on — so
    // for him it is a new link, and it fails on its own merits.
    expect(() => bob.team.merge(tampered)).toThrow(/hash does not match/)
    expect(bob.team.hasRole('attacker-chosen-role')).toBe(false)
  })

  it('rejects a genuine signature replayed onto a different link', () => {
    const { alice, bob } = setup('alice', 'bob')

    // 👩🏾 Alice honestly signs one link...
    const honest = forge({
      graph: alice.team.graph,
      action: ADD_MANAGERS,
      signer: alice.signer,
      teamKeys: alice.team.teamKeys(),
    })
    const [honestHash] = honest.head
    const aliceSignature = honest.encryptedLinks[honestHash].signature

    // ...and 🦹‍♀️ someone lifts that signature onto a link she never wrote. This is a *real*
    // signature by Alice's real key — it just covers a different hash, which is exactly why the
    // signature is over the hash and not over "some link by Alice".
    const forgedBody = linkBody(
      alice.team.graph,
      { type: 'ADD_MEMBER_ROLE', payload: { userId: bob.userId, roleName: 'ADMIN' } } as TeamAction,
      alice.signer.info
    )
    const built = buildEncryptedLink({
      body: forgedBody,
      teamKeys: alice.team.teamKeys(),
      senderKeys: alice.device.keys,
      signWith: alice.device.keys,
    })
    built.encryptedLink.signature = aliceSignature

    const forged = withInjectedLink(alice.team.graph, built)

    expectRejectedEverywhere({
      forged,
      teamKeys: alice.team.teamKeys(),
      peers: [bob, alice],
      message: /signature does not verify/,
    })
  })

  it('rejects the Diffie–Hellman sender-key swap', () => {
    const { alice, bob, eve } = setup('alice', 'bob', { user: 'eve', admin: false })
    const teamKeys = alice.team.teamKeys()

    // crypto_box derives the same shared secret from either direction of a keypair pair. So a
    // team-key holder can encrypt with (team secret, Alice's public key) and publish
    // `senderPublicKey: Alice`, and the recipient decrypts it with (team secret, Alice's public)
    // in the nominally opposite roles. That is why `senderPublicKey` can never identify an author,
    // and why the earlier attempt at this fix — comparing it to the registered key — didn't work.
    const body = linkBody(
      alice.team.graph,
      { type: 'ADD_MEMBER_ROLE', payload: { userId: eve.userId, roleName: 'ADMIN' } } as TeamAction,
      alice.signer.info
    )
    const encryptedBody = asymmetric.encryptBytes({
      secret: body,
      recipientPublicKey: alice.device.keys.encryption.publicKey,
      senderSecretKey: teamKeys.encryption.secretKey,
    })
    const hash = hashEncryptedLink(encryptedBody)

    const forged = withInjectedLink(alice.team.graph, {
      hash,
      body,
      encryptedLink: {
        encryptedBody,
        signature: signatures.sign(hash, eve.device.keys.signature.secretKey, LINK_AUTHORSHIP),
        senderPublicKey: alice.device.keys.encryption.publicKey,
        recipientPublicKey: teamKeys.encryption.publicKey,
      },
    })

    // The envelope passes every check that looks at the sender field; the signature is what stops it.
    expect(forged.encryptedLinks[hash].senderPublicKey).toBe(
      alice.team.members(alice.userId).devices![0].keys.encryption
    )

    expectRejectedEverywhere({
      forged,
      teamKeys,
      peers: [alice, bob],
      message: /signature does not verify/,
    })
    expect(alice.team.memberIsAdmin(eve.userId)).toBe(false)
  })

  it('ignores plaintext links supplied alongside the ciphertext', () => {
    const { alice, bob } = setup('alice', 'bob')
    alice.team.setTeamName('name authenticated by ciphertext')

    // A graph arrives from a peer with its `links` already decrypted — a convenience the sender
    // controls entirely. Nothing here is malformed; the attacker just wrote a different body next
    // to the real bytes and hoped we'd read that one.
    const withInjectedPlaintext = structuredClone(alice.team.graph)
    const [head] = withInjectedPlaintext.head
    const suppliedBody = withInjectedPlaintext.links[head].body
    if (suppliedBody.type !== 'SET_TEAM_NAME') throw new Error('expected SET_TEAM_NAME head')
    suppliedBody.payload.teamName = 'attacker-controlled plaintext'

    // Both acceptance paths rebuild the body from the ciphertext the hash commits to, so the link
    // is accepted — on its real contents.
    bob.team.merge(withInjectedPlaintext)
    expect(bob.team.teamName).toBe('name authenticated by ciphertext')

    const loaded = teams.load(
      withInjectedPlaintext,
      alice.localContext,
      createKeyring(alice.team.teamKeys())
    )
    expect(loaded.teamName).toBe('name authenticated by ciphertext')
  })

  it('CONTROL: a hand-built link that is internally consistent is accepted', () => {
    const { alice, bob } = setup('alice', 'bob')

    // Same construction as the forgeries above — outside the Team API, assembled by hand — but
    // with the ciphertext, the hash and the signature all agreeing. It lands.
    const body = linkBody(alice.team.graph, ADD_MANAGERS, alice.signer.info)
    const built = buildEncryptedLink({
      body,
      teamKeys: alice.team.teamKeys(),
      senderKeys: alice.device.keys,
      signWith: alice.device.keys,
    })
    const honest = withInjectedLink(alice.team.graph, built)

    bob.team.merge(honest)
    expect(bob.team.hasRole('managers')).toBe(true)

    const reloaded = teams.load(
      serializeTeamGraph(honest),
      bob.localContext,
      createKeyring(alice.team.teamKeys())
    )
    expect(reloaded.hasRole('managers')).toBe(true)
  })
})
