import { append, createKeyring, createKeyset } from '@localfirst/crdx'
import { symmetric } from '@localfirst/crypto'
import * as lockbox from 'lockbox/index.js'
import * as teams from 'team/index.js'
import { serializeTeamGraph } from 'team/serialize.js'
import type { TeamAction } from 'team/types.js'
import { KeyType } from 'util/index.js'
import { setup } from 'util/testing/index.js'
import { describe, expect, it } from 'vitest'

/**
 * A generation number must identify ONE keyset. `authorizedLockboxes` polices who may introduce a
 * *new* generation of a shared key; these tests attack the other edge: re-publishing the *current*
 * generation with different key material. Key lookup indexes by generation, so if a later lockbox
 * could rebind an established generation to a new keypair, whoever appends last would own the key
 * — no admin rights needed, since ADD_LOCKBOXES rides on links any member can author.
 *
 * Scenario (found reviewing TryQuiet/private#80): Bob is removed from a role (a Quiet private
 * channel), which rotates the role key so future messages are hidden from him. He then appends a
 * lockbox that offers a keyset HE minted under the same generation number as the legitimate
 * rotated key. If honest clients adopted it, they would encrypt future channel traffic under
 * Bob's key.
 *
 * Both tests assert the full outcome, not just an error: the merge must succeed (an unauthorized
 * lockbox is dropped, never a validation throw — a throw would let Bob brick the graph for
 * everyone, see lockboxAuthorization.ts), the established key must survive, and a message
 * encrypted after the removal must be readable with the legitimate key and not with Bob's.
 *
 * Covers exactly this one attack surface — same-generation replacement by a removed role member.
 * Authorship forgery, higher-generation re-keys, and holder-set rules are covered by the
 * lockboxAuthorization / channel-takeover suites.
 */
describe('same-generation lockbox replacement', () => {
  const CHANNEL = 'private-channel-role'

  /** Bob had the role, was removed from it (rotating the role key), and preps his forged keyset. */
  const setupRemovedRoleMember = () => {
    const { alice, bob } = setup('alice', { user: 'bob', admin: false })
    const originalTeamKeys = alice.team.teamKeys()

    alice.team.addRole(CHANNEL)
    alice.team.addMemberRole(bob.userId, CHANNEL)
    bob.team = teams.load(
      serializeTeamGraph(alice.team.graph),
      bob.localContext,
      createKeyring(originalTeamKeys)
    )

    alice.team.removeMemberRole(bob.userId, CHANNEL)
    const legitimateKeys = alice.team.roleKeys(CHANNEL)
    bob.team.merge(alice.team.graph)
    // The rotation worked: Bob can no longer read the role keys.
    expect(() => bob.team.roleKeys(CHANNEL)).toThrow()

    // Bob mints his own keyset for the role at the SAME generation as the legitimate rotated key,
    // and boxes it for a legitimate current holder — mimicking what an honest re-distribution of
    // the current generation looks like.
    const evilKeys = createKeyset(
      { type: KeyType.ROLE, name: CHANNEL },
      'bob-controls-the-replacement'
    )
    evilKeys.generation = legitimateKeys.generation
    const currentRoleLockbox = bob.team.state.lockboxes.find(
      ({ contents }) =>
        contents.type === KeyType.ROLE &&
        contents.name === CHANNEL &&
        contents.generation === legitimateKeys.generation
    )
    expect(currentRoleLockbox).toBeDefined()

    /** Appends `forged` to Bob's copy of the graph, signed honestly as Bob. */
    const attackWith = (forged: lockbox.Lockbox) =>
      append({
        graph: bob.team.graph,
        action: { type: 'ADD_LOCKBOXES', payload: { lockboxes: [forged] } } as TeamAction,
        signer: bob.signer,
        keys: bob.team.teamKeys(),
      })

    return { alice, legitimateKeys, evilKeys, recipient: currentRoleLockbox!.recipient, attackWith }
  }

  it('a removed role member cannot rebind the current generation to a key they control', () => {
    const { alice, legitimateKeys, evilKeys, recipient, attackWith } = setupRemovedRoleMember()

    // The forged lockbox is honest about what it carries: its manifest advertises Bob's public
    // key. It is dropped because the generation is already bound to a different key.
    const attack = attackWith(lockbox.create(evilKeys, recipient))
    expect(() => alice.team.merge(attack)).not.toThrow()
    expect(alice.team.roleKeys(CHANNEL).encryption.publicKey).toBe(
      legitimateKeys.encryption.publicKey
    )

    const message = alice.team.encrypt('secret after removal', CHANNEL)
    expect(() => symmetric.decryptBytes(message.contents, evilKeys.secretKey)).toThrow()
    expect(symmetric.decryptBytes(message.contents, legitimateKeys.secretKey)).toBe(
      'secret after removal'
    )
  })

  it('nor by lying in the manifest about which key the lockbox contains', () => {
    const { alice, legitimateKeys, evilKeys, recipient, attackWith } = setupRemovedRoleMember()

    // Authorization reads the public manifest; only recipients can decrypt the payload. So this
    // lockbox claims the legitimate public key in its manifest while sealing Bob's keyset inside.
    // It passes the manifest-level generation check, but `lockbox.open` binds ciphertext to
    // manifest, so the conflicting key can neither be adopted nor poison key lookup.
    const disguised = lockbox.create(evilKeys, recipient)
    disguised.contents.publicKey = legitimateKeys.encryption.publicKey

    const attack = attackWith(disguised)
    expect(() => alice.team.merge(attack)).not.toThrow()
    expect(alice.team.roleKeys(CHANNEL).encryption.publicKey).toBe(
      legitimateKeys.encryption.publicKey
    )

    const message = alice.team.encrypt('secret after removal', CHANNEL)
    expect(() => symmetric.decryptBytes(message.contents, evilKeys.secretKey)).toThrow()
    expect(symmetric.decryptBytes(message.contents, legitimateKeys.secretKey)).toBe(
      'secret after removal'
    )
  })
})
