import { challenge, prove, verify } from 'connection/identity.js'
import { ADMIN_SCOPE, TEAM_SCOPE } from 'team/index.js'
import { setup } from 'util/testing/index.js'
import 'util/testing/expect/toBeValid.js'
import { IDENTITY_CHALLENGE, signatures } from '@localfirst/crypto'
import { type KeyScope, KeyType, createKeyset, redactKeys } from '@localfirst/crdx'
import { describe, expect, it } from 'vitest'

const { bob, eve } = setup('alice', 'bob', 'eve')

const { USER } = KeyType

describe('identity', () => {
  it('accepts valid proof of identity', () => {
    const bobSecretKeys = bob.user.keys
    const bobPublicKeys = redactKeys(bob.user.keys)

    // 👨🏻‍🦲 Bob shows up and says he's Bob
    const bobsClaim: KeyScope = { type: USER, name: 'bob' }

    // 👩🏾 Alice asks maybe-Bob to prove it by sending him a document to sign
    const alicesChallenge = challenge(bobsClaim)

    // 👨🏻‍🦲 Bob submits proof
    const bobsProof = prove(alicesChallenge, bobSecretKeys)

    // 👩🏾 Alice checks his proof
    const validation = verify(alicesChallenge, bobsProof, bobPublicKeys)

    // ✅ Bob's proof checks out
    expect(validation).toBeValid()
  })

  it('rejects proof of identity with the wrong signature', () => {
    const eveSecretKeys = eve.user.keys
    const bobPublicKeys = redactKeys(bob.user.keys)

    // 🦹‍♀️ Eve shows up and says she's Bob
    const evesClaimToBeBob: KeyScope = { type: USER, name: 'bob' }

    // 👩🏾 Alice asks maybe-Bob to prove it by sending him a document to sign
    const alicesChallenge = challenge(evesClaimToBeBob)

    // 🦹‍♀️ Eve tries to submit proof
    const evesProof = prove(alicesChallenge, eveSecretKeys)

    // 👩🏾 Alice checks Eve's proof
    const validation = verify(alicesChallenge, evesProof, bobPublicKeys)

    // ❌ Eve's proof fails because she doesn't have Bob's secret signature key
    expect(validation).not.toBeValid()
  })

  it('rejects a legacy identity proof that does not commit to the negotiated protocol', () => {
    const alicesChallenge = challenge({ type: USER, name: 'bob' })
    const legacyProof = signatures.sign(
      alicesChallenge,
      bob.user.keys.signature.secretKey,
      IDENTITY_CHALLENGE
    )

    expect(verify(alicesChallenge, legacyProof, redactKeys(bob.user.keys))).not.toBeValid()
  })

  it('rejects a protocol 3 identity proof even if a relay rewrites its ready message', () => {
    const currentChallenge = challenge({ type: USER, name: 'bob' })
    const { type, name, nonce, timestamp } = currentChallenge
    const previousProof = signatures.sign(
      [3, type, name, nonce, timestamp],
      bob.user.keys.signature.secretKey,
      IDENTITY_CHALLENGE
    )

    expect(verify(currentChallenge, previousProof, redactKeys(bob.user.keys))).not.toBeValid()
  })

  it('rejects reused proof of identity', () => {
    const bobSecretKeys = bob.user.keys
    const bobPublicKeys = redactKeys(bob.user.keys)

    // 👨🏻‍🦲 Bob shows up and says he's Bob
    const bobsClaim: KeyScope = { type: USER, name: 'bob' }

    // 👩🏾 Alice asks maybe-Bob to prove it by sending him a document to sign
    const alicesChallengeToBob = challenge(bobsClaim)

    // 👨🏻‍🦲 Bob submits proof
    const bobsProof = prove(alicesChallengeToBob, bobSecretKeys)

    // 👩🏾 Alice checks his proof
    const validationOfBobsProof = verify(alicesChallengeToBob, bobsProof, bobPublicKeys)

    // ✅ Bob's proof checks out
    expect(validationOfBobsProof).toBeValid()

    // 👀 BUT! Eve intercepted Bob's proof, so she tries to re-use it

    // 🦹‍♀️ Eve shows up and says she's Bob
    const evesClaimToBeBob: KeyScope = { type: USER, name: 'bob' }

    // 👩🏾 Alice checks asks maybe-Bob to prove it by sending him a document to sign
    const alicesChallengeToEve = challenge(evesClaimToBeBob)

    // 🦹‍♀️ Eve submits the proof she intercepted from Bob
    const evesProof = bobsProof

    // 👩🏾 Alice checks Eve's proof
    const validationOfEvesProof = verify(alicesChallengeToEve, evesProof, bobPublicKeys)

    // ❌ FOILED AGAIN!! Eve's proof fails because the challenge she was given is different
    expect(validationOfEvesProof).not.toBeValid()
  })

  it('validates role membership', () => {
    const adminKeys = createKeyset(ADMIN_SCOPE)

    // 👨🏻‍🦲 Bob shows up and says he's an admin
    const bobsClaim = ADMIN_SCOPE

    // 👩🏾 Alice asks maybe-Bob to prove it by sending him a document to sign
    const alicesChallenge = challenge(bobsClaim)

    // 👨🏻‍🦲 Bob submits proof
    const bobsProof = prove(alicesChallenge, adminKeys)

    // 👩🏾 Alice checks his proof
    const validation = verify(alicesChallenge, bobsProof, redactKeys(adminKeys))

    // ✅ Bob's proof checks out
    expect(validation).toBeValid()
  })

  it('validates team membership', () => {
    const teamKeys = createKeyset(TEAM_SCOPE)

    // 👨🏻‍🦲 Bob shows up and says he's a USER of the team
    const bobsClaim = TEAM_SCOPE

    // 👩🏾 Alice asks maybe-Bob to prove it by sending him a document to sign
    const alicesChallenge = challenge(bobsClaim)

    // 👨🏻‍🦲 Bob submits proof
    const bobsProof = prove(alicesChallenge, teamKeys)

    // 👩🏾 Alice checks his proof
    const validation = verify(alicesChallenge, bobsProof, redactKeys(teamKeys))

    // ✅ Bob's proof checks out
    expect(validation).toBeValid()
  })
})
