import { createKeyset, redactKeys, type UserWithSecrets } from '@localfirst/crdx'
import { randomKey } from '@localfirst/crypto'
import { describe, expect, test } from 'vitest'
import { createDevice, createFirstUseDevice, redactDevice } from 'device/index.js'
import { create, randomSeed, validate, validateClaim } from 'invitation/index.js'
import type { MemberInvitationClaim } from 'invitation/index.js'
import { KeyType } from 'util/index.js'
import 'util/testing/expect/toBeValid.js'
import {
  deviceClaim,
  deviceInvitationProof,
  invitationNonces,
  memberClaim,
  memberInvitationProof,
} from 'util/testing/invitationProof.js'

const createUser = (
  userName: string
): Pick<UserWithSecrets, 'userName' | 'keys'> & { userId: string } => {
  const userId = randomKey()
  return { userId, userName, keys: createKeyset({ type: KeyType.USER, name: userId }) }
}

const bob = createUser('bob')
const bobsLaptop = createDevice({ userId: bob.userId, deviceName: 'laptop' })

const eve = createUser('eve')
const evesLaptop = createDevice({ userId: eve.userId, deviceName: 'laptop' })

describe('invitations', () => {
  test('create invitation', () => {
    const invitation = create({ seed: randomSeed() })
    expect(invitation).toHaveProperty('id')
    expect(invitation.id).toHaveLength(15)
    expect(invitation).toHaveProperty('publicKey')
  })

  test('validate member invitation', () => {
    // 👩🏾 Alice generates a secret key and sends it to 👨🏻‍🦲 Bob via a trusted side channel.
    const seed = 'passw0rd'

    // 👩🏾 Alice posts an invitation derived from that key on the team's signature chain.
    const invitation = create({ seed })

    // 👨🏻‍🦲 Bob accepts the invitation, binding it to the identity he wants to register.
    const claim = memberClaim(bob, bobsLaptop)
    const nonces = invitationNonces()
    const proof = memberInvitationProof(seed, bob, bobsLaptop, nonces)

    // 👳🏽‍♂️ Charlie checks the proof against the invitation Alice posted.
    expect(validate(proof, invitation, claim, nonces.identityNonce)).toBeValid()
  })

  test('validate device invitation', () => {
    const seed = 'passw0rd'
    const invitation = create({ seed, userId: bob.userId })

    // Bob's phone doesn't know its own userId yet — the invitation record supplies it.
    const bobsPhone = createFirstUseDevice({ deviceName: 'phone' })
    const claim = deviceClaim(bobsPhone)
    const proof = deviceInvitationProof(seed, bobsPhone)

    expect(validate(proof, invitation, claim)).toBeValid()
  })

  test('you have to have the secret key to accept an invitation', () => {
    const invitation = create({ seed: 'passw0rd' })

    // 🦹‍♀️ Eve tries to accept the invitation without the invitation key
    const proof = memberInvitationProof('horsebatterycorrectstaple', eve, evesLaptop)
    expect(validate(proof, invitation, memberClaim(eve, evesLaptop))).not.toBeValid()
  })

  test('a proof is bound to the keys it was created for', () => {
    const seed = 'passw0rd'
    const invitation = create({ seed })
    const proof = memberInvitationProof(seed, bob, bobsLaptop)

    // 🦹‍♀️ Eve intercepts Bob's proof and tries to use it to register her own device...
    const substitutedDevice = { ...memberClaim(bob, bobsLaptop), device: redactDevice(evesLaptop) }
    expect(validate(proof, invitation, substitutedDevice)).not.toBeValid()

    // ...or her own member keys
    const substitutedKeys: MemberInvitationClaim = {
      ...memberClaim(bob, bobsLaptop),
      memberKeys: redactKeys(eve.keys),
    }
    expect(validate(proof, invitation, substitutedKeys)).not.toBeValid()

    // ...or just a different user name
    const substitutedName = { ...memberClaim(bob, bobsLaptop), userName: 'admin' }
    expect(validate(proof, invitation, substitutedName)).not.toBeValid()
  })

  test('a proof is bound to the handshake it was created for', () => {
    const seed = 'passw0rd'
    const invitation = create({ seed })
    const claim = memberClaim(bob, bobsLaptop)
    const proof = memberInvitationProof(seed, bob, bobsLaptop)

    // The proof is only good for the connection whose nonce it signed
    expect(validate(proof, invitation, claim, proof.identityNonce)).toBeValid()
    expect(validate(proof, invitation, claim, randomKey())).not.toBeValid()

    // Replaying it with a rewritten nonce breaks the signature
    const replayed = { ...proof, identityNonce: randomKey() }
    expect(validate(replayed, invitation, claim, replayed.identityNonce)).not.toBeValid()
  })

  test('rejects a proof with extra or missing fields', () => {
    const seed = 'passw0rd'
    const invitation = create({ seed })
    const claim = memberClaim(bob, bobsLaptop)
    const proof = memberInvitationProof(seed, bob, bobsLaptop)

    expect(validate({ ...proof, extra: 'junk' } as any, invitation, claim)).not.toBeValid()
    const { inviteeNonce: _inviteeNonce, ...incomplete } = proof
    expect(validate(incomplete as any, invitation, claim)).not.toBeValid()
  })
})

describe('validateClaim', () => {
  test('accepts well-formed claims', () => {
    expect(validateClaim(memberClaim(bob, bobsLaptop))).toBeValid()
    expect(validateClaim(deviceClaim(createFirstUseDevice({ deviceName: 'phone' })))).toBeValid()
  })

  test('rejects a device id that is not the fingerprint of its signature key', () => {
    const claim = memberClaim(bob, bobsLaptop)
    const forged = {
      ...claim,
      device: {
        ...claim.device,
        deviceId: 'chosen-by-eve',
        keys: { ...claim.device.keys, name: 'chosen-by-eve' },
      },
    }
    expect(validateClaim(forged)).not.toBeValid()
  })

  test('rejects device keys of the wrong type', () => {
    const claim = memberClaim(bob, bobsLaptop)
    expect(
      validateClaim({
        ...claim,
        device: { ...claim.device, keys: { ...claim.device.keys, type: KeyType.USER } },
      })
    ).not.toBeValid()
  })

  test('rejects device keys past generation 0', () => {
    const claim = memberClaim(bob, bobsLaptop)
    expect(
      validateClaim({
        ...claim,
        device: { ...claim.device, keys: { ...claim.device.keys, generation: 1 } },
      })
    ).not.toBeValid()
  })

  test('rejects member keys that the device does not belong to', () => {
    const claim = memberClaim(bob, bobsLaptop)
    expect(validateClaim({ ...claim, memberKeys: redactKeys(eve.keys) })).not.toBeValid()
  })

  test('rejects member keys past generation 0', () => {
    const claim = memberClaim(bob, bobsLaptop)
    expect(
      validateClaim({ ...claim, memberKeys: { ...claim.memberKeys, generation: 1 } })
    ).not.toBeValid()
  })

  test('rejects a device claim that supplies its own owner', () => {
    // The invitation says who a new device belongs to; an invitee saying so itself would let it
    // attach to any user.
    const claim = deviceClaim(bobsLaptop)
    expect(validateClaim({ ...claim, device: { ...claim.device, userId: eve.userId } } as any)) //
      .not.toBeValid()
  })

  test('rejects claims with extra or missing fields', () => {
    const claim = memberClaim(bob, bobsLaptop)
    expect(validateClaim({ ...claim, extra: 'junk' } as any)).not.toBeValid()

    const { memberKeys: _memberKeys, ...incomplete } = claim
    expect(validateClaim(incomplete as any)).not.toBeValid()

    expect(
      validateClaim({
        ...claim,
        device: { ...claim.device, keys: { ...claim.device.keys, extra: 'junk' } },
      } as any)
    ).not.toBeValid()
  })
})
