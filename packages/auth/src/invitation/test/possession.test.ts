import { createKeyset, redactKeys, type UserWithSecrets } from '@localfirst/crdx'
import { randomKey, signatures, DEVICE_POSSESSION } from '@localfirst/crypto'
import { describe, expect, test } from 'vitest'
import { createDevice, createFirstUseDevice, redactDevice } from 'device/index.js'
import {
  create,
  createPossessionProof,
  possessionProofPayload,
  validatePossessionProof,
} from 'invitation/index.js'
import { KeyType } from 'util/index.js'
import 'util/testing/expect/toBeValid.js'
import {
  deviceClaim,
  devicePossessionProof,
  memberClaim,
  memberPossessionProof,
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

const { id: invitationId } = create({ seed: 'passw0rd' })

describe('possession proofs', () => {
  test('a device proves possession of its own keys', () => {
    const claim = memberClaim(bob, bobsLaptop)
    const proof = memberPossessionProof(invitationId, bob, bobsLaptop)
    expect(validatePossessionProof({ invitationId, claim, proof })).toBeValid()
  })

  test('a first-use device proves possession before it has an owner', () => {
    const bobsPhone = createFirstUseDevice({ deviceName: 'phone' })
    const claim = deviceClaim(bobsPhone)
    const proof = devicePossessionProof(invitationId, bobsPhone)
    expect(validatePossessionProof({ invitationId, claim, proof })).toBeValid()
  })

  test('only the device keyholder can produce the proof', () => {
    // This is the property an invitation proof can't provide: whoever issued the invitation knows
    // the seed, so they can mint invitation proofs for any keys — but not this.
    const claim = memberClaim(bob, bobsLaptop)
    const forged = signatures.sign(
      possessionProofPayload(invitationId, claim),
      evesLaptop.keys.signature.secretKey,
      DEVICE_POSSESSION
    )
    expect(validatePossessionProof({ invitationId, claim, proof: forged })).not.toBeValid()
  })

  test('the proof is bound to the invitation it was made for', () => {
    const otherInvitation = create({ seed: 'other-passw0rd' })
    const claim = memberClaim(bob, bobsLaptop)
    const proof = memberPossessionProof(invitationId, bob, bobsLaptop)

    expect(
      validatePossessionProof({ invitationId: otherInvitation.id, claim, proof })
    ).not.toBeValid()
  })

  test('the proof is bound to the identity being registered', () => {
    const claim = memberClaim(bob, bobsLaptop)
    const proof = memberPossessionProof(invitationId, bob, bobsLaptop)

    // Swapping in different member keys, a different user name, or a different device all break
    // the binding — the admitting peer can't reuse Bob's proof to register something else.
    expect(
      validatePossessionProof({
        invitationId,
        claim: { ...claim, memberKeys: redactKeys(eve.keys) },
        proof,
      })
    ).not.toBeValid()

    expect(
      validatePossessionProof({ invitationId, claim: { ...claim, userName: 'admin' }, proof })
    ).not.toBeValid()

    expect(
      validatePossessionProof({
        invitationId,
        claim: { ...claim, device: redactDevice(evesLaptop) },
        proof,
      })
    ).not.toBeValid()
  })

  test('substituting device keys under the same deviceId is rejected', () => {
    // Eve keeps Bob's deviceId (so the graph record still looks like Bob's device) but swaps in
    // keys she holds. The id is the fingerprint of the key, so the claim no longer hangs together.
    const claim = memberClaim(bob, bobsLaptop)
    const substituted = {
      ...claim,
      device: {
        ...claim.device,
        keys: { ...redactDevice(evesLaptop).keys, name: bobsLaptop.deviceId },
      },
    }
    const proof = signatures.sign(
      possessionProofPayload(invitationId, substituted),
      evesLaptop.keys.signature.secretKey,
      DEVICE_POSSESSION
    )
    expect(validatePossessionProof({ invitationId, claim: substituted, proof })).not.toBeValid()
  })

  test('creating a proof for a device you are not is a programming error', () => {
    expect(() =>
      createPossessionProof({
        invitationId,
        claim: memberClaim(bob, bobsLaptop),
        device: evesLaptop,
      })
    ).toThrow()
  })
})
