import { createUser, redactKeys } from '@localfirst/crdx'
import { randomKey } from '@localfirst/crypto'
import { createDevice, redactDevice } from 'device/index.js'
import {
  create,
  generateProof,
  randomSeed,
  validate,
  type MemberInvitationClaim,
  type ProofOfInvitationV2,
} from 'invitation/index.js'
import { describe, expect, test } from 'vitest'

describe('invitations', () => {
  test('creates a v2 invitation with both starter public keys', () => {
    const invitation = create({ seed: randomSeed() })

    expect(invitation).toMatchObject({ version: 2 })
    expect(invitation.id).toHaveLength(15)
    expect(invitation.signaturePublicKey).toBeDefined()
    expect(invitation.encryptionPublicKey).toBeDefined()
  })

  test('validates a transcript-bound member proof', () => {
    const { seed, invitation, claim, proof } = fixture()

    expect(validate(proof, invitation, claim, proof.acceptorNonce).isValid).toBe(true)
    expect(
      validate(
        generateProof({ seed: `${seed}-wrong`, claim, ...nonces() }),
        invitation,
        claim
      )
    ).toMatchObject({ isValid: false })
  })

  test.each([
    'member encryption key',
    'member signature key',
    'device encryption key',
    'device signature key',
    'user name',
    'invitation kind',
    'acceptor nonce',
    'invitee nonce',
  ])('rejects a changed %s', field => {
    const { invitation, claim, proof } = fixture()
    const changedClaim = structuredClone(claim) as MemberInvitationClaim
    const changedProof = { ...proof }

    switch (field) {
      case 'member encryption key':
        changedClaim.userKeys.encryption = randomKey()
        break
      case 'member signature key':
        changedClaim.userKeys.signature = randomKey()
        break
      case 'device encryption key':
        changedClaim.device.keys.encryption = randomKey()
        break
      case 'device signature key':
        changedClaim.device.keys.signature = randomKey()
        break
      case 'user name':
        changedClaim.userName = 'mallory'
        break
      case 'invitation kind':
        ;(changedClaim as { invitationKind: string }).invitationKind = 'device'
        break
      case 'acceptor nonce':
        changedProof.acceptorNonce = randomKey()
        break
      case 'invitee nonce':
        changedProof.inviteeNonce = randomKey()
        break
    }

    expect(validate(changedProof, invitation, changedClaim).isValid).toBe(false)
  })

  test('rejects replay against a second request nonce', () => {
    const { invitation, claim, proof } = fixture()

    expect(validate(proof, invitation, claim, randomKey()).isValid).toBe(false)
  })

  test('rejects unknown versions and extra or missing proof fields', () => {
    const { invitation, claim, proof } = fixture()
    const unknownVersion = { ...proof, version: 3 } as unknown as ProofOfInvitationV2
    const extraField = { ...proof, extra: true }
    const { signature: _signature, ...missingField } = proof

    expect(validate(unknownVersion, invitation, claim).isValid).toBe(false)
    expect(validate(extraField, invitation, claim).isValid).toBe(false)
    expect(
      validate(missingField as unknown as ProofOfInvitationV2, invitation, claim)
    ).toMatchObject({ isValid: false })
  })
})

const fixture = () => {
  const seed = 'passw0rd'
  const invitation = create({ seed })
  const user = createUser('bob')
  const device = createDevice({ userId: user.userId, deviceName: 'laptop' })
  const claim: MemberInvitationClaim = {
    invitationKind: 'member',
    userName: user.userName,
    userKeys: redactKeys(user.keys),
    device: redactDevice(device),
  }
  const proof = generateProof({ seed, claim, ...nonces() })
  return { seed, invitation, claim, proof }
}

const nonces = () => ({
  acceptorNonce: randomKey(),
  inviteeNonce: randomKey(),
})
