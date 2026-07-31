import { redactKeys } from '@localfirst/crdx'
import { signatures } from '@localfirst/crypto'
import { redactDevice } from 'device/index.js'
import {
  deviceInvitationProof,
  memberInvitationProof,
  redactFirstUseDevice,
  setup,
} from 'util/testing/index.js'
import { describe, expect, it } from 'vitest'

describe('replicated invitation proofs', () => {
  it('rejects a raw ADMIT_MEMBER without a valid proof for its claim', () => {
    const { alice, bob, eve } = setup(
      'alice',
      { user: 'bob', member: false },
      'eve'
    )
    const { id, seed } = alice.team.inviteMember()
    const claim = {
      invitationKind: 'member' as const,
      userName: bob.userName,
      userKeys: redactKeys(bob.user.keys),
      device: redactDevice(bob.device),
    }
    const validProof = memberInvitationProof(seed, bob.user, bob.device)
    const forgedProof = {
      ...validProof,
      signature: signatures.sign(['forged'], eve.user.keys.signature.secretKey),
    }

    expect(() =>
      eve.team.merge(alice.team.graph).dispatch({
        type: 'ADMIT_MEMBER',
        payload: {
          id,
          userName: bob.userName,
          memberKeys: redactKeys(bob.user.keys),
          proof: forgedProof,
          claim,
        },
      })
    ).toThrow(/Admission does not contain a valid invitation proof/)
  })

  it('rejects a proof whose signed claim differs from the admitted identity', () => {
    const { alice, bob, charlie } = setup(
      'alice',
      { user: 'bob', member: false },
      { user: 'charlie', member: false }
    )
    const { id, seed } = alice.team.inviteMember()
    const proof = memberInvitationProof(seed, bob.user, bob.device)
    const claim = {
      invitationKind: 'member' as const,
      userName: bob.userName,
      userKeys: redactKeys(bob.user.keys),
      device: redactDevice(bob.device),
    }

    expect(() =>
      alice.team.dispatch({
        type: 'ADMIT_MEMBER',
        payload: {
          id,
          userName: charlie.userName,
          memberKeys: redactKeys(charlie.user.keys),
          proof,
          claim,
        },
      })
    ).toThrow(/Admission identity does not match its signed invitation claim/)
  })

  it('rejects a raw ADMIT_DEVICE without a valid proof for its claim', () => {
    const { alice, eve } = setup('alice', 'eve')
    const invitedDevice = alice.phone!
    const { id, seed } = alice.team.inviteDevice()
    const firstUseDevice = redactFirstUseDevice(invitedDevice)
    const claim = {
      invitationKind: 'device' as const,
      userName: alice.userName,
      device: firstUseDevice,
    }
    const validProof = deviceInvitationProof(seed, alice.userName, invitedDevice)
    const forgedProof = {
      ...validProof,
      signature: signatures.sign(['forged'], eve.user.keys.signature.secretKey),
    }

    expect(() =>
      eve.team.merge(alice.team.graph).dispatch({
        type: 'ADMIT_DEVICE',
        payload: {
          id,
          device: { ...firstUseDevice, userId: alice.userId },
          proof: forgedProof,
          claim,
        },
      })
    ).toThrow(/Admission does not contain a valid invitation proof/)
  })
})
