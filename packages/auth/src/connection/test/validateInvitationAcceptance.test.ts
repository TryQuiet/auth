import { getSequence, merge, redactKeys, type UserWithSecrets } from '@localfirst/crdx'
import { randomKey } from '@localfirst/crypto'
import { redactDevice, type DeviceWithSecrets } from 'device/index.js'
import {
  generateProof,
  type InvitationClaim,
  type InvitationV2,
  type ProofOfInvitationV2,
} from 'invitation/index.js'
import { ADMIN } from 'role/index.js'
import { membershipResolver } from 'team/membershipResolver.js'
import { serializeTeamGraph } from 'team/serialize.js'
import type { Team } from 'team/Team.js'
import type { TeamGraph } from 'team/types.js'
import { redactFirstUseDevice, setup } from 'util/testing/index.js'
import { describe, expect, it } from 'vitest'
import { createInvitationAcceptance, openInvitationAcceptance } from '../invitationAcceptance.js'
import { validateInvitationAcceptance } from '../validateInvitationAcceptance.js'

describe('exact effective invitation admission validation', () => {
  it('accepts exact member and device admissions', () => {
    const member = admittedMemberFixture()
    expect(validateFixture(member).isValid).toBe(true)

    const { bob } = setup('bob')
    const { seed } = bob.team.inviteDevice()
    const claim: InvitationClaim = {
      invitationKind: 'device',
      userName: bob.userName,
      device: redactFirstUseDevice(bob.phone!),
    }
    const proof = proofFor(seed, claim)
    const invitation = v2Invitation(bob.team, proof)
    bob.team.admitDevice(proof, claim.device, bob.userName, proof.acceptorNonce)

    expect(
      validateFixture({
        team: bob.team,
        senderDevice: bob.device,
        seed,
        invitation,
        proof,
        claim,
      }).isValid
    ).toBe(true)
  })

  it('rejects an identity that exists without an ADMIT action', () => {
    const { alice, bob } = setup('alice', { user: 'bob', member: false })
    const { seed } = alice.team.inviteMember()
    const claim = memberClaim(bob)
    const proof = proofFor(seed, claim)
    const invitation = v2Invitation(alice.team, proof)
    alice.team.addForTesting(bob.user, [], redactDevice(bob.device))

    expect(
      validateFixture({
        team: alice.team,
        senderDevice: alice.device,
        seed,
        invitation,
        proof,
        claim,
      }).isValid
    ).toBe(false)
  })

  it('rejects an identity admitted by another invitation ID', () => {
    const { alice, bob } = setup('alice', { user: 'bob', member: false })
    const first = alice.team.inviteMember()
    const second = alice.team.inviteMember()
    const claim = memberClaim(bob)
    const firstProof = proofFor(first.seed, claim)
    const secondProof = proofFor(second.seed, claim)
    const secondInvitation = v2Invitation(alice.team, secondProof)
    alice.team.admitMember(
      firstProof,
      claim.userKeys,
      claim.userName,
      claim.device,
      firstProof.acceptorNonce
    )

    expect(
      validateFixture({
        team: alice.team,
        senderDevice: alice.device,
        seed: second.seed,
        invitation: secondInvitation,
        proof: secondProof,
        claim,
      }).isValid
    ).toBe(false)
  })

  it('rejects a matching invitation ID with different public keys', () => {
    const fixture = admittedMemberFixture()
    const changedClaim: InvitationClaim = {
      ...fixture.claim,
      userKeys: {
        ...fixture.claim.userKeys,
        signature: randomKey(),
      },
    }

    expect(validateFixture({ ...fixture, claim: changedClaim }).isValid).toBe(false)
  })

  it('rejects a matching device found under the wrong member', () => {
    const { alice, bob } = setup('alice', 'bob')
    const { seed } = bob.team.inviteDevice()
    const claim: InvitationClaim = {
      invitationKind: 'device',
      userName: bob.userName,
      device: redactFirstUseDevice(bob.phone!),
    }
    const proof = proofFor(seed, claim)
    const invitation = v2Invitation(bob.team, proof)
    const wrongOwnerDevice = {
      ...redactDevice(bob.phone!),
      userId: alice.userId,
    }
    bob.team.addForTesting(alice.user, [], wrongOwnerDevice)

    expect(
      validateFixture({
        team: bob.team,
        senderDevice: bob.device,
        seed,
        invitation,
        proof,
        claim,
      }).isValid
    ).toBe(false)
  })

  it('rejects a raw matching admission invalidated by the membership resolver', () => {
    const { alice, bob, charlie } = setup('alice', 'bob', {
      user: 'charlie',
      member: false,
    })
    alice.team.removeMemberRole(bob.userId, ADMIN)

    const { seed } = bob.team.inviteMember()
    const claim = memberClaim(charlie)
    const proof = proofFor(seed, claim)
    const invitation = v2Invitation(bob.team, proof)
    bob.team.admitMember(proof, claim.userKeys, claim.userName, claim.device, proof.acceptorNonce)

    const graph = merge(alice.team.graph, bob.team.graph) as TeamGraph
    const sequence = getSequence(graph, membershipResolver)
    expect(
      sequence.some(
        link =>
          link.body.type === 'ADMIT_MEMBER' && link.body.payload.id === proof.id && link.isInvalid
      )
    ).toBe(true)

    expect(
      validateFixture({
        team: bob.team,
        senderDevice: bob.device,
        seed,
        invitation,
        proof,
        claim,
        serializedGraph: serializeTeamGraph(graph),
        teamKeyring: {
          ...alice.team.teamKeyring(),
          ...bob.team.teamKeyring(),
        },
      }).isValid
    ).toBe(false)
  })

  it('rejects an admission followed by removal', () => {
    const fixture = admittedMemberFixture()
    fixture.team.remove(fixture.claim.userKeys.name)

    expect(validateFixture(fixture).isValid).toBe(false)
  })

  it('accepts only the matching admission from a multi-use member invitation', () => {
    const { alice, bob, eve } = setup(
      'alice',
      { user: 'bob', member: false },
      { user: 'eve', member: false }
    )
    const { seed } = alice.team.inviteMember({ maxUses: 0 })
    const invitationId = alice.team.getInvitation(proofFor(seed, memberClaim(bob)).id)
    if (invitationId.version !== 2) {
      throw new Error('Expected a version 2 invitation')
    }

    const bobClaim = memberClaim(bob)
    const bobProof = proofFor(seed, bobClaim)
    alice.team.admitMember(
      bobProof,
      bobClaim.userKeys,
      bobClaim.userName,
      bobClaim.device,
      bobProof.acceptorNonce
    )
    const eveClaim = memberClaim(eve)
    const eveProof = proofFor(seed, eveClaim)
    alice.team.admitMember(
      eveProof,
      eveClaim.userKeys,
      eveClaim.userName,
      eveClaim.device,
      eveProof.acceptorNonce
    )

    for (const fixture of [
      {
        team: alice.team,
        senderDevice: alice.device,
        seed,
        invitation: invitationId,
        proof: bobProof,
        claim: bobClaim,
      },
      {
        team: alice.team,
        senderDevice: alice.device,
        seed,
        invitation: invitationId,
        proof: eveProof,
        claim: eveClaim,
      },
    ]) {
      expect(validateFixture(fixture).isValid).toBe(true)
    }
  })
})

type Fixture = {
  team: Team
  senderDevice: DeviceWithSecrets
  seed: string
  invitation: InvitationV2
  proof: ProofOfInvitationV2
  claim: InvitationClaim
  serializedGraph?: Uint8Array
  teamKeyring?: ReturnType<Team['teamKeyring']>
}

const validateFixture = ({
  team,
  senderDevice,
  seed,
  invitation,
  proof,
  claim,
  serializedGraph = team.save(),
  teamKeyring = team.teamKeyring(),
}: Fixture) => {
  const payload = createInvitationAcceptance({
    invitation,
    proof,
    claim,
    senderDevice,
    serializedGraph,
    teamKeyring,
  })
  const acceptance = openInvitationAcceptance({
    payload,
    invitationSeed: seed,
    proof,
    claim,
  })
  return validateInvitationAcceptance({
    acceptance,
    payload,
    proof,
    claim,
  })
}

const admittedMemberFixture = (): Fixture & {
  claim: Extract<InvitationClaim, { invitationKind: 'member' }>
} => {
  const { alice, bob } = setup('alice', { user: 'bob', member: false })
  const { seed } = alice.team.inviteMember()
  const claim = memberClaim(bob)
  const proof = proofFor(seed, claim)
  const invitation = v2Invitation(alice.team, proof)
  alice.team.admitMember(proof, claim.userKeys, claim.userName, claim.device, proof.acceptorNonce)
  return {
    team: alice.team,
    senderDevice: alice.device,
    seed,
    invitation,
    proof,
    claim,
  }
}

const memberClaim = ({
  user,
  device,
}: {
  user: Pick<UserWithSecrets, 'userName' | 'keys'>
  device: DeviceWithSecrets
}): Extract<InvitationClaim, { invitationKind: 'member' }> => ({
  invitationKind: 'member',
  userName: user.userName,
  userKeys: redactKeys(user.keys),
  device: redactDevice(device),
})

const proofFor = (seed: string, claim: InvitationClaim) =>
  generateProof({
    seed,
    claim,
    acceptorNonce: randomKey(),
    inviteeNonce: randomKey(),
  })

const v2Invitation = (team: Team, proof: ProofOfInvitationV2) => {
  const invitation = team.getInvitation(proof.id)
  if (invitation.version !== 2) {
    throw new Error('Expected a version 2 invitation')
  }
  return invitation
}
