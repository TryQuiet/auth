import { createKeyset, type KeysetWithSecrets } from '@localfirst/crdx'
import { redactDevice } from 'device/index.js'
import * as teams from 'team/index.js'
import {
  connect,
  disconnect,
  memberInvitationProof,
  setup,
  type UserStuff,
} from 'util/testing/index.js'
import { describe, expect, it } from 'vitest'

const MEMBER = 'MEMBER'

type Admitter = 'admin' | 'self' | 'peer'

type AdmissionRace = {
  admin: UserStuff
  peer: UserStuff
  self: UserStuff
  roleDecryptionKeys: KeysetWithSecrets
}

describe('concurrent member admission', () => {
  it('merges an admin admission with a self admission from a disparate peer', async () => {
    await expectAdmissionsToMerge('admin', 'self')
  })

  it('merges a self admission with a peer admission from a disparate peer', async () => {
    await expectAdmissionsToMerge('self', 'peer')
  })

  it('merges a peer admission with an admin admission from a disparate peer', async () => {
    await expectAdmissionsToMerge('peer', 'admin')
  })

  const expectAdmissionsToMerge = async (leftAdmitter: Admitter, rightAdmitter: Admitter) => {
    const race = createAdmissionRace()
    const left = admitMember(race, leftAdmitter)
    const right = admitMember(race, rightAdmitter)
    const disparateHeads = {
      [leftAdmitter]: left.team.graph.head,
      [rightAdmitter]: right.team.graph.head,
    }

    expect(left.team.graph.head).not.toEqual(right.team.graph.head)
    expectMemberRoleOnce(left, race.self.userId)
    expectMemberRoleOnce(right, race.self.userId)

    const connected = await connect(left, right)
    const mergeResult = {
      connected,
      admitters: [leftAdmitter, rightAdmitter],
      disparateHeads,
      mergedHead: left.team.graph.head,
    }
    console.info('Concurrent member admission merge result:', mergeResult)

    expect(connected).toBe(true)
    expect(left.team.graph.head).toEqual(right.team.graph.head)
    expectMemberRoleOnce(left, race.self.userId)
    expectMemberRoleOnce(right, race.self.userId)

    await disconnect(left, right)
  }

  const createAdmissionRace = (): AdmissionRace => {
    const {
      alice: admin,
      bob: peer,
      charlie: self,
    } = setup('alice', { user: 'bob', admin: false }, { user: 'charlie', member: false })

    // Establish the shared graph up to identity admission. Charlie exists as a member identity but
    // does not become a full community member until one of the peers grants the MEMBER role.
    admin.team.addRole(MEMBER)
    const roleDecryptionKeys = createKeyset(
      { type: 'MEMBER_ADMISSION_TEST', name: MEMBER },
      'member-admission-test'
    )
    admin.team.createLockbox(MEMBER, roleDecryptionKeys)
    const invitation = admin.team.inviteMember()
    const proof = memberInvitationProof(invitation.seed, self.user, self.device)
    admin.team.admitMember(proof, self.user.keys, self.userName, redactDevice(self.device))

    const teamKeyring = admin.team.teamKeyring()
    self.team = teams.load(admin.team.save(), self.localContext, teamKeyring)
    self.team.join(teamKeyring)
    const baselineGraph = self.team.save()
    admin.team = teams.load(baselineGraph, admin.localContext, teamKeyring)
    peer.team = teams.load(baselineGraph, peer.localContext, teamKeyring)
    self.team = teams.load(baselineGraph, self.localContext, teamKeyring)
    for (const participant of [admin, peer, self]) {
      participant.connectionContext = {
        user: participant.user,
        device: participant.device,
        team: participant.team,
      }
    }

    expect(admin.team.memberIsAdmin(admin.userId)).toBe(true)
    expect(peer.team.memberIsAdmin(peer.userId)).toBe(false)
    expect(admin.team.has(self.userId)).toBe(true)
    expect(admin.team.memberHasRole(self.userId, MEMBER)).toBe(false)

    return { admin, peer, self, roleDecryptionKeys }
  }

  const admitMember = (race: AdmissionRace, admitter: Admitter): UserStuff => {
    const { admin, peer, self, roleDecryptionKeys } = race
    switch (admitter) {
      case 'admin': {
        admin.team.addMemberRole(self.userId, MEMBER)
        return admin
      }

      case 'self': {
        self.team.addMemberRoleToSelf(MEMBER, roleDecryptionKeys)
        return self
      }

      case 'peer': {
        peer.team.addMemberRole(self.userId, MEMBER, roleDecryptionKeys)
        return peer
      }
    }
  }

  const expectMemberRoleOnce = (participant: UserStuff, memberId: string) => {
    expect(participant.team.members(memberId).roles.filter(role => role === MEMBER)).toEqual([
      MEMBER,
    ])
  }
})
