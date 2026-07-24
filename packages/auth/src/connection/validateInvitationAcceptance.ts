import { getSequence } from '@localfirst/crdx'
import type { Logger } from '@localfirst/shared'
import type { InvitationClaim, ProofOfInvitationV2 } from 'invitation/index.js'
import { isEqual } from 'lodash-es'
import { membershipResolver } from 'team/membershipResolver.js'
import { deserializeTeamGraph } from 'team/serialize.js'
import { teamMachine } from 'team/teamMachine.js'
import type { TeamGraph, TeamLink, TeamState } from 'team/types.js'
import { ValidationError } from 'util/index.js'
import { invitationAcceptanceSenderIsActive } from './invitationAcceptance.js'
import type { AcceptInvitationPayload, InvitationAcceptance } from './message.js'

export type InvitationAcceptanceFailureReason =
  | 'WRONG_TEAM'
  | 'SENDER_UNKNOWN'
  | 'ADMISSION_INVALID'

export type InvitationAcceptanceValidation = {
  graph: TeamGraph
  state: TeamState
  admissionLink: TeamLink
}

export type InvitationAcceptanceValidationResult =
  | {
      isValid: true
      value: InvitationAcceptanceValidation
    }
  | {
      isValid: false
      reason: InvitationAcceptanceFailureReason
      error: ValidationError
    }

type ValidateInvitationAcceptanceOptions = {
  acceptance: InvitationAcceptance
  payload: AcceptInvitationPayload
  proof: ProofOfInvitationV2
  claim: InvitationClaim
  logger?: Logger
}

export const validateInvitationAcceptance = ({
  acceptance,
  payload,
  proof,
  claim,
  logger,
}: ValidateInvitationAcceptanceOptions): InvitationAcceptanceValidationResult => {
  let graph: TeamGraph
  let state: TeamState

  try {
    graph = deserializeTeamGraph(acceptance.serializedGraph, acceptance.teamKeyring)
    state = teamMachine(graph, logger)
  } catch (error) {
    return invalid('ADMISSION_INVALID', 'Invitation acceptance contains an invalid team graph', {
      error,
    })
  }

  const invitation = state.invitations[proof.id]
  if (invitation === undefined || invitation.kind !== claim.invitationKind) {
    return invalid(
      'WRONG_TEAM',
      'Invitation acceptance graph does not contain the claimed invitation'
    )
  }

  if (!invitationAcceptanceSenderIsActive(state, payload, acceptance)) {
    return invalid(
      'SENDER_UNKNOWN',
      'Invitation acceptance sender is not an active identity in the team graph'
    )
  }

  const sequence = getSequence(graph, membershipResolver)
  const effectiveLinks = sequence.filter(link => !link.isInvalid)
  const admissionLinks =
    claim.invitationKind === 'member'
      ? effectiveLinks.filter(link => memberAdmissionMatches(link, proof, claim))
      : effectiveLinks.filter(link => deviceAdmissionMatches(link, proof, claim, invitation.userId))

  if (admissionLinks.length !== 1) {
    return invalid(
      'ADMISSION_INVALID',
      `Expected one effective admission for invitation '${proof.id}', found ${admissionLinks.length}`
    )
  }

  const finalIdentityIsExact =
    claim.invitationKind === 'member'
      ? finalMemberIsExact(state, claim)
      : finalDeviceIsExact(state, claim, invitation.userId)

  if (!finalIdentityIsExact) {
    return invalid(
      'ADMISSION_INVALID',
      'The admitted identity is not uniquely active in the final team state'
    )
  }

  return {
    isValid: true,
    value: {
      graph,
      state,
      admissionLink: admissionLinks[0],
    },
  }
}

const memberAdmissionMatches = (
  link: TeamLink,
  proof: ProofOfInvitationV2,
  claim: Extract<InvitationClaim, { invitationKind: 'member' }>
): boolean =>
  link.body.type === 'ADMIT_MEMBER' &&
  link.body.payload.id === proof.id &&
  link.body.payload.userName === claim.userName &&
  isEqual(link.body.payload.memberKeys, claim.userKeys)

const deviceAdmissionMatches = (
  link: TeamLink,
  proof: ProofOfInvitationV2,
  claim: Extract<InvitationClaim, { invitationKind: 'device' }>,
  invitationUserId?: string
): boolean => {
  if (invitationUserId === undefined) {
    return false
  }

  return (
    link.body.type === 'ADMIT_DEVICE' &&
    link.body.payload.id === proof.id &&
    isEqual(link.body.payload.device, {
      ...claim.device,
      userId: invitationUserId,
    })
  )
}

const finalMemberIsExact = (
  state: TeamState,
  claim: Extract<InvitationClaim, { invitationKind: 'member' }>
): boolean => {
  const members = state.members.filter(member => member.userId === claim.userKeys.name)
  return (
    members.length === 1 &&
    members[0].userName === claim.userName &&
    isEqual(members[0].keys, claim.userKeys)
  )
}

const finalDeviceIsExact = (
  state: TeamState,
  claim: Extract<InvitationClaim, { invitationKind: 'device' }>,
  invitationUserId?: string
): boolean => {
  if (invitationUserId === undefined) {
    return false
  }

  const devices = state.members
    .flatMap(member => member.devices ?? [])
    .filter(device => device.deviceId === claim.device.deviceId)
  return (
    devices.length === 1 &&
    isEqual(devices[0], {
      ...claim.device,
      userId: invitationUserId,
    })
  )
}

const invalid = (
  reason: InvitationAcceptanceFailureReason,
  message: string,
  details?: unknown
): InvitationAcceptanceValidationResult => ({
  isValid: false,
  reason,
  error: new ValidationError(message, details),
})
