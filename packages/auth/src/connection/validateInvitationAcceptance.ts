import { getSequence, type Base58 } from '@localfirst/crdx'
import type { Logger } from '@localfirst/shared'
import type { InvitationClaim, ProofOfInvitation } from 'invitation/index.js'
import { isEqual } from 'lodash-es'
import { membershipResolver } from 'team/membershipResolver.js'
import { deserializeTeamGraph } from 'team/serialize.js'
import { teamMachine } from 'team/teamMachine.js'
import type { TeamGraph, TeamLink, TeamState } from 'team/types.js'
import { ValidationError } from 'util/index.js'
import {
  invitationAcceptanceSenderIsActive,
  openInvitationAcceptance,
} from './invitationAcceptance.js'
import type { AcceptInvitationPayload, InvitationAcceptanceEnvelope } from './message.js'

export type InvitationAcceptanceFailureReason =
  | 'ACCEPTANCE_INVALID'
  | 'WRONG_TEAM'
  | 'SENDER_UNKNOWN'
  | 'ADMISSION_INVALID'

export type InvitationAcceptanceValidation = {
  acceptance: InvitationAcceptanceEnvelope
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
  acceptance: InvitationAcceptanceEnvelope
  payload: AcceptInvitationPayload
  proof: ProofOfInvitation
  claim: InvitationClaim
  expectedTeamId: Base58
  logger?: Logger
}

type ProcessInvitationAcceptanceOptions = Omit<
  ValidateInvitationAcceptanceOptions,
  'acceptance'
> & {
  invitationSeed: string
}

/** Opens the authenticated envelope exactly once, then validates the graph it contained. */
export const processInvitationAcceptance = ({
  payload,
  invitationSeed,
  proof,
  claim,
  expectedTeamId,
  logger,
}: ProcessInvitationAcceptanceOptions): InvitationAcceptanceValidationResult => {
  let acceptance: InvitationAcceptanceEnvelope
  try {
    acceptance = openInvitationAcceptance({ payload, invitationSeed, proof, claim })
  } catch (error) {
    return invalid('ACCEPTANCE_INVALID', 'Invitation acceptance could not be authenticated', {
      error,
    })
  }

  return validateInvitationAcceptance({
    acceptance,
    payload,
    proof,
    claim,
    expectedTeamId,
    logger,
  })
}

/**
 * Validates the graph returned to an invitee against independently authenticated handshake data.
 *
 * Merely finding the invitee in final state is insufficient: the graph must belong to the expected
 * team and contain exactly one effective admission carrying this handshake's exact proof and claim.
 */
export const validateInvitationAcceptance = ({
  acceptance,
  payload,
  proof,
  claim,
  expectedTeamId,
  logger,
}: ValidateInvitationAcceptanceOptions): InvitationAcceptanceValidationResult => {
  try {
    const graph = deserializeTeamGraph(acceptance.serializedGraph, acceptance.teamKeyring)
    if (graph.root !== expectedTeamId) {
      return invalid('WRONG_TEAM', 'Invitation acceptance graph has an unexpected team root')
    }

    // teamMachine authenticates and validates the graph before reducing it, but returns only the
    // reduced state; run the resolver again to recover the effective link sequence, which is where
    // admission provenance lives.
    const state = teamMachine(graph, logger)
    const effectiveLinks = getSequence(graph, membershipResolver).filter(link => !link.isInvalid)
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

    const admissionLinks = effectiveLinks.filter(link =>
      claim.invitationKind === 'member'
        ? memberAdmissionMatches(link, proof, claim)
        : deviceAdmissionMatches(link, proof, claim, invitation.userId)
    )

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
        acceptance,
        graph,
        state,
        admissionLink: admissionLinks[0],
      },
    }
  } catch (error) {
    return invalid('ADMISSION_INVALID', 'Invitation acceptance contains an invalid team graph', {
      error,
    })
  }
}

const memberAdmissionMatches = (
  link: TeamLink,
  proof: ProofOfInvitation,
  claim: Extract<InvitationClaim, { invitationKind: 'member' }>
): boolean =>
  link.body.type === 'ADMIT_MEMBER' &&
  link.body.payload.id === proof.id &&
  isEqual(link.body.payload.proof, proof) &&
  isEqual(link.body.payload.claim, claim)

const deviceAdmissionMatches = (
  link: TeamLink,
  proof: ProofOfInvitation,
  claim: Extract<InvitationClaim, { invitationKind: 'device' }>,
  invitationUserId?: string
): boolean =>
  invitationUserId !== undefined &&
  link.body.type === 'ADMIT_DEVICE' &&
  link.body.payload.id === proof.id &&
  isEqual(link.body.payload.proof, proof) &&
  isEqual(link.body.payload.claim, claim)

const finalMemberIsExact = (
  state: TeamState,
  claim: Extract<InvitationClaim, { invitationKind: 'member' }>
): boolean => {
  const members = state.members.filter(member => member.userId === claim.memberKeys.name)
  return (
    members.length === 1 &&
    members[0].userName === claim.userName &&
    isEqual(members[0].keys, claim.memberKeys)
  )
}

const finalDeviceIsExact = (
  state: TeamState,
  claim: Extract<InvitationClaim, { invitationKind: 'device' }>,
  invitationUserId?: string
): boolean => {
  if (invitationUserId === undefined) return false

  const devices = state.members
    .flatMap(member => member.devices ?? [])
    .filter(device => device.deviceId === claim.device.deviceId)
  if (devices.length !== 1) return false

  const device = devices[0]
  return (
    device.userId === invitationUserId &&
    device.deviceId === claim.device.deviceId &&
    device.deviceName === claim.device.deviceName &&
    device.created === claim.device.created &&
    isEqual(device.deviceInfo, claim.device.deviceInfo) &&
    isEqual(device.keys, claim.device.keys)
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
