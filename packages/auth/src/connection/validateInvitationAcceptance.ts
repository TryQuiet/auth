import type { MachineResult } from '@localfirst/crdx'
import type { Logger } from '@localfirst/shared'
import type { InvitationClaim, ProofOfInvitationV2 } from 'invitation/index.js'
import { isEqual } from 'lodash-es'
import { deserializeTeamGraph } from 'team/serialize.js'
import { teamMachine } from 'team/teamMachine.js'
import type { TeamAction, TeamContext, TeamGraph, TeamLink, TeamState } from 'team/types.js'
import { ValidationError } from 'util/index.js'
import {
  invitationAcceptanceSenderIsActive,
  openInvitationAcceptance,
} from './invitationAcceptance.js'
import type { AcceptInvitationPayload, InvitationAcceptance } from './message.js'

export type InvitationAcceptanceFailureReason =
  | 'ACCEPTANCE_INVALID'
  | 'WRONG_TEAM'
  | 'SENDER_UNKNOWN'
  | 'ADMISSION_INVALID'

export type InvitationAcceptanceValidation = {
  acceptance: InvitationAcceptance
  graph: TeamGraph
  state: TeamState
  admissionLink: TeamLink
  machineResult: MachineResult<TeamState, TeamAction, TeamContext>
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

type ProcessInvitationAcceptanceOptions = Omit<
  ValidateInvitationAcceptanceOptions,
  'acceptance'
> & {
  invitationSeed: string
}

export const processInvitationAcceptance = ({
  payload,
  invitationSeed,
  proof,
  claim,
  logger,
}: ProcessInvitationAcceptanceOptions): InvitationAcceptanceValidationResult => {
  let acceptance: InvitationAcceptance
  try {
    acceptance = openInvitationAcceptance({
      payload,
      invitationSeed,
      proof,
      claim,
    })
  } catch (error) {
    logger?.error('Invalid invitation acceptance', error)
    return invalid('ACCEPTANCE_INVALID', 'Invitation acceptance could not be authenticated', {
      error,
    })
  }

  return validateInvitationAcceptance({ acceptance, payload, proof, claim, logger })
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
    const machineResult = teamMachine.derive(graph, logger)
    state = machineResult.state

    const effectiveLinks = machineResult.sequence.filter(link => !link.isInvalid)
    const admissionLinks =
      claim.invitationKind === 'member'
        ? effectiveLinks.filter(link => memberAdmissionMatches(link, proof, claim))
        : effectiveLinks.filter(link =>
            deviceAdmissionMatches(link, proof, claim, state.invitations[proof.id]?.userId)
          )

    return validateDerivedAcceptance({
      acceptance,
      payload,
      proof,
      claim,
      graph,
      state,
      machineResult,
      admissionLinks,
    })
  } catch (error) {
    return invalid('ADMISSION_INVALID', 'Invitation acceptance contains an invalid team graph', {
      error,
    })
  }
}

type ValidateDerivedAcceptanceOptions = ValidateInvitationAcceptanceOptions & {
  graph: TeamGraph
  state: TeamState
  machineResult: MachineResult<TeamState, TeamAction, TeamContext>
  admissionLinks: TeamLink[]
}

const validateDerivedAcceptance = ({
  acceptance,
  payload,
  proof,
  claim,
  graph,
  state,
  machineResult,
  admissionLinks,
}: ValidateDerivedAcceptanceOptions): InvitationAcceptanceValidationResult => {
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
      machineResult,
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
  isEqual(link.body.payload.proof, proof) &&
  isEqual(link.body.payload.claim, claim) &&
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
    isEqual(link.body.payload.proof, proof) &&
    isEqual(link.body.payload.claim, claim) &&
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
