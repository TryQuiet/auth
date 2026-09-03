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
  InvitationAcceptanceProtocolError,
  invitationAcceptanceSenderIsActive,
  openInvitationAcceptance,
} from './invitationAcceptance.js'
import type { AcceptInvitationPayload, InvitationAcceptanceEnvelope } from './message.js'

/**
 * How an invitee decides whether to trust the team it has just been handed.
 *
 * At this point the invitee's only trust anchors are the two values that came over the side
 * channel with the invite: the secret seed and the expected team id. The acceptance envelope has
 * already been authenticated and bound to this handshake (`openInvitationAcceptance`), but
 * everything INSIDE it — the graph and keyring — is still just data an untrusted acceptor chose
 * to send. This module decides whether that graph is the real team admitting this invitee, in
 * this session, as exactly the identity they claimed. The checks run in order, each mapped to a
 * failure reason the connection machine reports distinctly:
 *
 * 1. the outer and inner schemas are exactly v3 — else PROTOCOL_VERSION_UNSUPPORTED
 * 2. the envelope opened and is bound to this handshake — else ACCEPTANCE_INVALID
 * 3. the graph's root hash is the expected team id — else WRONG_TEAM
 * 4. the graph validates and contains this invitation with the claimed kind — else WRONG_TEAM
 * 5. the acceptance's sender is an active device in that graph — else SENDER_UNKNOWN
 * 6. exactly one effective (resolver-surviving) admission consumed this invitation id carrying
 *    this exact claim — else ADMISSION_INVALID
 * 7. the final state registers exactly the claimed identity — else ADMISSION_INVALID
 *
 * Merely appearing in the final state proves nothing — presence is not provenance. The specific
 * attacks each rule defeats are enumerated in test/validateInvitationAcceptance.test.ts.
 */
export type InvitationAcceptanceFailureReason =
  | 'ACCEPTANCE_INVALID'
  | 'PROTOCOL_VERSION_UNSUPPORTED'
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
    if (error instanceof InvitationAcceptanceProtocolError) {
      return invalid(
        'PROTOCOL_VERSION_UNSUPPORTED',
        'Invitation acceptance uses an unsupported protocol schema',
        { error }
      )
    }
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
 * team and contain exactly one effective admission that consumed this invitation carrying this
 * exact claim.
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

    // teamMachine authenticates and validates the graph before reducing it, but reduced state
    // cannot answer "which admission produced this member?" — the proof and claim live only on
    // the ADMIT links themselves. Run the resolver again to recover the effective sequence (the
    // links that survive conflict resolution) so admissions can be checked by provenance.
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

/**
 * What makes an admission *mine*: it consumed the invitation I am redeeming, and it registers the
 * exact identity I signed.
 *
 * The `ProofOfInvitation` is deliberately not compared. Binding the admission to this handshake's
 * nonces looks like a replay defence, but it buys no security property that the surrounding rules
 * don't already provide:
 *
 *  - The acceptance envelope is still bound to this handshake's nonces (rule 2), so an old
 *    *welcome* can't be replayed at me.
 *  - The graph root is pinned to the team I was invited to (rule 3).
 *  - The graph has already been fully validated (rule 4), and that validation verifies every
 *    ADMIT link's `possessionProof` against the signature key inside the link's own claim
 *    (team/validate.ts, `cantAdmitWithInvalidInvitation`). That signature can only be produced by
 *    the device being registered.
 *  - The claim names exactly my own keys, and rule 7 requires the final state to register exactly
 *    that identity.
 *
 * So an effective admission carrying my exact claim under my invitation id is necessarily one I
 * initiated myself, in some handshake. Demanding that it be *this* handshake bought nothing and
 * cost real availability: an admitter whose durable write failed still holds the admission in
 * memory, cannot append a second one (ids are unique), and so could never admit that invitee again
 * — permanently, and for a QSS-only community with no other admitter reachable, until the server
 * restarts. See private#203 / QSS-006 and invariant D5.
 */
const memberAdmissionMatches = (
  link: TeamLink,
  proof: ProofOfInvitation,
  claim: Extract<InvitationClaim, { invitationKind: 'member' }>
): boolean =>
  link.body.type === 'ADMIT_MEMBER' &&
  link.body.payload.id === proof.id &&
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
