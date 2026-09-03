import { getSequence } from '@localfirst/crdx'
import type { Base58 } from '@localfirst/crypto'
import type { InvitationClaim } from 'invitation/index.js'
import { isEqual } from 'lodash-es'
import type { Team } from 'team/index.js'
import { membershipResolver } from 'team/membershipResolver.js'
import type { TeamLink } from 'team/types.js'

/**
 * Answers one question for the admitting side of a retried invitation handshake: is this exact
 * identity already registered on this team, by this invitation?
 *
 * Why it exists (private#203 / QSS-006, threat-model C3 and D5): admission is now gated on a
 * durable write, and a durable write can fail. When it does, the ADMIT link is already on the
 * in-memory graph — an append-only graph has no undo — but the invitee got nothing. The invitee
 * retries, and the naive path re-dispatches the same admission, which the `registeredIdsAreUnique`
 * validator rejects (`The id '…' is already in use`). That throw would turn a recoverable failure
 * into a permanent one: the invitee could never be admitted by this peer again. So a retry that
 * finds its own previous admission already on the graph must be able to skip straight to
 * persisting and sending the acceptance.
 *
 * The match has to be exact, because "skip the dispatch" means "hand over the team keys without
 * writing anything new". Two things must both hold:
 *
 *  1. An *effective* admission link (one that survives conflict resolution) consumed this exact
 *     invitation id carrying this exact signed claim. Provenance, not presence: a member who
 *     happens to hold the same id but was registered some other way is not this admission.
 *  2. The current team state registers exactly that identity — same keys, not removed. A
 *     tombstoned or re-keyed identity must fall through to the dispatch, where the uniqueness
 *     validator refuses it.
 *
 * Note what is deliberately NOT compared: the `ProofOfInvitation`. A proof is bound to the nonces
 * of the handshake that produced it, so a retry over a fresh connection necessarily carries a
 * different one. The claim is what names the identity being registered, and it is signed by the
 * invitee's own device key, so an exact claim match is what makes this idempotent rather than
 * merely similar.
 *
 * KNOWN GAP, on the invitee's side rather than this one. `validateInvitationAcceptance` requires
 * the graph it is handed to contain an effective admission carrying *this* handshake's exact
 * proof (rule 6, "presence is not provenance"). The link this function matches carries the
 * earlier handshake's, so an invitee that retries against an admitter still holding the failed
 * attempt in memory refuses the acceptance with ADMIT_MEMBER_LINK_MISSING — safe, but that
 * admitter can never admit that invitee again until its team is rebuilt from durable storage.
 * The recovery that does work is the one QSS-006 is actually about: an admitter that crashed
 * before the write restarts without the link and admits cleanly. Closing the remaining case means
 * choosing between relaxing rule 6 to "same invitation id, exact claim" (which drops the ADMIT
 * link's handshake binding while keeping the acceptance envelope's), having the admitter decline
 * outright when it finds an admission from a different handshake, or having applications reload
 * the team from durable storage after a failed write. That is a security decision, not a
 * refactor, so it is left to the engagement owner. See
 * test/persistAdmission.test.ts, which pins the current behaviour.
 */
export const findExistingAdmission = ({
  team,
  invitationId,
  claim,
}: {
  team: Team
  invitationId: Base58
  claim: InvitationClaim
}): TeamLink | undefined => {
  const admissionType = claim.invitationKind === 'member' ? 'ADMIT_MEMBER' : 'ADMIT_DEVICE'

  const admissions = getSequence(team.graph, membershipResolver).filter(
    link =>
      !link.isInvalid &&
      link.body.type === admissionType &&
      link.body.payload.id === invitationId &&
      isEqual(link.body.payload.claim, claim)
  )

  // More than one would mean the graph disagrees with itself about who was admitted; that is not a
  // state we can silently treat as "already done".
  if (admissions.length !== 1) return undefined

  return identityIsExactlyRegistered({ team, invitationId, claim }) ? admissions[0] : undefined
}

/** Whether the team's current state registers exactly the identity in `claim`, and it is live. */
const identityIsExactlyRegistered = ({
  team,
  invitationId,
  claim,
}: {
  team: Team
  invitationId: Base58
  claim: InvitationClaim
}): boolean => {
  if (claim.invitationKind === 'member') {
    const userId = claim.memberKeys.name
    if (!team.has(userId) || team.memberWasRemoved(userId)) return false

    const member = team.members(userId)
    if (member.userName !== claim.userName) return false
    if (!isEqual(member.keys, claim.memberKeys)) return false

    // The admission registers the member together with the one device they'll sign links with.
    return deviceIsExactlyRegistered(team, claim.device.deviceId, claim.device.keys, userId)
  }

  // A device invitation names its owner; the claim doesn't get a say (see `addInvitedDevice`).
  const { userId } = team.getInvitation(invitationId)
  if (userId === undefined) return false
  return deviceIsExactlyRegistered(team, claim.device.deviceId, claim.device.keys, userId)
}

const deviceIsExactlyRegistered = (
  team: Team,
  deviceId: string,
  keys: unknown,
  ownerUserId: string
): boolean => {
  if (!team.hasDevice(deviceId) || team.deviceWasRemoved(deviceId)) return false
  const device = team.device(deviceId)
  return device.userId === ownerUserId && isEqual(device.keys, keys)
}
