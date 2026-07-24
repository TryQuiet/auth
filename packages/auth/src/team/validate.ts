import { debug, Logger, truncateHashes } from '@localfirst/shared'
import { ROOT } from '@localfirst/crdx'
import { invitationCanBeUsed } from 'invitation/index.js'
import { VALID, ValidationError, actionFingerprint } from 'util/index.js'
import { isAdminOnlyAction } from './isAdminOnlyAction.js'
import * as select from './selectors/index.js'
import {
  type TeamLink,
  type TeamState,
  type TeamStateValidator,
  type TeamStateValidatorSet,
} from './types.js'

export const validate: TeamStateValidator = (previousState: TeamState, link: TeamLink, extendableLogger?: Logger) => {
  const logger = extendableLogger != null ? extendableLogger.extend('validate') : new Logger({ moduleName: 'auth:validate' })
  logger.debug('Validating link')
  for (const key in validators) {
    const validator = validators[key]
    const validation = validator(previousState, link, logger)
    if (!validation.isValid) {
      return validation
    }
  }

  return VALID
}

export const canUserAddMemberToRole = (roleName: string, assigningUserId: string, previousState: TeamState): boolean => {
    const metadata = select.getMetadata(previousState)
    if (metadata.selfAssignableRoles.includes(roleName)) {
      return true
    }
    if (select.memberIsAdmin(previousState, assigningUserId)) {
      return true
    }
    return false
  }

const validators: TeamStateValidatorSet = {
  /** The authenticated encryption key must belong to the user or server claimed by the action. */
  actionAuthorIsAuthenticated(
    previousState: TeamState,
    link: TeamLink,
    extendableLogger: Logger
  ) {
    const logger = extendableLogger.extend('actionAuthorIsAuthenticated')
    const { senderPublicKey } = link
    const { type, userId } = link.body

    if (type === ROOT) {
      const { rootMember } = link.body.payload
      if (
        userId !== rootMember.userId ||
        senderPublicKey !== rootMember.keys.encryption
      ) {
        return fail('Root action author does not match the founding member', previousState, link, logger)
      }
      return VALID
    }

    const matchingMembers = previousState.members.filter(member => member.userId === userId)
    const matchingServers = previousState.servers.filter(server => server.host === userId)
    const matchingAuthors = [...matchingMembers, ...matchingServers]

    if (matchingAuthors.length !== 1) {
      return fail(
        `Action author '${userId}' is unknown or ambiguous`,
        previousState,
        link,
        logger
      )
    }

    if (senderPublicKey !== matchingAuthors[0].keys.encryption) {
      return fail(
        `Action author '${userId}' did not authenticate with their current encryption key`,
        previousState,
        link,
        logger
      )
    }

    return VALID
  },

  rootDeviceBelongsToRootUser(previousState: TeamState, link: TeamLink, extendableLogger: Logger) {
    const logger = extendableLogger.extend('rootDeviceBelongsToRootUser')
    const { type, payload } = link.body
    if (type !== 'ROOT') return VALID

    const { rootDevice, rootMember } = payload
    if (rootDevice.userId !== rootMember.userId) {
      const msg = 'The founding device must belong to the founding member (userIds must match).'
      return fail(msg, previousState, link, logger)
    }
    return VALID
  },

  /** The user who made these changes was a member with appropriate rights at the time */
  mustBeAdmin(previousState: TeamState, link: TeamLink, extendableLogger: Logger) {
    const logger = extendableLogger.extend('mustBeAdmin')
    const action = link.body
    const { type, userId } = action

    // At root link, team doesn't yet have members
    if (type === ROOT) return VALID

    // Certain actions are allowed to be performed by non-members
    if (isAdminOnlyAction(action)) {
      const isntAdmin = !select.memberIsAdmin(previousState, userId)
      if (isntAdmin) {
        return fail(`Member '${userId}' is not an admin`, previousState, link, logger)
      }
    }
    return VALID
  },

  /** Unless I'm an admin, I can't remove anyone's devices but my own */
  canOnlyRemoveYourOwnDevices(previousState: TeamState, link: TeamLink, extendableLogger: Logger) {
    const logger = extendableLogger.extend('canOnlyRemoveYourOwnDevices')
    const author = link.body.userId

    // Only admins can remove another user's devices
    const authorIsAdmin = select.memberIsAdmin(previousState, author)
    if (authorIsAdmin) return VALID

    if (link.body.type === 'REMOVE_DEVICE') {
      const target = link.body.payload.deviceId
      const device = select.device(previousState, target)
      const deviceOwner = device.userId
      if (author !== deviceOwner) {
        return fail("Can't remove another user's device.", previousState, link, logger)
      }
    }
    return VALID
  },

  /** Unless I'm an admin, I can't change anyone's keys but my own */
  canOnlyChangeYourOwnKeys(previousState: TeamState, link: TeamLink, extendableLogger: Logger) {
    const logger = extendableLogger.extend('canOnlyChangeYourOwnKeys')
    const author = link.body.userId

    // Only admins can change another user's keys
    const authorIsAdmin = select.memberIsAdmin(previousState, author)
    if (!authorIsAdmin) {
      if (link.body.type === 'CHANGE_MEMBER_KEYS') {
        const target = link.body.payload.keys.name
        if (author !== target) {
          return fail("Can't change another user's keys.", previousState, link, logger)
        }
      } else if (link.body.type === 'CHANGE_SERVER_KEYS') {
        const target = link.body.payload.keys.name
        if (author !== target) {
          return fail("Can't change another server's keys.", previousState, link, logger)
        }
      }
    }
    return VALID
  },

  /** Check for ADMIT with invitations that are revoked OR have been used more than maxUses OR are expired */
  cantAdmitWithInvalidInvitation(previousState: TeamState, link: TeamLink, extendableLogger: Logger) {
    const logger = extendableLogger.extend('cantAdmitWithInvalidInvitation')
    if (link.body.type === 'ADMIT_MEMBER' || link.body.type === 'ADMIT_DEVICE') {
      const { id } = link.body.payload
      const invitation = select.getInvitation(previousState, id)
      return invitationCanBeUsed(invitation, link.body.timestamp)
    }
    return VALID
  },

  admissionMatchesInvitationKind(
    previousState: TeamState,
    link: TeamLink,
    extendableLogger: Logger
  ) {
    const logger = extendableLogger.extend('admissionMatchesInvitationKind')
    if (link.body.type !== 'ADMIT_MEMBER' && link.body.type !== 'ADMIT_DEVICE') {
      return VALID
    }

    const { id } = link.body.payload
    const invitation = select.getInvitation(previousState, id)
    const expectedKind = link.body.type === 'ADMIT_MEMBER' ? 'member' : 'device'
    if (invitation.kind !== expectedKind) {
      return fail(
        `${invitation.kind} invitation cannot be used by ${link.body.type}`,
        previousState,
        link,
        logger
      )
    }

    if (link.body.type === 'ADMIT_DEVICE') {
      if (!invitation.userId) {
        return fail('Device invitation has no owner', previousState, link, logger)
      }
      if (link.body.payload.device.userId !== invitation.userId) {
        return fail(
          'Admitted device owner does not match the invitation owner',
          previousState,
          link,
          logger
        )
      }
    }

    return VALID
  },

  /** Check for self-assigned roles that aren't in the allowed list set by the admin */
  nonAdminsCanOnlyModifyCertainRoles(previousState: TeamState, link: TeamLink, extendableLogger: Logger) {
    const logger = extendableLogger.extend('nonAdminsCanOnlyModifyCertainRoles')
    if (link.body.type === 'ADD_MEMBER_ROLE') {
      const { userId: assigningUserId } = link.body
      const { roleName } = link.body.payload
      if (canUserAddMemberToRole(roleName, assigningUserId, previousState)) return VALID
      return fail(`User ${assigningUserId} attempted to assign role ${roleName} illegally`, previousState, link, logger)
    }
    return VALID
  },
}

const fail = (message: string, previousState: TeamState, link: TeamLink, extendableLogger: Logger) => {
  const logger = extendableLogger.extend('fail')
  message = truncateHashes(`${actionFingerprint(link)} ${message}`)
  logger.error(message, link.hash)
  return {
    isValid: false,
    error: new ValidationError(message, { prevState: previousState, link }),
  }
}
