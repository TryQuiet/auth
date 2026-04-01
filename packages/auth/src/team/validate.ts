import { Logger, truncateHashes } from '@localfirst/shared'
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
import { RolePermissions } from 'role/constants.js'

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

const validators: TeamStateValidatorSet = {
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

  /** Check for self-assigned roles that aren't in the allowed list set by the admin */
  canOnlySelfAddCertainRoles(previousState: TeamState, link: TeamLink, extendableLogger: Logger) {
    const logger = extendableLogger.extend('canOnlySelfAddCertainRoles')
    if (link.body.type === 'ADD_MEMBER_ROLE') {
      const { userId: assigningUserId } = link.body
      const { userId, roleName } = link.body.payload
      if (userId !== assigningUserId) {
        return VALID
      }
      const metadata = select.getMetadata(previousState)
      if (metadata.selfAssignableRoles.includes(roleName)) {
        return VALID
      }
      const role = select.role(previousState, roleName)
      if (role.createdBy === assigningUserId) {
        return VALID
      } 
      return fail(`User ${userId} attempted to self-assign role ${roleName} illegally`, previousState, link, logger)
    }
    return VALID
  },

  /** Check for sub roles that are already on the parent role */
  cantReaddSubRoles(previousState: TeamState, link: TeamLink, extendableLogger: Logger) {
    const logger = extendableLogger.extend('cantReadSubRoles')
    if (link.body.type === 'ADD_SUB_ROLE') {
      const { parentRoleName, roleName } = link.body.payload
      const parentRole = select.role(previousState, parentRoleName)
      if (!parentRole.subRoles.includes(roleName)) {
        return VALID
      }
      return fail(`Role ${parentRoleName} already has ${roleName} as sub role`, previousState, link, logger)
    }
    return VALID
  },

  /** Check for sub roles that would create circular role dependencies */
  cantAddCircularSubRoles(previousState: TeamState, link: TeamLink, extendableLogger: Logger) {
    const logger = extendableLogger.extend('cantAddCircularSubRoles')
    if (link.body.type === 'ADD_SUB_ROLE') {
      const { parentRoleName, roleName } = link.body.payload
      if (parentRoleName === roleName) {
        return fail(`Role ${parentRoleName} can't have itself as sub role`, previousState, link, logger)
      }
      const parentRole = select.role(previousState, parentRoleName)
      const subRole = select.role(previousState, roleName)
      if (subRole.subRoles.includes(parentRoleName)) {
        return fail(`Intended sub role ${roleName} already has parent role ${parentRoleName} as its sub role`, previousState, link, logger)
      }
      if (parentRole.subRoles.includes(roleName)) {
        return fail(`Role ${parentRoleName} already has ${roleName} as sub role`, previousState, link, logger)
      }
      return VALID
    }
    return VALID
  },

  /** Check for roles that aren't allowed to have sub roles */
  canAddSubRolesToRole(previousState: TeamState, link: TeamLink, extendableLogger: Logger) {
    const logger = extendableLogger.extend('canAddSubRolesToRole')
    if (link.body.type === 'ADD_SUB_ROLE') {
      const { parentRoleName } = link.body.payload
      const { permissions: parentPermissions } = select.role(previousState, parentRoleName)
      if (parentPermissions?.[RolePermissions.CAN_HAVE_SUB_ROLES]) {
        return VALID
      }
      return fail(`Role ${parentRoleName} doesn't allow sub roles`, previousState, link, logger)
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
