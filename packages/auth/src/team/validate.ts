import { Logger, truncateHashes } from '@localfirst/shared'
import { ROOT } from '@localfirst/crdx'
import { invitationCanBeUsed } from 'invitation/index.js'
import { KeyType, VALID, ValidationError, actionFingerprint } from 'util/index.js'
import { isActionAllowedWithMemberRole, isAdminOnlyAction } from './isAdminOnlyAction.js'
import * as select from './selectors/index.js'
import {
  type Member,
  type TeamAction,
  type TeamLink,
  type TeamState,
  type TeamStateValidator,
  type TeamStateValidatorSet,
} from './types.js'
import { ADMIN, MEMBER } from '../role/constants.js'
import { isActionAllowedWithoutLockboxes } from './lockboxesRequiredForAction.js'
import type { Lockbox } from '../lockbox/types.js'

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

const hasTeamLockbox = (userId: string, lockboxes: Lockbox[], checkGenerationNonZero = false): boolean => 
  lockboxes.find(l => l.contents.type === KeyType.TEAM && l.recipient.name === userId && (!checkGenerationNonZero || l.contents.generation > 0)) != null

const hasRoleLockbox = (userIdOrRoleName: string, roleName: string, lockboxes: Lockbox[], checkGenerationNonZero = false): boolean => 
  lockboxes.find(l => l.contents.type === KeyType.ROLE && l.contents.name === roleName && l.recipient.name === userIdOrRoleName  && (!checkGenerationNonZero || l.contents.generation > 0)) != null

const hasDeviceLockbox = (userId: string, deviceId: string, lockboxes: Lockbox[], checkGenerationNonZero = false): boolean => 
  lockboxes.find(l => l.contents.type === KeyType.USER && l.contents.name === userId && l.recipient.name === deviceId && (!checkGenerationNonZero || l.contents.generation > 0)) != null

const validateLockboxesOnChangeKeysOrRotateKeys = (actionType: 'CHANGE_MEMBER_KEYS' | 'ROTATE_KEYS', previousState: TeamState, userId: string, lockboxes: Lockbox[], link: TeamLink, logger: Logger) => {
  // ROTATE_KEYS can clean up access for an admission that conflict resolution already moved to
  // removedMembers; CHANGE_MEMBER_KEYS must still target an active member.
  const includeRemoved = actionType === 'ROTATE_KEYS'
  const [member] = select.members(previousState, [userId], { includeRemoved, throwOnMissing: false })
  if (member == null) {
    return fail(`${actionType} found no member for ID ${userId}`, previousState, link, logger)
  }
  const rolesForMember = select.rolesMemberIsIn(previousState, member.userId)
  for (const device of member.devices ?? []) {
    if (!hasDeviceLockbox(member.userId, device.deviceId, lockboxes, true)) {
      return fail(`${actionType} requires a device lockbox for all devices for the user`, previousState, link, logger)
    }
  }
  const members = select.allMembers(previousState, { includeRemoved: false })
  for (const m of members) {
    if (!hasTeamLockbox(m.userId, lockboxes, true)) {
      return fail(`${actionType} requires an updated team lockbox for all members`, previousState, link, logger)
    }
    for (const role of rolesForMember) {
      if (select.memberHasRole(previousState, m.userId, role.roleName) && !hasRoleLockbox(m.userId, role.roleName, lockboxes, true)) {
        return fail(`${actionType} requires an updated role lockbox for all roles for each member (offending role = ${role.roleName})`, previousState, link, logger)
      }
    }
  }
  const servers = select.servers(previousState, { includeRemoved: false, })
  for (const server of servers) {
    if (!hasTeamLockbox(server.host, lockboxes, true)) {
      return fail(`${actionType} requires an updated team lockbox for all servers`, previousState, link, logger)
    }
  }
  return VALID
}

export const canUserAddMemberToRole = (roleName: string, assigningUserId: string, previousState: TeamState): boolean => {
  const metadata = select.getMetadata(previousState)
  if (select.hasServer(previousState, assigningUserId)) {
    return false
  }
  if (!select.hasMember(previousState, assigningUserId)) {
    return false
  }
  if (metadata.selfAssignableRoles.includes(roleName)) {
    return true
  }
  if (select.memberIsAdmin(previousState, assigningUserId)) {
    return true
  }
  return false
}

const getCurrentMembersOfRole = (roleName: string, previousState: TeamState): Member[] => {
  return select.membersInRole(previousState, roleName)
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

  /** The user who made these changes was a member with the MEMBER role at the time */
  mustBeMember(previousState: TeamState, link: TeamLink, extendableLogger: Logger) {
    const logger = extendableLogger.extend('mustBeMember')
    const action = link.body
    const { type, userId } = action

    // At root link, team doesn't yet have members
    if (type === ROOT) return VALID

    if (select.memberIsAdmin(previousState, userId)) {
      return VALID
    }

    // Certain actions are allowed to be performed by non-members
    if (isActionAllowedWithMemberRole(action)) {
      const isntMember = !select.memberHasRole(previousState, userId, MEMBER)
      if (isntMember) {
        return fail(`User '${userId}' is missing the MEMBER role`, previousState, link, logger)
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
        if (select.hasServer(previousState, author)) {
          return fail("Can't change member keys as a server", previousState, link, logger)
        }
        const target = link.body.payload.keys.name
        if (author !== target) {
          return fail("Can't change another user's keys.", previousState, link, logger)
        }
      } else if (link.body.type === 'CHANGE_SERVER_KEYS') {
        if (!select.hasServer(previousState, author)) {
          return fail("Can't change server keys when not a server", previousState, link, logger)
        }
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

  /** ADD_MEMBER_TEST is a unit-test only convenience action */
  cantUseAddMemberTestInProduction(previousState: TeamState, link: TeamLink, extendableLogger: Logger) {
    const logger = extendableLogger.extend('cantUseAddMemberTestInProduction')
    if (link.body.type === 'ADD_MEMBER_TEST') {
      const { userId: assigningUserId } = link.body
      const { member } = link.body.payload
      if (process.env.ALLOW_ADD_MEMBER_TEST === 'true') return VALID
      return fail(`User ${assigningUserId} attempted to use the ADD_MEMBER_TEST action to add ${member.userId} in production`, previousState, link, logger)
    }
    return VALID
  },

  /** Validate the presence of lockboxes on an action payload when required */
  lockboxesArePresentWhenRequired(previousState: TeamState, link: TeamLink, extendableLogger: Logger) {
    const logger = extendableLogger.extend('lockboxesArePresentWhenRequired')
    const action = link.body
    if (isActionAllowedWithoutLockboxes(action)) {
      return VALID
    }
    const { lockboxes } = link.body.payload
    if (lockboxes == null) {
      return fail(`Action ${action.type} requires lockboxes but value on payload was nullish`, previousState, link, logger)
    }
    if (lockboxes.length === 0) {
      return fail(`Action ${action.type} requires lockboxes but value on payload was empty`, previousState, link, logger)
    }
    return VALID
  },

  /** Validate the presence of team and role lockboxes on ADD_MEMBER */
  correctLockboxesPresentOnAddMember(previousState: TeamState, link: TeamLink, extendableLogger: Logger) {
    const logger = extendableLogger.extend('correctLockboxesPresentOnAddMember')
    if (link.body.type === 'ADD_MEMBER') {
      const { lockboxes, roles, member } = link.body.payload
      if (!hasTeamLockbox(member.userId, lockboxes)) {
        return fail(`ADD_MEMBER requires a team lockbox for the added member`, previousState, link, logger)
      }
      for (const role of roles ?? []) {
        if (!hasRoleLockbox(member.userId, role, lockboxes)) {
          return fail(`ADD_MEMBER requires a lockbox for each role for the added member`, previousState, link, logger)
        }
      }
    }
    return VALID
  },

  /** Validate the presence of team and role lockboxes on ADMIT_MEMBER */
  correctLockboxesPresentOnAdmitMember(previousState: TeamState, link: TeamLink, extendableLogger: Logger) {
    const logger = extendableLogger.extend('correctLockboxesPresentOnAdmitMember')
    if (link.body.type === 'ADMIT_MEMBER') {
      const { lockboxes, memberKeys } = link.body.payload
      if (!hasTeamLockbox(memberKeys.name, lockboxes)) {
        return fail(`ADMIT_MEMBER requires a team lockbox for the admitted member`, previousState, link, logger)
      }
    }
    return VALID
  },

  /** Validate the presence of role lockboxes on REMOVE_MEMBER */
  correctLockboxesPresentOnRemoveMember(previousState: TeamState, link: TeamLink, extendableLogger: Logger) {
    const logger = extendableLogger.extend('correctLockboxesPresentOnRemoveMember')
    if (link.body.type === 'REMOVE_MEMBER') {
      const { lockboxes, userId } = link.body.payload
      const rolesMemberIsIn = select.rolesMemberIsIn(previousState, userId)
      for (const role of rolesMemberIsIn) {
        const membersInRole = getCurrentMembersOfRole(role.roleName, previousState)
        for (const member of membersInRole) {
          if (member.userId !== userId && !hasRoleLockbox(member.userId, role.roleName, lockboxes, true)) {
            return fail(`REMOVE_MEMBER requires a role lockbox for each member remaining in the role`, previousState, link, logger)
          }
        }
        if (role.roleName !== ADMIN && !hasRoleLockbox(ADMIN, role.roleName, lockboxes, true)) {
          return fail(`REMOVE_MEMBER requires a role lockbox for all roles for the ADMIN role`, previousState, link, logger)
        }
      }
      const allMembers = select.allMembers(previousState, { includeRemoved: false })
      for (const member of allMembers) {
        if (!hasTeamLockbox(member.userId, lockboxes, true)) {
          return fail(`REMOVE_MEMBER requires an updated team lockbox for all remaining members`, previousState, link, logger)
        }
      }
    }
    return VALID
  },

  /** Validate the presence of role lockboxes on ADD_MEMBER_ROLE */
  correctLockboxesPresentOnAddMemberRole(previousState: TeamState, link: TeamLink, extendableLogger: Logger) {
    const logger = extendableLogger.extend('correctLockboxesPresentOnAddMemberRole')
    if (link.body.type === 'ADD_MEMBER_ROLE') {
      const { lockboxes, userId, roleName } = link.body.payload
      if (!hasRoleLockbox(userId, roleName, lockboxes)) {
        return fail(`ADD_MEMBER_ROLE requires a lockbox for the role being added`, previousState, link, logger)
      }
    }
    return VALID
  },

  /** Validate the presence of role lockboxes on REMOVE_MEMBER_ROLE */
  correctLockboxesPresentOnRemoveMemberRole(previousState: TeamState, link: TeamLink, extendableLogger: Logger) {
    const logger = extendableLogger.extend('correctLockboxesPresentOnRemoveMemberRole')
    if (link.body.type === 'REMOVE_MEMBER_ROLE') {
      const { lockboxes, userId, roleName } = link.body.payload
      const membersInRole = getCurrentMembersOfRole(roleName, previousState)
      for (const member of membersInRole) {
        if (member.userId !== userId && !hasRoleLockbox(member.userId, roleName, lockboxes, true)) {
          return fail(`REMOVE_MEMBER_ROLE requires a role lockbox for each member remaining in the role`, previousState, link, logger)
        }
      }
    }
    return VALID
  },

  /** Validate the presence of role lockboxes on ADD_ROLE */
  correctLockboxesPresentOnAddRole(previousState: TeamState, link: TeamLink, extendableLogger: Logger) {
    const logger = extendableLogger.extend('correctLockboxesPresentOnAddRole')
    if (link.body.type === 'ADD_ROLE') {
      const { lockboxes, roleName } = link.body.payload
      if (!hasRoleLockbox(ADMIN, roleName, lockboxes)) {
        return fail(`ADD_ROLE requires a role lockbox for the ${ADMIN} role`, previousState, link, logger)
      }
    }
    return VALID
  },

  /** Validate the presence of role lockboxes on ADD_DEVICE */
  correctLockboxesPresentOnAddDevice(previousState: TeamState, link: TeamLink, extendableLogger: Logger) {
    const logger = extendableLogger.extend('correctLockboxesPresentOnAddDevice')
    if (link.body.type === 'ADD_DEVICE') {
      const { lockboxes, device } = link.body.payload
      if (!hasDeviceLockbox(device.userId, device.deviceId, lockboxes)) {
        return fail(`ADD_DEVICE requires a device lockbox for the user`, previousState, link, logger)
      }
    }
    return VALID
  },

  /** Validate the presence of role lockboxes on REMOVE_DEVICE */
  correctLockboxesPresentOnRemoveDevice(previousState: TeamState, link: TeamLink, extendableLogger: Logger) {
    const logger = extendableLogger.extend('correctLockboxesPresentOnRemoveDevice')
    if (link.body.type === 'REMOVE_DEVICE') {
      const { lockboxes, deviceId, updatedUserKeys = [] } = link.body.payload
      const member = select.memberByDeviceId(previousState, deviceId)
      if (updatedUserKeys.some(keys => keys.type !== KeyType.USER || keys.name !== member.userId)) {
        return fail(`REMOVE_DEVICE can only update keys for the removed device's owner`, previousState, link, logger)
      }
      logger.warn('lockboxes', lockboxes.map(l => JSON.stringify({ c: { id: l.contents.name, type: l.contents.type, gen: l.contents.generation }, r: { id: l.recipient.name, type: l.recipient.type, gen: l.recipient.generation }}, null, 2)))
      if (!hasTeamLockbox(member.userId, lockboxes, true)) {
        return fail(`REMOVE_DEVICE requires a team lockbox for the user`, previousState, link, logger)
      }
      const { devices, roles } = member
      const rolesMemberIsIn = select.rolesMemberIsIn(previousState, member.userId)
      for (const device of devices ?? []) {
        if (device.deviceId !== deviceId && !hasDeviceLockbox(member.userId, device.deviceId, lockboxes, true)) {
          return fail(`REMOVE_DEVICE requires a device lockbox for all remaining devices for the user`, previousState, link, logger)
        }
      }
      for (const role of rolesMemberIsIn) {
        if (!hasRoleLockbox(member.userId, role.roleName, lockboxes, true)) {
          return fail(`REMOVE_DEVICE requires a role lockbox for all roles for the user`, previousState, link, logger)
        }
        if (role.roleName !== ADMIN && !hasRoleLockbox(ADMIN, role.roleName, lockboxes, true)) {
          return fail(`REMOVE_DEVICE requires a role lockbox for all roles for the ADMIN role`, previousState, link, logger)
        }
      }
    }
    return VALID
  },

  /** Validate the presence of team and role lockboxes on ADD_SERVER */
  correctLockboxesPresentOnAddServer(previousState: TeamState, link: TeamLink, extendableLogger: Logger) {
    const logger = extendableLogger.extend('correctLockboxesPresentOnAddServer')
    if (link.body.type === 'ADD_SERVER') {
      const { lockboxes, server } = link.body.payload
      if (!hasTeamLockbox(server.host, lockboxes)) {
        return fail(`ADD_SERVER requires a team lockbox for the added server`, previousState, link, logger)
      }
    }
    return VALID
  },

  /** Validate the presence of team and role lockboxes on REMOVE_SERVER */
  correctLockboxesPresentOnRemoveServer(previousState: TeamState, link: TeamLink, extendableLogger: Logger) {
    const logger = extendableLogger.extend('correctLockboxesPresentOnRemoveServer')
    if (link.body.type === 'REMOVE_SERVER') {
      const { lockboxes, host } = link.body.payload
      const members = select.allMembers(previousState, { includeRemoved: false })
      for (const member of members) {
        if (!hasTeamLockbox(member.userId, lockboxes, true)) {
          return fail(`REMOVE_SERVER requires an updated team lockbox for all members`, previousState, link, logger)
        }
      }
      const servers = select.servers(previousState, { includeRemoved: false, })
      for (const server of servers) {
        if (server.host != host && !hasTeamLockbox(server.host, lockboxes, true)) {
          return fail(`REMOVE_SERVER requires an updated team lockbox for all remaining servers`, previousState, link, logger)
        }
      }
    }
    return VALID
  },

  /** Validate the presence of team and role lockboxes on CHANGE_MEMBER_KEYS */
  correctLockboxesPresentOnChangeMemberKeys(previousState: TeamState, link: TeamLink, extendableLogger: Logger) {
    const logger = extendableLogger.extend('correctLockboxesPresentOnChangeMemberKeys')
    if (link.body.type === 'CHANGE_MEMBER_KEYS') {
      const { lockboxes, keys } = link.body.payload
      return validateLockboxesOnChangeKeysOrRotateKeys('CHANGE_MEMBER_KEYS', previousState, keys.name, lockboxes, link, logger)
    }
    return VALID
  },

  /** Validate the presence of team and role lockboxes on ROTATE_KEYS */
  correctLockboxesPresentOnRotateKeys(previousState: TeamState, link: TeamLink, extendableLogger: Logger) {
    const logger = extendableLogger.extend('correctLockboxesPresentOnRotateKeys')
    if (link.body.type === 'ROTATE_KEYS') {
      const { lockboxes, userId } = link.body.payload
      return validateLockboxesOnChangeKeysOrRotateKeys('ROTATE_KEYS', previousState, userId, lockboxes, link, logger)
    }
    return VALID
  },

  /** Validate the presence of team and role lockboxes on CHANGE_SERVER_KEYS */
  correctLockboxesPresentOnChangeServerKeys(previousState: TeamState, link: TeamLink, extendableLogger: Logger) {
    const logger = extendableLogger.extend('correctLockboxesPresentOnChangeServerKeys')
    if (link.body.type === 'CHANGE_SERVER_KEYS') {
      const { lockboxes, keys } = link.body.payload
      const members = select.allMembers(previousState, { includeRemoved: false })
      for (const m of members) {
        if (!hasTeamLockbox(m.userId, lockboxes, true)) {
          return fail(`CHANGE_SERVER_KEYS requires an updated team lockbox for all members`, previousState, link, logger)
        }
      }
      const servers = select.servers(previousState, { includeRemoved: false, })
      for (const server of servers) {
        if (!hasTeamLockbox(server.host, lockboxes, true)) {
          return fail(`CHANGE_SERVER_KEYS requires an updated team lockbox for all servers`, previousState, link, logger)
        }
      }
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
