import { Logger, truncateHashes } from '@localfirst/shared'
import { ROOT, type Keyset } from '@localfirst/crdx'
import { invitationCanBeUsed } from 'invitation/index.js'
import { KeyType, VALID, ValidationError, actionFingerprint } from 'util/index.js'
import { isAdminOnlyAction } from './isAdminOnlyAction.js'
import * as select from './selectors/index.js'
import {
  type TeamLink,
  type TeamState,
  type TeamStateValidator,
  type TeamStateValidatorSet,
} from './types.js'

export const validate: TeamStateValidator = (previousState: TeamState, link: TeamLink, extendableLogger?: Logger) => {
  const logger = extendableLogger !== undefined ? extendableLogger.extend('validate') : new Logger({ moduleName: 'auth:validate' })
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

  identityKeyMetadataIsValid(previousState: TeamState, link: TeamLink, extendableLogger: Logger) {
    const logger = extendableLogger.extend('identityKeyMetadataIsValid')
    const { type, payload } = link.body

    const invalidInitialMember = (member: {
      userId: string
      keys: Keyset
      devices?: Array<{ deviceId: string; userId: string; keys: Keyset }>
    }) =>
      !keysetMatches(member.keys, KeyType.USER, member.userId, 0) ||
      (member.devices ?? []).some(
        device =>
          device.userId !== member.userId ||
          !keysetMatches(device.keys, KeyType.DEVICE, device.deviceId, 0)
      )

    if (type === ROOT) {
      const { rootMember, rootDevice } = payload
      if (
        invalidInitialMember(rootMember) ||
        !keysetMatches(rootDevice.keys, KeyType.DEVICE, rootDevice.deviceId, 0)
      ) {
        return fail('Root member or device key metadata is invalid', previousState, link, logger)
      }
    }

    if (type === 'ADD_MEMBER' && invalidInitialMember(payload.member)) {
      return fail('New member key metadata is invalid', previousState, link, logger)
    }

    if (
      type === 'ADMIT_MEMBER' &&
      !keysetMatches(payload.memberKeys, KeyType.USER, payload.memberKeys.name, 0)
    ) {
      return fail('Admitted member key metadata is invalid', previousState, link, logger)
    }

    if (
      (type === 'ADD_DEVICE' || type === 'ADMIT_DEVICE') &&
      !keysetMatches(payload.device.keys, KeyType.DEVICE, payload.device.deviceId, 0)
    ) {
      return fail('New device key metadata is invalid', previousState, link, logger)
    }

    if (
      type === 'ADD_SERVER' &&
      !keysetMatches(payload.server.keys, KeyType.SERVER, payload.server.host, 0)
    ) {
      return fail('New server key metadata is invalid', previousState, link, logger)
    }

    if (type === 'CHANGE_MEMBER_KEYS') {
      const members = previousState.members.filter(member => member.userId === payload.keys.name)
      if (
        members.length !== 1 ||
        !keysetMatches(
          payload.keys,
          KeyType.USER,
          members[0].userId,
          members[0].keys.generation + 1
        )
      ) {
        return fail('Changed member key metadata is invalid', previousState, link, logger)
      }
    }

    if (type === 'CHANGE_SERVER_KEYS') {
      const servers = previousState.servers.filter(server => server.host === payload.keys.name)
      if (
        servers.length !== 1 ||
        !keysetMatches(
          payload.keys,
          KeyType.SERVER,
          servers[0].host,
          servers[0].keys.generation + 1
        )
      ) {
        return fail('Changed server key metadata is invalid', previousState, link, logger)
      }
    }

    return VALID
  },

  activeIdentityIdsAreUnique(previousState: TeamState, link: TeamLink, extendableLogger: Logger) {
    const logger = extendableLogger.extend('activeIdentityIdsAreUnique')
    const { type, payload } = link.body

    const memberIds =
      type === ROOT
        ? [payload.rootMember.userId]
        : type === 'ADD_MEMBER'
          ? [payload.member.userId]
          : type === 'ADMIT_MEMBER'
            ? [payload.memberKeys.name]
            : []
    for (const userId of memberIds) {
      if (
        previousState.members.some(member => member.userId === userId) ||
        previousState.servers.some(server => server.host === userId)
      ) {
        return fail(`Active member ID '${userId}' is already in use`, previousState, link, logger)
      }
    }

    const devices =
      type === ROOT
        ? [payload.rootDevice, ...(payload.rootMember.devices ?? [])]
        : type === 'ADD_MEMBER'
          ? payload.member.devices ?? []
          : type === 'ADD_DEVICE' || type === 'ADMIT_DEVICE'
            ? [payload.device]
            : []
    const deviceIds = devices.map(device => device.deviceId)
    if (new Set(deviceIds).size !== deviceIds.length) {
      return fail('An action contains duplicate device IDs', previousState, link, logger)
    }
    for (const deviceId of deviceIds) {
      const existingDevices = previousState.members.flatMap(member => member.devices ?? [])
      if (
        existingDevices.some(device => device.deviceId === deviceId) ||
        previousState.servers.some(server => server.host === deviceId)
      ) {
        return fail(`Active device ID '${deviceId}' is already in use`, previousState, link, logger)
      }
    }

    if (type === 'ADD_SERVER') {
      const { host } = payload.server
      const deviceCollision = previousState.members
        .flatMap(member => member.devices ?? [])
        .some(device => device.deviceId === host)
      if (
        previousState.servers.some(server => server.host === host) ||
        previousState.members.some(member => member.userId === host) ||
        deviceCollision
      ) {
        return fail(`Active server host '${host}' is already in use`, previousState, link, logger)
      }
    }

    return VALID
  },

  deviceAdditionIsAuthorized(previousState: TeamState, link: TeamLink, extendableLogger: Logger) {
    const logger = extendableLogger.extend('deviceAdditionIsAuthorized')
    const { type, payload, userId: author } = link.body
    if (type !== 'ADD_DEVICE' && type !== 'ADMIT_DEVICE') {
      return VALID
    }
    if (type === 'ADMIT_DEVICE' && previousState.invitations[payload.id]?.kind !== 'device') {
      // The invitation-kind validator below owns this failure.
      return VALID
    }

    const owners = previousState.members.filter(member => member.userId === payload.device.userId)
    if (owners.length !== 1) {
      return fail('Device owner is missing or ambiguous', previousState, link, logger)
    }

    if (
      type === 'ADD_DEVICE' &&
      author !== payload.device.userId &&
      !select.memberIsAdmin(previousState, author)
    ) {
      return fail("A non-admin cannot add another member's device", previousState, link, logger)
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
  cantAdmitWithInvalidInvitation(
    previousState: TeamState,
    link: TeamLink,
    _extendableLogger: Logger
  ) {
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

const keysetMatches = (keys: Keyset, type: string, name: string, generation: number) =>
  keys.type === type &&
  keys.name === name &&
  keys.generation === generation &&
  typeof keys.encryption === 'string' &&
  typeof keys.signature === 'string'

const fail = (message: string, previousState: TeamState, link: TeamLink, extendableLogger: Logger) => {
  const logger = extendableLogger.extend('fail')
  message = truncateHashes(`${actionFingerprint(link)} ${message}`)
  logger.error(message, link.hash)
  return {
    isValid: false,
    error: new ValidationError(message, { prevState: previousState, link }),
  }
}
