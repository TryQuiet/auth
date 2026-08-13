import { ROOT, type Reducer } from '@localfirst/crdx'
import { Logger } from '@localfirst/shared'
import { ADMIN } from 'role/index.js'
import { clone, composeTransforms } from 'util/index.js'
import { invalidLinkReducer } from './invalidLinkReducer.js'
import { setHead } from './setHead.js'
import {
  addDevice,
  addInvitedDevice,
  addMember,
  addMemberRoles,
  addMessage,
  addRole,
  addServer,
  changeMemberKeys,
  changeServerKeys,
  collectLockboxes,
  postInvitation,
  removeDevice,
  removeMember,
  removeMemberRole,
  removeRole,
  removeServer,
  revokeInvitation,
  rotateKeys,
  setTeamName,
  useInvitation,
} from './transforms/index.js'
import { setMetadata } from './transforms/setMetadata.js'
import {
  type Member,
  type TeamAction,
  type TeamContext,
  type TeamLink,
  type TeamState,
  type Transform,
} from './types.js'
import { validate } from './validate.js'

/**
 * Each link has a `type` and a `payload`, just like a Redux action. So we can derive a `TeamState`
 * from a `TeamGraph`, by applying a Redux-style reducer to the array of links. The reducer runs on
 * each link in sequence, accumulating a team state.
 *
 * > *Note:* Keep in mind that this reducer is a pure function that acts on the publicly available
 * links in the signature chain, and must independently return the same result for every member. It
 * knows nothing about the current user's context, and it does not have access to any secrets. Any
 * crypto operations using secret keys that **the current user has** must happen elsewhere.
 *
 * @param state The team state as of the previous link in the signature chain.
 * @param link The current link being processed.
 */
export const reducer: Reducer<TeamState, TeamAction, TeamContext> = (state, link, extendableLogger) => {
  const logger = extendableLogger != null ? extendableLogger.extend('reducer') : new Logger({ moduleName: 'auth:reducer' })
  // Invalid links are marked to be discarded by the MembershipResolver due to conflicting
  // concurrent actions. In most cases we just ignore these links and they don't affect state at
  // all; but in some cases we need to clean up, for example when someone's admission is reversed
  // but they already joined and had access to the chain.
  if (link.isInvalid) {
    logger.warn('Link is invalid', link)
    return invalidLinkReducer(state, link)
  }

  state = clone(state)

  // Make sure this link can be applied to the previous state & doesn't put us in an invalid state.
  // This is where the link's signature is checked against the identity it claims to be from, so
  // nothing below this line has to wonder whether the author is who they say they are.
  const validation = validate(state, link, logger)
  if (!validation.isValid) {
    throw validation.error
  }

  // Get all transforms and compose them into a single function
  const applyTransforms = composeTransforms([
    setHead(link),
    collectLockboxes(link.body.payload.lockboxes), // Any payload can include lockboxes
    ...getTransforms(link), // Get the specific transforms indicated by this action
  ])

  return applyTransforms(state)
}

/**
 * Each action type generates one or more transforms (functions that take the old state and return a
 * new state). This returns an array of transforms that are then applied in order.
 * @param link The link being processed; its body is the team action, and its timestamp is what
 * registration and removal records are stamped with.
 */
const getTransforms = (link: TeamLink): Transform[] => {
  const action = link.body as TeamAction
  const { timestamp } = link.body

  switch (action.type) {
    case ROOT: {
      const { name, rootMember, rootDevice, metadata } = action.payload
      return [
        setTeamName(name),
        ...(metadata === undefined ? [] : [setMetadata(metadata)]),
        addRole({ roleName: ADMIN, createdBy: action.payload.rootMember.userId }), // Create the admin role
        addMember(rootMember, [rootDevice], timestamp), // Add the founding member & their device
        ...addMemberRoles(rootMember.userId, [ADMIN]), // Make the founding member an admin
      ]
    }

    case 'ADD_MEMBER': {
      const { member, roles } = action.payload
      return [
        addMember(member, member.devices ?? [], timestamp), // Add this member and any devices they're registering
        ...addMemberRoles(member.userId, roles), // Add each of these roles to the member's list of roles
      ]
    }

    case 'ADD_ROLE': {
      const newRole = action.payload
      return [
        addRole(newRole), // Add this role to the team
      ]
    }

    case 'ADD_MEMBER_ROLE': {
      const { userId, roleName } = action.payload
      return [
        ...addMemberRoles(userId, [roleName]), // Add this role to the member's list of roles
      ]
    }

    case 'REMOVE_MEMBER': {
      const { userId } = action.payload
      return [
        removeMember(userId), // Remove this member from the team
      ]
    }

    case 'REMOVE_DEVICE': {
      const { deviceId } = action.payload
      return [
        removeDevice(deviceId, timestamp), // Tombstone this device
      ]
    }

    case 'REMOVE_ROLE': {
      const { roleName } = action.payload
      return [
        removeRole(roleName), // Remove this role from the team
      ]
    }

    case 'REMOVE_MEMBER_ROLE': {
      const { userId, roleName } = action.payload
      return [
        removeMemberRole(userId, roleName), // Remove this role from the member's list of roles
      ]
    }

    case 'INVITE_MEMBER': {
      const { invitation } = action.payload
      return [
        postInvitation(invitation, 'member'), // Add the invitation to the list of open invitations.
      ]
    }

    case 'INVITE_DEVICE': {
      const { invitation } = action.payload
      return [
        postInvitation(invitation, 'device'), // Add the invitation to the list of open invitations.
      ]
    }

    case 'REVOKE_INVITATION': {
      const { id } = action.payload
      return [
        revokeInvitation(id), // Mark the invitation revoked so it can't be used
      ]
    }

    case 'ADMIT_MEMBER': {
      // Everything we register comes out of the signed claim, not out of fields the admitting peer
      // chose: the validator has checked that the claim is what the invitee signed.
      const { id, claim } = action.payload
      const member: Member = {
        userId: claim.memberKeys.name,
        userName: claim.userName,
        keys: claim.memberKeys,
        roles: [],
      }

      return [
        useInvitation(id), // Mark the invitation as used
        addMember(member, [claim.device], timestamp), // Add the member and the device they'll use
      ]
    }

    case 'ADMIT_DEVICE': {
      const { id, claim } = action.payload
      return [
        useInvitation(id), // Mark the invitation as used
        addInvitedDevice(id, claim.device, timestamp), // Add the device to the invitation's owner
      ]
    }

    case 'CHANGE_MEMBER_KEYS': {
      const { keys } = action.payload
      return [
        changeMemberKeys(keys), // Replace this member's public keys with the ones provided
      ]
    }

    case 'ROTATE_KEYS': {
      const { userId } = action.payload
      return [
        rotateKeys(userId), // Mark this member's keys as having been rotated (the rotated keys themselves are in the lockboxes)
      ]
    }

    case 'ADD_SERVER': {
      const { server } = action.payload
      return [
        addServer(server, timestamp), // Add the specified server to the team
      ]
    }

    case 'REMOVE_SERVER': {
      const { serverId } = action.payload
      return [
        removeServer(serverId, timestamp), // Tombstone the specified server
      ]
    }

    case 'CHANGE_SERVER_KEYS': {
      const { keys } = action.payload
      return [
        changeServerKeys(keys), // Replace this server's public keys with the ones provided
      ]
    }

    case 'MESSAGE': {
      const { message } = action.payload
      return [
        addMessage(message), // Add the message to the team's message log
      ]
    }

    case 'SET_TEAM_NAME': {
      const { teamName } = action.payload
      return [
        setTeamName(teamName), // Set the team's name
      ]
    }

    case 'ADD_LOCKBOXES': {
      // Note: lockboxes are handled by default so we don't need to do anything special here
      return [(state) => state]
    }

    case 'SET_METADATA': {
      const { metadata } = action.payload
      return [
        setMetadata(metadata)
      ]
    }

    default: {
      // ignore coverage
      throw unrecognizedLinkType(action)
    }
  }
}

// ignore coverage
function unrecognizedLinkType(action: never) {
  const { type } = action as TeamAction
  return new Error(`Unrecognized link type: ${type}`)
}
