import { ADMIN } from 'role/index.js'
import { type TeamAction, type TeamLinkBody } from './types.js'

export const isAdminOnlyAction = (action: TeamLinkBody) => {
  // Preserve replay compatibility for a serialized ambient action while making its reducer
  // transition a no-op. ADD_LOCKBOXES is intentionally absent from TeamAction and cannot
  // introduce ambient deliveries.
  if ((action as { type?: unknown }).type === 'ADD_LOCKBOXES') return false

  // Granting the admin role is itself an admin-only act. Role grants are otherwise open to any
  // member (see below), but admin is the keys to the team: if a plain member could grant it, two
  // members could promote each other (or a colluder) to admin and take over. Self-assignment is
  // already gated separately by `nonAdminsCanOnlyModifyCertainRoles`.
  if (action.type === 'ADD_MEMBER_ROLE' && action.payload.roleName === ADMIN) {
    return true
  }

  return isAdminOnlyActionType(action.type)
}

export const isAdminOnlyActionType = (actionType: TeamAction['type']): boolean => {
  // Any team member can do these things
  const nonAdminActions: Array<TeamAction['type']> = [
    'INVITE_DEVICE',
    'REMOVE_DEVICE',
    'CHANGE_MEMBER_KEYS',
    'CHANGE_SERVER_KEYS',
    'ADMIT_MEMBER',
    'ADMIT_DEVICE',
    'ADD_MEMBER_ROLE',

    // A newly admitted member publishes its own USER keys to an already-registered device. The
    // action-specific collector verifies both sides of that relationship.
    'PUBLISH_USER_KEYS_TO_DEVICE',
  ]

  return !nonAdminActions.includes(actionType)
}
