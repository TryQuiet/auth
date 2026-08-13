import { ADMIN } from 'role/index.js'
import { type TeamAction, type TeamLinkBody } from './types.js'

export const isAdminOnlyAction = (action: TeamLinkBody) => {
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

    // A newly admitted member posts lockboxes for its own device as its first act, before it could
    // possibly be an admin. Lockboxes ride along on every other action's payload anyway, so
    // gating this one wouldn't be keeping anything out.
    'ADD_LOCKBOXES',
  ]

  return !nonAdminActions.includes(actionType)
}
