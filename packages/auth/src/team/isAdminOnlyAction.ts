import { ADMIN } from 'role/index.js'
import { type TeamAction, type TeamLinkBody } from './types.js'

/**
 * Returns whether an action requires an administrator. Assigning the administrator role is always
 * admin-only even though other `ADD_MEMBER_ROLE` actions may be self-service.
 */
export const isAdminOnlyAction = (action: TeamLinkBody) => {
  if (action.type === 'ADD_MEMBER_ROLE' && action.payload.roleName === ADMIN) {
    return true
  }

  return isAdminOnlyActionType(action.type)
}

export const isAdminOnlyActionType = (actionType: TeamAction['type']): boolean => {
  // Any team member can do these things
  const nonAdminActions: Array<TeamAction['type']> = [
    'INVITE_DEVICE',
    'ADD_DEVICE',
    'REMOVE_DEVICE',
    'CHANGE_MEMBER_KEYS',
    'CHANGE_SERVER_KEYS',
    'ADMIT_MEMBER',
    'ADMIT_DEVICE',
    'ADD_MEMBER_ROLE',
    'SET_METADATA',
  ]

  return !nonAdminActions.includes(actionType)
}
