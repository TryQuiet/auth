import { type TeamAction, type TeamLinkBody } from './types.js'

export const isAdminOnlyAction = (action: TeamLinkBody) => {
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
    'ADD_ROLE',
    'ADD_MEMBER_ROLE',
    'ADD_STATIC_ROLE',
    'ADD_MEMBER_STATIC_ROLE',
    'SET_METADATA',
  ]

  return !nonAdminActions.includes(actionType)
}
