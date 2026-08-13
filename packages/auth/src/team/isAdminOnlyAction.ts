import { type TeamAction, type TeamLinkBody } from './types.js'

export const isAdminOnlyAction = (action: TeamLinkBody) => {
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
