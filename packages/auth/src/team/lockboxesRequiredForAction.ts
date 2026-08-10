import { type TeamAction } from './types.js'

// These actions don't require lockboxes to be present on payloads
const NON_LOCKBOX_REQUIRED_ACTIONS: Array<TeamAction['type']> = [
  'SET_METADATA',
  'MESSAGE',
  'SET_TEAM_NAME',
  'ADMIT_DEVICE',
  'REVOKE_INVITATION',
  'INVITE_DEVICE',
  'INVITE_MEMBER',
  'REMOVE_ROLE',
  'ROOT',
  'ADD_MEMBER_TEST',
]

export const isActionAllowedWithoutLockboxes = (action: TeamAction): boolean => {
  return isActionTypeAllowedWithoutLockboxes(action.type)
}

export const isActionTypeAllowedWithoutLockboxes = (actionType: TeamAction['type']): boolean => {
  return NON_LOCKBOX_REQUIRED_ACTIONS.includes(actionType)
}
