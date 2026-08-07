import { type TeamAction } from './types.js'

// These actions don't require lockboxes to be present on payloads
const NON_LOCKBOX_REQUIRED_ACTIONS: Array<TeamAction['type']> = [
  'SET_METADATA',
  'MESSAGE',
  'SET_TEAM_NAME',
  'ADMIT_DEVICE',
  'ADMIT_MEMBER',
  'REVOKE_INVITATION',
  'INVITE_DEVICE',
  'INVITE_MEMBER',
  'REMOVE_ROLE',
  'ROOT',
]

export const isActionAllowedWithoutLockboxes = (action: TeamAction): boolean => {
  return isActionTypeAllowedWithoutLockboxes(action.type)
}

export const isActionTypeAllowedWithoutLockboxes = (actionType: TeamAction['type']): boolean => {
  return NON_LOCKBOX_REQUIRED_ACTIONS.includes(actionType)
}
