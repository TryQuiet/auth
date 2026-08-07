import { type TeamAction, type TeamLinkBody } from './types.js'

// Anyone with team key can perform these actions
const NON_MEMBER_NON_ADMIN_ACTIONS: Array<TeamAction['type']> = [
  'ADD_MEMBER_ROLE',
  'ADMIT_MEMBER',
  'ADD_DEVICE',
  'ADD_MEMBER_ROLE',
  'CHANGE_SERVER_KEYS',
  'ADMIT_DEVICE',
]

// Anyone with MEMBER role can perform these actions + those in NON_MEMBER_NON_ADMIN_ACTIONS
const MEMBER_NON_ADMIN_ACTIONS: Array<TeamAction['type']> = [
  'INVITE_DEVICE',
  'CHANGE_MEMBER_KEYS',
  'REMOVE_DEVICE',
]

export const isAdminOnlyAction = (action: TeamLinkBody) => {
  return isAdminOnlyActionType(action.type)
}

export const isActionAllowedWithTeamKey = (action: TeamLinkBody): boolean => {
  return isActionTypeAllowedWithTeamKey(action.type)
}

export const isActionAllowedWithMemberRole = (action: TeamLinkBody): boolean => {
  return isActionTypeAllowedWithMemberRole(action.type)
}

export const isAdminOnlyActionType = (actionType: TeamAction['type']): boolean => {
  return !isActionTypeAllowedWithTeamKey(actionType) && !isActionTypeAllowedWithMemberRole(actionType)
}

export const isActionTypeAllowedWithTeamKey = (actionType: TeamAction['type']): boolean => {
  return NON_MEMBER_NON_ADMIN_ACTIONS.includes(actionType)
}

export const isActionTypeAllowedWithMemberRole = (actionType: TeamAction['type']): boolean => {
  return MEMBER_NON_ADMIN_ACTIONS.includes(actionType)
}
