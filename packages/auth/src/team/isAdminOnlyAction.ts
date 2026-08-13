import { ADMIN } from 'role/index.js'
import { type TeamAction, type TeamLinkBody } from './types.js'

// Anyone with team key can perform these actions
const TEAM_KEY_ACTIONS: Array<TeamAction['type']> = [
  'ADMIT_MEMBER',
  'ADD_DEVICE',
  'ADD_MEMBER_ROLE',
  'CHANGE_SERVER_KEYS',
  'ADMIT_DEVICE',
]

// Anyone with MEMBER role can perform these actions + those in NON_MEMBER_NON_ADMIN_ACTIONS
const MEMBER_ROLE_ACTIONS: Array<TeamAction['type']> = [
  'INVITE_DEVICE',
  'CHANGE_MEMBER_KEYS',
  'REMOVE_DEVICE',
]

export const isAdminOnlyAction = (action: TeamLinkBody) => {
  // ADD_MEMBER_ROLE is generally permitted with the team key so invitation handshakes can assign
  // MEMBER, but promoting someone to ADMIN still depends on the author's admin privileges.
  if (action.type === 'ADD_MEMBER_ROLE' && action.payload.roleName === ADMIN) return true
  return isAdminOnlyActionType(action.type)
}

export const isActionAllowedWithTeamKey = (action: TeamLinkBody): boolean => {
  return isActionTypeAllowedWithTeamKey(action.type)
}

export const isActionAllowedWithMemberRole = (action: TeamLinkBody): boolean => {
  return isActionTypeAllowedWithMemberRole(action.type)
}

export const isAdminOnlyActionType = (actionType: TeamAction['type']): boolean => {
  return (
    !isActionTypeAllowedWithTeamKey(actionType) && !isActionTypeAllowedWithMemberRole(actionType)
  )
}

export const isActionTypeAllowedWithTeamKey = (actionType: TeamAction['type']): boolean => {
  return TEAM_KEY_ACTIONS.includes(actionType)
}

export const isActionTypeAllowedWithMemberRole = (actionType: TeamAction['type']): boolean => {
  return MEMBER_ROLE_ACTIONS.includes(actionType)
}
