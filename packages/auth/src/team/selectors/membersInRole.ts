import { ADMIN, type Role } from 'role/index.js'
import { type Member, type TeamState } from 'team/types.js'
import { memberHasRole } from './memberHasRole.js'

export const membersInRole = (state: TeamState, roleName: string) => {
  const memberHasRoleLockbox = (member: Member): boolean => memberHasRole(state, member.userId, roleName)

  return membersWithRoleMarker(state, roleName).filter(member => memberHasRoleLockbox(member))
}

export const membersWithRoleMarker = (state: TeamState, roleName: string): Member[] => 
  state.members.filter(member => member.roles?.includes(roleName))

export const admins = (state: TeamState) => membersInRole(state, ADMIN)

export const rolesMemberIsIn = (state: TeamState, userId: string): Role[] => {
  const roles: Role[] = []
  for (const role of state.roles) {
    if (memberHasRole(state, userId, role.roleName)) roles.push(role)
  }
  return roles
}
