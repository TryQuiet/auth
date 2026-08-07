import { ADMIN } from 'role/index.js'
import * as select from 'team/selectors/index.js'
import { type TeamState } from 'team/types.js'
import { KeyType } from '../../util/types.js'

export const memberHasRole = (state: TeamState, userId: string, roleName: string) => {
  if (!memberHasRoleMarker(state, userId, roleName)) {
    return false
  }

  const lockboxesForRole = select.lockboxesInScope(state, { type: KeyType.ROLE, name: roleName })
  if (lockboxesForRole.length === 0) {
    return false
  }

  const member = select.member(state, userId, { includeRemoved: false })
  if (lockboxesForRole.find((lockbox) => {
    return lockbox.recipient.type === KeyType.USER && lockbox.recipient.name === userId && lockbox.recipient.generation === member.keys.generation && lockbox.recipient.publicKey === member.keys.encryption
  }) == null) {
    return false
  }

  return true
}

export const memberHasRoleMarker = (state: TeamState, userId: string, role: string) => {
  if (!select.hasMember(state, userId)) {
    return false
  }

  const member = select.member(state, userId)
  const { roles = [] } = member
  return roles.includes(role)
}

export const memberIsAdmin = (state: TeamState, userId: string) =>
  memberHasRole(state, userId, ADMIN)
