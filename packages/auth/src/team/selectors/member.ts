import { type TeamState } from 'team/types.js'

/** Returns the unique member with this userId; missing and ambiguous ids throw. */
export const member = (state: TeamState, userId: string, options = { includeRemoved: false }) => {
  const membersToSearch = [
    ...state.members,
    ...(options.includeRemoved ? state.removedMembers : []),
  ]
  const matchingMembers = membersToSearch.filter(m => m.userId === userId)

  if (matchingMembers.length === 0) {
    throw new Error(`A member named '${userId}' was not found`)
  }

  if (matchingMembers.length > 1) {
    throw new Error(`Member ID '${userId}' is ambiguous`)
  }

  return matchingMembers[0]
}

export const members = (state: TeamState, userIds: string[], options = { includeRemoved: false, throwOnMissing: true }) => {
  const membersToSearch = [
    ...state.members,
    ...(options.includeRemoved ? state.removedMembers : []),
  ]
  const members = membersToSearch.filter(m => userIds.includes(m.userId))

  if (members.length < userIds.length) {
    const message = `Expected ${userIds.length} members but found ${members.length}`
    if (options.throwOnMissing) {
      throw new Error(message)
    }
    console.error(message)
  }

  return members
}
