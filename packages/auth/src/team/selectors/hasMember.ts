import { type TeamState } from 'team/types.js'

/** Returns whether exactly one active member has `userId`; throws when the ID is ambiguous. */
export const hasMember = (state: TeamState, userId: string) => {
  const matchingMembers = state.members.filter(member => member.userId === userId)
  if (matchingMembers.length > 1) {
    throw new Error(`Member ID '${userId}' is ambiguous`)
  }
  return matchingMembers.length === 1
}
